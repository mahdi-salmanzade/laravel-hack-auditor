<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

use function Laravel\Prompts\spin;

use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\AI\ResponseParser;
use Mahdi\HackAuditor\Exceptions\InvalidAIResponseException;
use Mahdi\HackAuditor\Report\HtmlReportGenerator;
use Mahdi\HackAuditor\Scanner\Baseline;
use Mahdi\HackAuditor\Scanner\CodeExtractor;
use Mahdi\HackAuditor\Scanner\FileCollector;
use Mahdi\HackAuditor\Scanner\GitDiffCollector;
use Mahdi\HackAuditor\Scanner\HackScanner;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\AiProviders;
use Mahdi\HackAuditor\Support\ScanHistory;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\UsageLog;
use Mahdi\HackAuditor\Support\UsageTracker;
use SplFileInfo;

final class HackScanCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'hack:scan
        {--path= : Scan a specific file or directory}
        {--severity=Low : Minimum severity to report}
        {--fix : Auto-generate fixes}
        {--json : Output as JSON}
        {--html : Generate an HTML report}
        {--save : Save results to database}
        {--force : Skip confirmation prompt for large scans}
        {--detailed : Show full descriptions in the table instead of truncating}
        {--diff : Only scan files changed in the current git branch}
        {--base= : Base branch for --diff comparison (default: auto-detect main/master)}
        {--baseline : Apply baseline to suppress known findings (on by default if file exists)}
        {--no-baseline : Ignore the baseline file}
        {--update-baseline : Save current findings as the new baseline}
        {--limit= : Maximum token budget for this scan (stops scanning when reached)}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Scan your Laravel application for security vulnerabilities using AI';

    /** @var array<string, int> */
    private const array SEVERITY_ORDER = [
        'critical' => 4,
        'high' => 3,
        'medium' => 2,
        'low' => 1,
    ];

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $startTime = hrtime(true);

        if (! $this->option('json')) {
            $this->displayBanner();
            $this->line('');

            $provider = config('hack-auditor.ai.provider', 'laravel-ai');
            $model = config('hack-auditor.ai.model', 'default');
            $fileCount = $this->estimateFileCount();

            $this->line('  <fg=gray>target</>   '.$fileCount.' files');
            $this->line('  <fg=gray>engine</>   '.$provider.' / '.$model);
            $this->line('');
            $this->line('  <fg=yellow>●</> Collecting files...');
        }

        /** @var HackScanner $scanner */
        $scanner = app(HackScanner::class);

        // Set up usage tracking with auto-detected pricing
        $tokenLimit = (int) ($this->option('limit') ?: config('hack-auditor.usage.default_limit', 0));
        $tracker = UsageTracker::forCurrentConfig($tokenLimit);
        $scanner->setUsageTracker($tracker);

        if (! $this->option('json') && $tracker->isLimitSet()) {
            $this->line('  <fg=gray>limit</>    '.number_format($tracker->getTokenLimit()).' tokens');
        }

        $path = $this->option('path');

        if (! is_string($path) || $path === '') {
            if (! $this->option('json') && ! $this->option('force')) {
                $fileCount = $fileCount ?? $this->estimateFileCount();
                /** @var int $threshold */
                $threshold = config('hack-auditor.scan.confirm_above_files', 20);

                if ($fileCount > $threshold) {
                    /** @var int $chunkSize */
                    $chunkSize = config('hack-auditor.scan.chunk_size', 10);
                    $estimatedRequests = (int) ceil($fileCount / $chunkSize);

                    $this->components->warn(
                        "This will analyze ~{$fileCount} files in ~{$estimatedRequests} AI requests."
                    );

                    if (! $this->confirm('Continue? (use --force to skip this prompt)')) {
                        $this->components->info('Scan cancelled.');

                        return self::SUCCESS;
                    }
                }
            }
        }

        /** @var VulnerabilityReport $report */
        $report = spin(
            callback: function () use ($scanner, $path): VulnerabilityReport {
                if ($this->option('diff')) {
                    return $this->scanDiff($scanner);
                }

                if (is_string($path) && $path !== '') {
                    return $scanner->scanFile($path);
                }

                return $scanner->scan();
            },
            message: 'Analyzing files with AI...',
        );

        $elapsedMs = (int) ((hrtime(true) - $startTime) / 1_000_000);
        $minimumSeverity = SeverityLevel::fromString((string) $this->option('severity'));
        $filteredVulnerabilities = $this->filterBySeverity($report->vulnerabilities, $minimumSeverity);
        $filteredVulnerabilities = $this->applyBaseline($filteredVulnerabilities);

        if ($this->option('json')) {
            return $this->outputJson($report, $filteredVulnerabilities, $elapsedMs);
        }

        $this->line('  <fg=green>✓</> Scan complete <fg=gray>('.round($elapsedMs / 1000, 1).'s)</>');
        $this->newLine();
        $this->displayAnalyzedPaths();

        $this->displayFileSummary($report);
        $this->newLine();
        $this->displayScore($report->overallScore);
        $this->newLine();
        $this->displaySummary($report->summary);
        $this->newLine();

        if (count($filteredVulnerabilities) > 0) {
            $this->displayVulnerabilityTable($filteredVulnerabilities);
            $this->newLine();
            $this->displayDetailedFindings($filteredVulnerabilities);
            $this->newLine();
        }

        $this->displayStats($report, $filteredVulnerabilities, $minimumSeverity);
        $this->newLine();

        if ($this->option('fix') && count($filteredVulnerabilities) > 0) {
            $this->displayFixes($filteredVulnerabilities);
            $this->newLine();
        }

        if ($this->option('update-baseline')) {
            $this->updateBaseline($report);
        }

        if ($this->option('save')) {
            $this->saveResults($report, $elapsedMs);
        }

        if ($this->option('html')) {
            $this->generateHtmlReport($report, $elapsedMs);
        }

        // Log usage data
        if (config('hack-auditor.usage.log_enabled', true) && $report->hasUsageData()) {
            try {
                $usageLog = new UsageLog;
                $detectedPricing = AiProviders::detectPricing();
                $usageLog->record($report->getUsageTracker(), [
                    'files_skipped' => $report->getFilesSkipped(),
                    'path' => is_string($this->option('path')) ? $this->option('path') : null,
                    'score' => $report->overallScore,
                    'provider' => $detectedPricing['provider'],
                    'model' => $detectedPricing['model'],
                ]);
            } catch (\Throwable) {
                // Usage logging is best-effort
            }
        }

        $this->displayScanComparison($report);

        $this->displayUsageSummary($report);

        if ($report->getFilesSkipped() > 0) {
            $this->components->warn(
                "Token limit reached — {$report->getFilesSkipped()} file(s) skipped. "
                .'Increase with --limit or remove the flag for unlimited.'
            );
        }

        $chunksFailedParse = $scanner->getChunksFailedParse();
        if ($chunksFailedParse > 0) {
            $this->components->warn(
                "{$chunksFailedParse} chunk(s) returned unparseable AI responses and were skipped. "
                .'Re-run the scan to retry those files.'
            );
        }

        $this->components->info('Run `<fg=cyan>php artisan hack:ctf</>` to generate CTF challenges from these findings');

        return $report->hasCritical() ? self::FAILURE : self::SUCCESS;
    }

    /**
     * Display the Hack Auditor ASCII banner.
     */
    private function displayBanner(): void
    {
        $bannerPath = dirname(__DIR__, 2).'/resources/stubs/banner.stub';

        if (file_exists($bannerPath)) {
            $lines = explode("\n", trim(file_get_contents($bannerPath)));
            $this->line('');
            foreach ($lines as $line) {
                $this->line('  <fg=red>'.$line.'</>');
            }
        } else {
            $this->line('');
            $this->line('  <fg=red>HACK AUDITOR</>');
        }
    }

    /**
     * Filter vulnerabilities to only include those at or above the minimum severity.
     *
     * @param  array<int, Vulnerability>  $vulnerabilities
     * @return array<int, Vulnerability>
     */
    private function filterBySeverity(array $vulnerabilities, SeverityLevel $minimum): array
    {
        $minimumOrder = self::SEVERITY_ORDER[$minimum->value] ?? 1;

        return array_values(array_filter(
            $vulnerabilities,
            fn (Vulnerability $v): bool => (self::SEVERITY_ORDER[$v->severity->value] ?? 0) >= $minimumOrder,
        ));
    }

    /**
     * Sort vulnerabilities by severity (Critical first, Low last).
     *
     * @param  array<int, Vulnerability>  $vulnerabilities
     * @return array<int, Vulnerability>
     */
    private function sortBySeverity(array $vulnerabilities): array
    {
        usort(
            $vulnerabilities,
            fn (Vulnerability $a, Vulnerability $b): int => (self::SEVERITY_ORDER[$b->severity->value] ?? 0) <=> (self::SEVERITY_ORDER[$a->severity->value] ?? 0),
        );

        return $vulnerabilities;
    }

    /**
     * Display the file collection summary line.
     */
    private function displayFileSummary(VulnerabilityReport $report): void
    {
        $totalFiles = count($report->vulnerabilities);
        $uniqueLocations = count(array_unique(array_map(
            fn (Vulnerability $v): string => $v->location,
            $report->vulnerabilities,
        )));

        $this->components->info("Found <options=bold>{$totalFiles}</> vulnerabilities across <options=bold>{$uniqueLocations}</> files");
    }

    /**
     * Display the overall security score with color-coded formatting.
     */
    private function displayScore(int $score): void
    {
        $color = match (true) {
            $score > 80 => 'green',
            $score > 50 => 'yellow',
            $score > 30 => 'yellow',
            default => 'red',
        };

        $this->line("  <fg={$color};options=bold>╔═══════════════════════╗</>");
        $this->line("  <fg={$color};options=bold>║   Security Score      ║</>");
        $this->line("  <fg={$color};options=bold>║       {$score}/100           ║</>");
        $this->line("  <fg={$color};options=bold>╚═══════════════════════╝</>");
    }

    /**
     * Display the summary paragraphs from the AI analysis, word-wrapped for readability.
     */
    private function displaySummary(string $summary): void
    {
        $paragraphs = preg_split('/\n{2,}/', trim($summary));

        foreach ($paragraphs as $index => $paragraph) {
            $paragraph = preg_replace('/\s+/', ' ', trim($paragraph));
            $wrapped = wordwrap($paragraph, 100);

            foreach (explode("\n", $wrapped) as $line) {
                $this->line("  <fg=gray>{$line}</>");
            }

            if ($index < count($paragraphs) - 1) {
                $this->newLine();
            }
        }
    }

    /**
     * Display the vulnerability results as a styled console table.
     *
     * @param  array<int, Vulnerability>  $vulnerabilities
     */
    private function displayVulnerabilityTable(array $vulnerabilities): void
    {
        $sorted = $this->sortBySeverity($vulnerabilities);
        $isVerbose = $this->option('detailed');

        $rows = [];
        foreach ($sorted as $index => $vuln) {
            $description = $isVerbose
                ? $vuln->description
                : $this->truncateDescription($vuln->description, 120);

            $rows[] = [
                '<fg=gray>'.($index + 1).'</>',
                $vuln->severity->label(),
                "<options=bold>{$vuln->type->label()}</>",
                "<fg=cyan>{$vuln->location}:{$vuln->line}</>",
                $description,
            ];
        }

        $this->table(
            ['<options=bold>#</>', '<options=bold>Severity</>', '<options=bold>Type</>', '<options=bold>Location:Line</>', '<options=bold>Description</>'],
            $rows,
        );
    }

    /**
     * Display full details for each vulnerability.
     *
     * @param  array<int, Vulnerability>  $vulnerabilities
     */
    private function displayDetailedFindings(array $vulnerabilities): void
    {
        $sorted = $this->sortBySeverity($vulnerabilities);

        $this->components->info('Detailed Findings');
        $this->newLine();

        foreach ($sorted as $index => $vuln) {
            $number = $index + 1;
            $this->line("  <fg=cyan;options=bold>━━━ #{$number}: {$vuln->type->label()} ━━━</>");
            $this->line("  <fg=gray>Location:</> <fg=cyan>{$vuln->location}:{$vuln->line}</>");
            $this->line("  <fg=gray>Severity:</> {$vuln->severity->label()}");
            $this->newLine();
            $this->line('  <fg=white;options=bold>Description:</>');

            foreach (explode("\n", wordwrap($vuln->description, 100)) as $descLine) {
                $this->line("    <fg=gray>{$descLine}</>");
            }

            $this->newLine();
        }
    }

    /**
     * Display the statistics summary line.
     *
     * @param  array<int, Vulnerability>  $filteredVulnerabilities
     */
    private function displayStats(VulnerabilityReport $report, array $filteredVulnerabilities, SeverityLevel $minimum): void
    {
        $total = count($filteredVulnerabilities);

        $critical = count(array_filter($filteredVulnerabilities, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::Critical));
        $high = count(array_filter($filteredVulnerabilities, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::High));
        $medium = count(array_filter($filteredVulnerabilities, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::Medium));
        $low = count(array_filter($filteredVulnerabilities, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::Low));

        $statsLine = "  Found <options=bold>{$total}</> vulnerabilities";

        if ($minimum !== SeverityLevel::Low) {
            $statsLine .= " (filtered to {$minimum->name}+)";
        }

        $statsLine .= ': ';
        $statsLine .= "<fg=red>{$critical} Critical</>, ";
        $statsLine .= "<fg=yellow>{$high} High</>, ";
        $statsLine .= "<fg=blue>{$medium} Medium</>, ";
        $statsLine .= "<fg=gray>{$low} Low</>";

        $this->line($statsLine);
    }

    /**
     * Display fix suggestions for each vulnerability in styled code blocks.
     *
     * @param  array<int, Vulnerability>  $vulnerabilities
     */
    private function displayFixes(array $vulnerabilities): void
    {
        $sorted = $this->sortBySeverity($vulnerabilities);

        $this->components->info('Suggested Fixes');
        $this->newLine();

        foreach ($sorted as $index => $vuln) {
            $number = $index + 1;
            $this->line("  <fg=cyan;options=bold>━━━ Fix #{$number}: {$vuln->type->label()} ━━━</>");
            $this->line("  <fg=gray>Location:</> <fg=cyan>{$vuln->location}:{$vuln->line}</>");
            $this->line("  <fg=gray>Severity:</> {$vuln->severity->label()}");
            $this->newLine();
            $this->line('  <fg=green;options=bold>Recommended fix:</>');
            $this->newLine();

            foreach (explode("\n", $vuln->fix) as $fixLine) {
                $this->line("    <fg=green>{$fixLine}</>");
            }

            $this->newLine();
        }
    }

    /**
     * Output the full report as JSON and return the exit code.
     *
     * @param  array<int, Vulnerability>  $filteredVulnerabilities
     */
    private function outputJson(VulnerabilityReport $report, array $filteredVulnerabilities, int $elapsedMs): int
    {
        $output = [
            'overall_score' => $report->overallScore,
            'summary' => $report->summary,
            'ctf_idea' => $report->ctfIdea,
            'scan_duration_ms' => $elapsedMs,
            'counts' => [
                'total' => count($filteredVulnerabilities),
                'critical' => count(array_filter($filteredVulnerabilities, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::Critical)),
                'high' => count(array_filter($filteredVulnerabilities, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::High)),
                'medium' => count(array_filter($filteredVulnerabilities, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::Medium)),
                'low' => count(array_filter($filteredVulnerabilities, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::Low)),
            ],
            'vulnerabilities' => array_map(
                fn (Vulnerability $v): array => $v->toArray(),
                $filteredVulnerabilities,
            ),
        ];

        if ($report->hasUsageData()) {
            $output['usage'] = $report->getUsageTracker()->toArray();
            $output['files_skipped'] = $report->getFilesSkipped();
        }

        $this->line((string) json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

        return $report->hasCritical() ? self::FAILURE : self::SUCCESS;
    }

    /**
     * Save scan results to a JSON file.
     */
    private function saveResults(VulnerabilityReport $report, int $elapsedMs): void
    {
        try {
            $history = new ScanHistory;
            $data = $report->toArray();
            $data['scan_duration_ms'] = $elapsedMs;
            $data['ai_provider'] = config('hack-auditor.ai.provider');
            $data['ai_model'] = config('hack-auditor.ai.model');
            $data['laravel_version'] = app()->version();

            if ($report->hasUsageData()) {
                $data['usage'] = $report->getUsageTracker()->toArray();
                $data['files_skipped'] = $report->getFilesSkipped();
            }

            $id = $history->save($data);

            $this->components->info("Scan saved: <fg=cyan>{$id}</>");
        } catch (\Throwable $e) {
            $this->components->error("Failed to save results: {$e->getMessage()}");
        }
    }

    /**
     * Scan only files changed in the current git branch.
     */
    private function scanDiff(HackScanner $scanner): VulnerabilityReport
    {
        $collector = new GitDiffCollector;
        $baseBranch = $this->option('base');

        if (! is_string($baseBranch) || $baseBranch === '') {
            /** @var ?string $configBranch */
            $configBranch = config('hack-auditor.scan.diff_base_branch');
            $baseBranch = is_string($configBranch) && $configBranch !== '' ? $configBranch : 'main';
        }

        $files = $collector->getChangedFiles($baseBranch);

        if ($files === []) {
            return new VulnerabilityReport(
                vulnerabilities: [],
                overallScore: 100,
                summary: "No changed PHP files found compared to {$baseBranch}.",
                ctfIdea: '',
            );
        }

        /** @var CodeExtractor $extractor */
        $extractor = app(CodeExtractor::class);

        $splFiles = collect($files)->map(fn (string $path): SplFileInfo => new SplFileInfo($path));
        $chunks = $extractor->chunk($splFiles);

        $reports = [];

        foreach ($chunks as $chunk) {
            try {
                $systemPrompt = app(PromptBuilder::class)->systemPrompt();
                $userPrompt = app(PromptBuilder::class)->userPrompt($chunk);
                $response = app(AIAdapter::class)->send($systemPrompt, $userPrompt);
                $reports[] = app(ResponseParser::class)->parse($response);
            } catch (InvalidAIResponseException $e) {
                Log::warning('[HackAuditor] Skipping diff chunk due to unparseable AI response', [
                    'files' => array_map(fn (array $f): string => $f['path'], $chunk),
                    'error' => $e->getMessage(),
                ]);
            }
        }

        if (count($reports) === 0) {
            return new VulnerabilityReport(
                vulnerabilities: [],
                overallScore: 100,
                summary: 'No files analyzed.',
                ctfIdea: '',
            );
        }

        if (count($reports) === 1) {
            return $reports[0];
        }

        // Merge reports
        $allVulns = [];
        $scoreSum = 0;
        $summaries = [];

        foreach ($reports as $r) {
            $allVulns = array_merge($allVulns, $r->vulnerabilities);
            $scoreSum += $r->overallScore;

            if ($r->summary !== '') {
                $summaries[] = $r->summary;
            }
        }

        return new VulnerabilityReport(
            vulnerabilities: $allVulns,
            overallScore: (int) round($scoreSum / count($reports)),
            summary: implode("\n\n", $summaries),
            ctfIdea: '',
        );
    }

    /**
     * Apply baseline filtering to suppress known findings.
     *
     * @param  array<int, Vulnerability>  $vulnerabilities
     * @return array<int, Vulnerability>
     */
    private function applyBaseline(array $vulnerabilities): array
    {
        if ($this->option('no-baseline')) {
            return $vulnerabilities;
        }

        $baseline = new Baseline;
        $baselinePath = config('hack-auditor.scan.baseline_path');

        if (! $baseline->exists(is_string($baselinePath) ? $baselinePath : null)) {
            return $vulnerabilities;
        }

        $baseline->load(is_string($baselinePath) ? $baselinePath : null);
        $result = $baseline->filter($vulnerabilities);

        if ($result['suppressed'] > 0 && ! $this->option('json')) {
            $newCount = count($result['new']);
            $this->components->info(
                "<fg=gray>{$result['suppressed']} findings suppressed by baseline</> ({$newCount} new findings)"
            );
        }

        return $result['new'];
    }

    /**
     * Save current findings as the new baseline file.
     */
    private function updateBaseline(VulnerabilityReport $report): void
    {
        $baseline = new Baseline;
        $baselinePath = config('hack-auditor.scan.baseline_path');
        $baseline->save($report, is_string($baselinePath) ? $baselinePath : null);

        $this->components->info("Baseline updated with {$report->totalCount()} findings");
    }

    /**
     * Generate an HTML report and save it to the configured output path.
     */
    private function generateHtmlReport(VulnerabilityReport $report, int $elapsedMs): void
    {
        try {
            /** @var HtmlReportGenerator $generator */
            $generator = app(HtmlReportGenerator::class);

            $html = $generator->generate($report, [
                'duration' => round($elapsedMs / 1000, 1).'s',
                'provider' => config('hack-auditor.ai.provider', 'default'),
                'model' => config('hack-auditor.ai.model', 'default'),
            ]);

            /** @var string $outputBase */
            $outputBase = config('hack-auditor.report.output_path', 'hack-auditor/reports');
            $outputDir = storage_path($outputBase);

            if (! is_dir($outputDir)) {
                mkdir($outputDir, 0755, true);
            }

            $filename = 'scan-'.now()->format('Y-m-d-His').'.html';
            $fullPath = $outputDir.DIRECTORY_SEPARATOR.$filename;

            file_put_contents($fullPath, $html);

            $this->components->info("HTML report saved to <fg=cyan>{$fullPath}</>");
        } catch (\Throwable $e) {
            $this->components->error("Failed to generate HTML report: {$e->getMessage()}");
        }
    }

    /**
     * Display scan comparison with previous scan if saved scans exist.
     */
    private function displayScanComparison(VulnerabilityReport $report): void
    {
        try {
            $history = new ScanHistory;
            $previous = $history->latest();

            if ($previous === null) {
                return;
            }

            $previousScore = (int) ($previous['overall_score'] ?? 0);
            $delta = $report->overallScore - $previousScore;
            $deltaSign = $delta > 0 ? '+' : '';
            $deltaColor = $delta > 0 ? 'green' : ($delta < 0 ? 'red' : 'gray');

            $this->newLine();
            $this->line("  <fg={$deltaColor}>Score: {$report->overallScore}/100 ({$deltaSign}{$delta} since last scan)</>");
        } catch (\Throwable) {
            // History comparison is best-effort
        }
    }

    /**
     * Display token usage summary after scan results.
     */
    private function displayUsageSummary(VulnerabilityReport $report): void
    {
        if (! $report->hasUsageData()) {
            return;
        }

        if (! config('hack-auditor.usage.show_usage', true)) {
            return;
        }

        $tracker = $report->getUsageTracker();
        $this->newLine();

        $this->components->twoColumnDetail(
            '<fg=gray>Token Usage</>',
            sprintf(
                '<fg=cyan>%s</> prompt + <fg=cyan>%s</> completion = <fg=white;options=bold>%s</> total',
                number_format($tracker->getPromptTokens()),
                number_format($tracker->getCompletionTokens()),
                number_format($tracker->totalTokens()),
            ),
        );

        $this->components->twoColumnDetail(
            '<fg=gray>AI Requests</>',
            (string) $tracker->getRequests(),
        );

        $cost = $tracker->estimateCost();
        if ($cost > 0) {
            $this->components->twoColumnDetail(
                '<fg=gray>Estimated Cost</>',
                sprintf('<fg=yellow>$%.4f</>', $cost),
            );
        }

        $this->components->twoColumnDetail(
            '<fg=gray>Scan Duration</>',
            sprintf('%.1fs', $tracker->getElapsedSeconds()),
        );

        $pricing = AiProviders::detectPricing();
        if ($pricing['provider'] !== null) {
            $modelInfo = AiProviders::model($pricing['provider'], $pricing['model'] ?? '');
            $modelName = $modelInfo['name'] ?? $pricing['model'];

            $this->components->twoColumnDetail(
                '<fg=gray>Model</>',
                sprintf('%s <fg=gray>(%s)</>',  $modelName, $pricing['provider']),
            );

            $this->components->twoColumnDetail(
                '<fg=gray>Rates</>',
                sprintf(
                    '<fg=gray>$%.2f / $%.2f per 1M tokens (%s)</>',
                    $pricing['input'],
                    $pricing['output'],
                    $pricing['source'],
                ),
            );
        }

        if ($tracker->isLimitSet()) {
            $percent = $tracker->getUsagePercent();
            $color = $percent > 90 ? 'red' : ($percent > 70 ? 'yellow' : 'green');

            $this->components->twoColumnDetail(
                '<fg=gray>Budget Used</>',
                sprintf(
                    '<fg=%s>%.1f%%</> (%s / %s tokens)',
                    $color,
                    $percent,
                    number_format($tracker->totalTokens()),
                    number_format($tracker->getTokenLimit()),
                ),
            );
        }
    }

    /**
     * Estimate how many files would be scanned using the FileCollector.
     */
    private function estimateFileCount(): int
    {
        try {
            /** @var FileCollector $collector */
            $collector = app(FileCollector::class);

            return $collector->collect()->count();
        } catch (\Throwable) {
            return 0;
        }
    }

    /**
     * Display which paths were analyzed for scan transparency.
     */
    private function displayAnalyzedPaths(): void
    {
        /** @var array<int, string> $paths */
        $paths = config('hack-auditor.scan.paths', []);

        if ($paths === []) {
            return;
        }

        $this->line('  <fg=gray>analyzed</>  '.implode(', ', $paths));
        $this->newLine();
    }

    /**
     * Truncate a description string to a maximum length with ellipsis.
     */
    private function truncateDescription(string $description, int $maxLength): string
    {
        if (mb_strlen($description) <= $maxLength) {
            return $description;
        }

        return mb_substr($description, 0, $maxLength - 3).'...';
    }
}
