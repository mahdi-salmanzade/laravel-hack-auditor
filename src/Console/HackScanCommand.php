<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

use function Laravel\Prompts\spin;

use Mahdi\HackAuditor\Report\HtmlReportGenerator;
use Mahdi\HackAuditor\Scanner\Baseline;
use Mahdi\HackAuditor\Scanner\FileCollector;
use Mahdi\HackAuditor\Scanner\GitDiffCollector;
use Mahdi\HackAuditor\Scanner\HackScanner;
use Mahdi\HackAuditor\Scanner\ScanCoverage;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\AiProviders;
use Mahdi\HackAuditor\Support\ScanHistory;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\UsageLog;
use Mahdi\HackAuditor\Support\UsageTracker;

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
        {--save : Save results to JSON file}
        {--force : Skip confirmation prompt for large scans}
        {--detailed : Show full descriptions in the table instead of truncating}
        {--diff : Only scan files changed in the current git branch}
        {--base= : Base branch for --diff comparison (default: auto-detect main/master)}
        {--baseline : Apply baseline to suppress known findings (on by default if file exists)}
        {--no-baseline : Ignore the baseline file}
        {--update-baseline : Save current findings as the new baseline}
        {--limit= : Maximum token budget for this scan (stops scanning when reached)}
        {--verify : Run multi-pass exploit verification on HIGH+ findings (doubles API cost on those findings)}';

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

        $verifyEnabled = $this->option('verify') || (bool) config('hack-auditor.verification.enabled', false);
        $scanner->setVerify($verifyEnabled);

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

        $scanCallback = function () use ($scanner, $path): VulnerabilityReport {
            if ($this->option('diff')) {
                return $this->scanDiff($scanner);
            }

            if (is_string($path) && $path !== '') {
                return $scanner->scanFile($path);
            }

            return $scanner->scan();
        };

        // Defense in depth: the scanner catches per-chunk failures itself, but a
        // failure it does NOT catch (a fatal in the spinner, the container, or
        // future pipeline code) would otherwise discard a tracker that has
        // already paid for real requests. Record the spend, then rethrow.
        try {
            /** @var VulnerabilityReport $report */
            $report = $this->option('json')
                ? $scanCallback()
                : spin(
                    callback: $scanCallback,
                    message: 'Analyzing files with AI...',
                );
        } catch (\Throwable $e) {
            $this->logUsage($tracker, null);

            throw $e;
        }

        $elapsedMs = (int) ((hrtime(true) - $startTime) / 1_000_000);
        $minimumSeverity = SeverityLevel::fromString((string) $this->option('severity'));
        $filteredVulnerabilities = $this->filterBySeverity($report->vulnerabilities, $minimumSeverity);
        $filteredVulnerabilities = $this->applyBaseline($filteredVulnerabilities);

        // Two classes, never mixed: assertions the analyzer can back with an
        // evidence chain, and questions it wants a human to answer. Only the
        // first list is counted, scored or allowed to fail the build.
        $confirmed = $this->onlyConfirmed($filteredVulnerabilities);
        $reviewItems = $this->onlyReviewItems($filteredVulnerabilities);

        // These run before any early return so --json mode still logs and saves
        $this->logUsage($tracker, $report);

        if ($this->option('save')) {
            $this->saveResults($report, $elapsedMs);
        }

        if ($this->option('json')) {
            return $this->outputJson($report, $confirmed, $reviewItems, $elapsedMs);
        }

        $this->line('  <fg=green>✓</> Scan complete <fg=gray>('.round($elapsedMs / 1000, 1).'s)</>');
        $this->newLine();
        $this->displayAnalyzedPaths();

        $this->displayFileSummary($report);
        $this->newLine();
        $this->displayCoverage($report);
        $this->displayScore($report);
        $this->newLine();
        $this->displaySummary($report->summary);
        $this->newLine();

        $this->displayConfirmedSection($report, $confirmed);
        $this->displayReviewSection($reviewItems);

        $this->displayStats($confirmed, $reviewItems, $minimumSeverity);
        $this->newLine();

        if ($this->option('fix') && count($confirmed) > 0) {
            $this->displayFixes($confirmed);
            $this->newLine();
        }

        if ($this->option('update-baseline')) {
            $this->updateBaseline($report);
        }

        if ($this->option('html')) {
            $this->generateHtmlReport($report, $elapsedMs);
        }

        $this->displayScanComparison($report);

        $this->displayVerificationSummary($report);

        $this->displayUsageSummary($report);

        $this->displaySkipRemediation($report);

        $this->components->info('Run `<fg=cyan>php artisan hack:ctf</>` to generate CTF challenges from these findings');

        // hasCritical() counts CONFIRMED vulnerabilities only, so a review item
        // can never fail a build no matter how bad it would be if it were real.
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
     * Filter findings to only include those at or above the minimum severity.
     *
     * This is a DISPLAY filter over both classes — for a review item severity
     * means "impact if this turns out to be real", so the same threshold hides
     * the quiet ones. It is not the build gate: the exit code is decided by
     * VulnerabilityReport::hasCritical(), which sees confirmed vulnerabilities
     * only, so no --severity value can ever promote a question into a failure.
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
     * Keep only the findings the analyzer is asserting.
     *
     * @param  array<int, Vulnerability>  $vulnerabilities
     * @return array<int, Vulnerability>
     */
    private function onlyConfirmed(array $vulnerabilities): array
    {
        return array_values(array_filter(
            $vulnerabilities,
            static fn (Vulnerability $v): bool => $v->isConfirmedVulnerability(),
        ));
    }

    /**
     * Keep only the findings the analyzer is asking about.
     *
     * @param  array<int, Vulnerability>  $vulnerabilities
     * @return array<int, Vulnerability>
     */
    private function onlyReviewItems(array $vulnerabilities): array
    {
        return array_values(array_filter(
            $vulnerabilities,
            static fn (Vulnerability $v): bool => $v->isReviewItem(),
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
        $confirmed = $report->confirmedVulnerabilities();
        $findings = count($confirmed);
        $uniqueLocations = count(array_unique(array_map(
            fn (Vulnerability $v): string => $v->location,
            $confirmed,
        )));

        // "affected files", not "files" — this counts files with findings, not
        // files scanned. Sitting next to the coverage line, the old wording
        // ("0 vulnerabilities across 0 files") read as "0 files were scanned".
        $this->components->info("Found <options=bold>{$findings}</> vulnerabilities in <options=bold>{$uniqueLocations}</> affected file(s)");

        $reviewCount = $report->reviewCount();

        if ($reviewCount > 0) {
            $this->line("  <fg=gray>plus</>     <fg=yellow>{$reviewCount}</> item(s) flagged for human review <fg=gray>(not counted as vulnerabilities)</>");
        }
    }

    /**
     * Display scan coverage, naming every file that was NOT analysed.
     *
     * A count alone ("1 chunk(s) were skipped") is unusable: the reader cannot
     * tell whether the gap covers a README or the payments controller. Every
     * unanalysed file is listed by path with the reason it was skipped.
     */
    private function displayCoverage(VulnerabilityReport $report): void
    {
        $coverage = $report->getCoverage();

        if ($coverage === null) {
            return;
        }

        if ($coverage->isComplete()) {
            $this->line(sprintf(
                '  <fg=gray>coverage</>  <fg=green>%d/%d files analyzed (100%%)</>',
                $coverage->filesAnalyzed,
                $coverage->filesDiscovered,
            ));
            $this->newLine();

            return;
        }

        if ($coverage->filesDiscovered === 0) {
            $this->line('  <fg=gray>coverage</>  <fg=yellow>0 files discovered — nothing was analyzed</>');
            $this->newLine();

            return;
        }

        $this->line(sprintf(
            '  <fg=gray>coverage</>  <fg=red;options=bold>%d/%d files analyzed (%s%%) — INCOMPLETE</>',
            $coverage->filesAnalyzed,
            $coverage->filesDiscovered,
            $coverage->percent(),
        ));
        $this->newLine();

        $this->components->warn(sprintf(
            '%d file(s) were NOT analyzed. Findings below cannot be treated as complete.',
            $coverage->filesSkipped(),
        ));

        foreach ($coverage->skippedByReason() as $reason => $paths) {
            $this->line('  <fg=yellow>'.ucfirst(ScanCoverage::reasonLabel($reason)).':</>');

            foreach ($paths as $path) {
                $this->line("    <fg=gray>-</> <fg=cyan>{$path}</>");
            }
        }

        $this->newLine();
    }

    /**
     * Tell the user how to close each kind of coverage gap.
     *
     * Grouped by reason so the remediation matches the cause: a token-budget
     * skip needs a bigger --limit, an unparseable AI response needs a re-run.
     */
    private function displaySkipRemediation(VulnerabilityReport $report): void
    {
        $coverage = $report->getCoverage();

        if ($coverage === null || $coverage->skipped === []) {
            return;
        }

        foreach ($coverage->skippedByReason() as $reason => $paths) {
            $count = count($paths);

            $remediation = match ($reason) {
                ScanCoverage::REASON_TOKEN_LIMIT => 'Increase with --limit or remove the flag for unlimited.',
                ScanCoverage::REASON_AI_FAILURE => 'Re-run the scan to retry those files.',
                default => 'Re-run the scan.',
            };

            $this->components->warn(sprintf(
                '%d file(s) skipped — %s. %s',
                $count,
                ScanCoverage::reasonLabel($reason),
                $remediation,
            ));
        }
    }

    /**
     * Display the overall security score, or withhold it when coverage is
     * incomplete or nothing was analysed.
     *
     * The score is penalty-only — it starts at 100 and drops per finding — so an
     * empty scan used to print a flawless 100/100. A score that rewards scanning
     * nothing is worse than no score, so it is suppressed rather than shown.
     */
    private function displayScore(VulnerabilityReport $report): void
    {
        if (! $report->scoreIsMeaningful()) {
            $this->line('  <fg=yellow;options=bold>╔═══════════════════════╗</>');
            $this->line('  <fg=yellow;options=bold>║   Security Score      ║</>');
            $this->line('  <fg=yellow;options=bold>║     not available     ║</>');
            $this->line('  <fg=yellow;options=bold>╚═══════════════════════╝</>');

            $reason = $report->scoreSuppressionReason();

            if ($reason !== null) {
                $this->newLine();

                foreach (explode("\n", wordwrap($reason, 100)) as $line) {
                    $this->line("  <fg=gray>{$line}</>");
                }
            }

            return;
        }

        $score = $report->overallScore;

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
     * Render the first of the two sections: findings the analyzer asserts.
     *
     * When this section is empty it says so plainly and immediately states what
     * was analysed. "0 confirmed vulnerabilities" is a statement about the
     * evidence, not a clean bill of health, and the coverage line is what stops
     * a reader from reading it as one.
     *
     * @param  array<int, Vulnerability>  $confirmed
     */
    private function displayConfirmedSection(VulnerabilityReport $report, array $confirmed): void
    {
        $count = count($confirmed);

        $this->line("  <fg=red;options=bold>━━━ Confirmed vulnerabilities ({$count}) ━━━</>");
        $this->line('  <fg=gray>Asserted findings: a source, a sink and an unguarded path between them were resolved.</>');
        $this->newLine();

        if ($count === 0) {
            $this->line('  <fg=green>No confirmed vulnerabilities.</> <fg=gray>Nothing below was proven exploitable.</>');

            foreach (explode("\n", wordwrap($report->coverageStatement(), 100)) as $line) {
                $this->line("  <fg=gray>{$line}</>");
            }

            $this->newLine();

            return;
        }

        $this->displayVulnerabilityTable($confirmed);
        $this->newLine();
        $this->displayDetailedFindings($confirmed);
        $this->newLine();
    }

    /**
     * Render the second section: questions for a human, never assertions.
     *
     * Every line here is phrased as a question and no fix is ever printed —
     * a suggested fix implies a diagnosis, and this section exists precisely
     * because the analyzer could not make one.
     *
     * @param  array<int, Vulnerability>  $reviewItems
     */
    private function displayReviewSection(array $reviewItems): void
    {
        $count = count($reviewItems);

        $this->line("  <fg=yellow;options=bold>━━━ Needs review ({$count}) ━━━</>");
        $this->line('  <fg=gray>NOT vulnerabilities. Security-sensitive code the analyzer could not clear or condemn.</>');
        $this->line('  <fg=gray>Excluded from the count, the score and the exit code. No fixes are suggested for these.</>');
        $this->newLine();

        if ($count === 0) {
            $this->line('  <fg=gray>Nothing was flagged for review.</>');
            $this->newLine();

            return;
        }

        foreach ($this->sortBySeverity($reviewItems) as $index => $item) {
            $number = $index + 1;

            $this->line("  <fg=yellow>?</> <options=bold>#{$number} {$item->type->label()}</> <fg=cyan>{$item->location}:{$item->line}</>");
            $this->line("    <fg=gray>Impact if real:</> {$item->severity->label()}  <fg=gray>Confidence:</> <fg=yellow>{$item->confidence->label()}</>");

            foreach (explode("\n", wordwrap($this->asQuestion($item->description), 96)) as $line) {
                $this->line("    <fg=gray>{$line}</>");
            }

            $this->newLine();
        }
    }

    /**
     * Phrase a review item as the question it is.
     *
     * Detectors are expected to write these as questions already; this is a
     * guard for the ones that slip through with an assertion's voice.
     */
    private function asQuestion(string $description): string
    {
        $trimmed = trim($description);

        if ($trimmed === '' || str_contains($trimmed, '?')) {
            return $trimmed;
        }

        return 'Worth checking: '.$trimmed;
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
     * The severity breakdown covers CONFIRMED vulnerabilities only. Review
     * items get their own total on a separate line so they can never pad the
     * headline number.
     *
     * @param  array<int, Vulnerability>  $confirmed
     * @param  array<int, Vulnerability>  $reviewItems
     */
    private function displayStats(array $confirmed, array $reviewItems, SeverityLevel $minimum): void
    {
        $total = count($confirmed);

        $critical = count(array_filter($confirmed, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::Critical));
        $high = count(array_filter($confirmed, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::High));
        $medium = count(array_filter($confirmed, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::Medium));
        $low = count(array_filter($confirmed, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::Low));

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

        $reviewCount = count($reviewItems);

        if ($reviewCount > 0) {
            $this->line("  <fg=yellow>{$reviewCount}</> item(s) need review <fg=gray>(not counted above; they do not affect the score or the exit code)</>");
        }
    }

    /**
     * Display fix suggestions for each vulnerability in styled code blocks.
     *
     * Confirmed vulnerabilities only, and only those that actually carry a fix.
     * A finding with no fix prints nothing rather than an empty code block —
     * a missing fix is fine, an invented one is a catastrophe.
     *
     * @param  array<int, Vulnerability>  $vulnerabilities
     */
    private function displayFixes(array $vulnerabilities): void
    {
        $withFixes = array_values(array_filter(
            $vulnerabilities,
            static fn (Vulnerability $v): bool => $v->isConfirmedVulnerability() && $v->hasFix(),
        ));

        if ($withFixes === []) {
            return;
        }

        $sorted = $this->sortBySeverity($withFixes);

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
     * `vulnerabilities` carries assertions only; questions live under
     * `review_items` so an existing consumer that counts `vulnerabilities`
     * cannot be handed a number inflated by things nobody proved.
     *
     * @param  array<int, Vulnerability>  $confirmed
     * @param  array<int, Vulnerability>  $reviewItems
     */
    private function outputJson(VulnerabilityReport $report, array $confirmed, array $reviewItems, int $elapsedMs): int
    {
        $output = [
            'overall_score' => $report->scoreIsMeaningful() ? $report->overallScore : null,
            'score_suppressed' => ! $report->scoreIsMeaningful(),
            'score_suppression_reason' => $report->scoreSuppressionReason(),
            'coverage' => $report->getCoverage()?->toArray(),
            'coverage_statement' => $report->coverageStatement(),
            'summary' => $report->summary,
            'ctf_idea' => $report->ctfIdea,
            'scan_duration_ms' => $elapsedMs,
            'counts' => [
                'total' => count($confirmed),
                'critical' => count(array_filter($confirmed, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::Critical)),
                'high' => count(array_filter($confirmed, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::High)),
                'medium' => count(array_filter($confirmed, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::Medium)),
                'low' => count(array_filter($confirmed, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::Low)),
                'review' => count($reviewItems),
            ],
            'vulnerabilities' => array_map(
                fn (Vulnerability $v): array => $v->toArray(),
                $confirmed,
            ),
            'review_items' => array_map(
                fn (Vulnerability $v): array => $v->toArray(),
                $reviewItems,
            ),
        ];

        if ($report->hasUsageData()) {
            $output['usage'] = $report->getUsageTracker()->toArray();
            $output['files_skipped'] = $report->getFilesSkipped();
        }

        $output['verification'] = [
            'attempted' => $report->verificationAttempted,
            'verified' => $report->verifiedCount,
            'downgraded' => $report->downgradedCount,
            'input_tokens' => $report->verificationInputTokens,
            'output_tokens' => $report->verificationOutputTokens,
        ];

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
            $report = new VulnerabilityReport(
                vulnerabilities: [],
                overallScore: 100,
                summary: "No changed PHP files found compared to {$baseBranch}.",
                ctfIdea: '',
            );
            $report->setCoverage(ScanCoverage::none());

            return $report;
        }

        // Use scanFile for each changed file so it goes through the full
        // HackScanner pipeline (route context, routed methods, form requests,
        // model context) instead of bypassing it with raw PromptBuilder calls.
        $reports = [];
        $filesAnalyzed = 0;
        $skipped = [];

        foreach ($files as $filePath) {
            try {
                $fileReport = $scanner->scanFile($filePath);
                $reports[] = $fileReport;

                $fileCoverage = $fileReport->getCoverage();

                if ($fileCoverage === null) {
                    $filesAnalyzed++;

                    continue;
                }

                $filesAnalyzed += $fileCoverage->filesAnalyzed;
                $skipped = array_merge($skipped, $fileCoverage->skipped);
            } catch (\Throwable $e) {
                $skipped[] = ['path' => $filePath, 'reason' => ScanCoverage::REASON_AI_FAILURE];

                Log::warning('[HackAuditor] Skipping diff file due to scan failure', [
                    'file' => $filePath,
                    'error' => $e->getMessage(),
                ]);
            }
        }

        $coverage = new ScanCoverage(
            filesDiscovered: count($files),
            filesAnalyzed: $filesAnalyzed,
            skipped: $skipped,
        );

        if (count($reports) === 0) {
            $report = new VulnerabilityReport(
                vulnerabilities: [],
                overallScore: 100,
                summary: 'No files analyzed.',
                ctfIdea: '',
            );
            $report->setCoverage($coverage);

            return $report;
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

        $merged = new VulnerabilityReport(
            vulnerabilities: $allVulns,
            overallScore: (int) round($scoreSum / count($reports)),
            summary: implode("\n\n", $summaries),
            ctfIdea: '',
        );

        $tracker = $reports[0]->getUsageTracker();

        if ($tracker !== null) {
            $merged->setUsageTracker($tracker);
        }

        $merged->setCoverage($coverage);

        return $merged;
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

        $this->components->info("Baseline updated with {$report->allFindingsCount()} findings");
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

            // A suppressed score on either side makes the delta meaningless —
            // comparing "no score" against a number invents a trend.
            if (! $report->scoreIsMeaningful() || ! isset($previous['overall_score'])) {
                return;
            }

            $previousScore = (int) $previous['overall_score'];
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
     * Log usage data to the filesystem usage log.
     *
     * Reads the tracker the command handed to the scanner rather than the one
     * attached to the report. The tracker is the authoritative record of spend:
     * it is mutated in place by every AI request, so it survives report
     * rebuilds, partial chunk failures and an outright crash. A null report
     * means the scan aborted after spending.
     */
    private function logUsage(UsageTracker $tracker, ?VulnerabilityReport $report): void
    {
        if (! config('hack-auditor.usage.log_enabled', true)) {
            return;
        }

        $spent = $tracker->getRequests() > 0
            || $tracker->getVerificationRequests() > 0
            || $tracker->totalTokens() > 0;

        if (! $spent) {
            return;
        }

        try {
            $usageLog = new UsageLog;
            $detectedPricing = AiProviders::detectPricing();
            $coverage = $report?->getCoverage();

            $usageLog->record($tracker, [
                'files_scanned' => $coverage?->filesAnalyzed,
                'files_skipped' => $report?->getFilesSkipped() ?? 0,
                'coverage_complete' => $coverage?->isComplete(),
                'aborted' => $report === null,
                'path' => is_string($this->option('path')) ? $this->option('path') : null,
                'score' => ($report !== null && $report->scoreIsMeaningful()) ? $report->overallScore : null,
                'provider' => $detectedPricing['provider'],
                'model' => $detectedPricing['model'],
            ]);
        } catch (\Throwable) {
            // Usage logging is best-effort
        }
    }

    /**
     * Display the multi-pass verification summary after a --verify run.
     *
     * Surfaces how many HIGH+ findings the AI confirmed with a concrete
     * exploit, how many were downgraded, and the verification token spend
     * so users can separate pass-1 from pass-2 cost.
     */
    private function displayVerificationSummary(VulnerabilityReport $report): void
    {
        if (! $report->verificationAttempted) {
            return;
        }

        $totalHighPlus = $report->verifiedCount + $report->downgradedCount;
        $this->newLine();
        $this->line(sprintf(
            '  <fg=magenta;options=bold>Verification</> %d/%d HIGH+ findings had working exploits <fg=gray>(%d downgraded)</>',
            $report->verifiedCount,
            $totalHighPlus,
            $report->downgradedCount,
        ));

        $verificationTokens = $report->verificationInputTokens + $report->verificationOutputTokens;
        if ($verificationTokens > 0) {
            $this->line(sprintf(
                '  <fg=gray>Verification tokens:</> %s input + %s output = <fg=white>%s total</>',
                number_format($report->verificationInputTokens),
                number_format($report->verificationOutputTokens),
                number_format($verificationTokens),
            ));
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
                sprintf('%s <fg=gray>(%s)</>', $modelName, $pricing['provider']),
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
