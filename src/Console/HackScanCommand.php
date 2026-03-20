<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Console;

use Illuminate\Console\Command;
use Mahdi\HackAuditor\Models\ScanResult;
use Mahdi\HackAuditor\Scanner\HackScanner;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\SeverityLevel;

use function Laravel\Prompts\spin;

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
        {--save : Save results to database}
        {--force : Skip confirmation prompt for large scans}';

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
        }

        /** @var HackScanner $scanner */
        $scanner = app(HackScanner::class);

        if (! $this->option('json')) {
            $this->components->info('Collecting files...');
        }

        $path = $this->option('path');

        if (! is_string($path) || $path === '') {
            if (! $this->option('json') && ! $this->option('force')) {
                $fileCount = $this->estimateFileCount();
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
                if (is_string($path) && $path !== '') {
                    return $scanner->scanFile($path);
                }

                return $scanner->scan();
            },
            message: 'Analyzing with AI...',
        );

        $elapsedMs = (int) ((hrtime(true) - $startTime) / 1_000_000);
        $minimumSeverity = SeverityLevel::fromString((string) $this->option('severity'));
        $filteredVulnerabilities = $this->filterBySeverity($report->vulnerabilities, $minimumSeverity);

        if ($this->option('json')) {
            return $this->outputJson($report, $filteredVulnerabilities, $elapsedMs);
        }

        $this->displayFileSummary($report);
        $this->newLine();
        $this->displayScore($report->overallScore);
        $this->newLine();
        $this->displaySummary($report->summary);
        $this->newLine();

        if (count($filteredVulnerabilities) > 0) {
            $this->displayVulnerabilityTable($filteredVulnerabilities);
            $this->newLine();
        }

        $this->displayStats($report, $filteredVulnerabilities, $minimumSeverity);
        $this->newLine();

        if ($this->option('fix') && count($filteredVulnerabilities) > 0) {
            $this->displayFixes($filteredVulnerabilities);
            $this->newLine();
        }

        if ($this->option('save')) {
            $this->saveResults($report, $elapsedMs);
        }

        $this->components->info('Run `<fg=cyan>php artisan hack:ctf</>` to generate CTF challenges from these findings');

        return $report->hasCritical() ? self::FAILURE : self::SUCCESS;
    }

    /**
     * Display the Hack Auditor ASCII banner.
     */
    private function displayBanner(): void
    {
        $this->newLine();
        $this->line('<fg=cyan>╔══════════════════════════════════════════════════╗</>');
        $this->line('<fg=cyan>║</>  <options=bold>🔥 HACK AUDITOR — AI Security Scanner v1.0</>     <fg=cyan>║</>');
        $this->line('<fg=cyan>║</>  <fg=gray>"Watch AI hack your Laravel app in 15 seconds."</> <fg=cyan>║</>');
        $this->line('<fg=cyan>╚══════════════════════════════════════════════════╝</>');
        $this->newLine();
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
     * Display the summary paragraph from the AI analysis.
     */
    private function displaySummary(string $summary): void
    {
        $this->line("  <fg=gray>{$summary}</>");
    }

    /**
     * Display the vulnerability results as a styled console table.
     *
     * @param  array<int, Vulnerability>  $vulnerabilities
     */
    private function displayVulnerabilityTable(array $vulnerabilities): void
    {
        $sorted = $this->sortBySeverity($vulnerabilities);

        $rows = [];
        foreach ($sorted as $index => $vuln) {
            $rows[] = [
                '<fg=gray>' . ($index + 1) . '</>',
                $vuln->severity->label(),
                "<options=bold>{$vuln->type->label()}</>",
                "<fg=cyan>{$vuln->location}:{$vuln->line}</>",
                $this->truncateDescription($vuln->description, 60),
            ];
        }

        $this->table(
            ['<options=bold>#</>', '<options=bold>Severity</>', '<options=bold>Type</>', '<options=bold>Location:Line</>', '<options=bold>Description</>'],
            $rows,
        );
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

        $this->line((string) json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

        return $report->hasCritical() ? self::FAILURE : self::SUCCESS;
    }

    /**
     * Persist scan results to the database.
     */
    private function saveResults(VulnerabilityReport $report, int $elapsedMs): void
    {
        try {
            ScanResult::create([
                'score' => $report->overallScore,
                'total_vulnerabilities' => $report->totalCount(),
                'critical_count' => $report->criticalCount(),
                'high_count' => $report->highCount(),
                'medium_count' => $report->mediumCount(),
                'low_count' => $report->lowCount(),
                'vulnerabilities' => array_map(
                    fn (Vulnerability $v): array => $v->toArray(),
                    $report->vulnerabilities,
                ),
                'summary' => $report->summary,
                'files_scanned' => count(array_unique(array_map(
                    fn (Vulnerability $v): string => $v->location,
                    $report->vulnerabilities,
                ))),
                'scan_duration_ms' => $elapsedMs,
                'ai_provider' => config('hack-auditor.ai.provider'),
                'ai_model' => config('hack-auditor.ai.model'),
                'laravel_version' => app()->version(),
            ]);

            $this->components->info('Scan results saved to database');
        } catch (\Throwable $e) {
            $this->components->error("Failed to save results: {$e->getMessage()}");
            $this->components->warn('Have you run the migrations? Try: php artisan migrate');
        }
    }

    /**
     * Estimate how many files would be scanned using the FileCollector.
     */
    private function estimateFileCount(): int
    {
        try {
            /** @var \Mahdi\HackAuditor\Scanner\FileCollector $collector */
            $collector = app(\Mahdi\HackAuditor\Scanner\FileCollector::class);

            return $collector->collect()->count();
        } catch (\Throwable) {
            return 0;
        }
    }

    /**
     * Truncate a description string to a maximum length with ellipsis.
     */
    private function truncateDescription(string $description, int $maxLength): string
    {
        if (mb_strlen($description) <= $maxLength) {
            return $description;
        }

        return mb_substr($description, 0, $maxLength - 3) . '...';
    }
}
