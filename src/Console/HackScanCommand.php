<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Console;

use Illuminate\Console\Command;

use function Laravel\Prompts\spin;

use Mahdi\HackAuditor\Report\HtmlReportGenerator;
use Mahdi\HackAuditor\Report\MarkdownReportGenerator;
use Mahdi\HackAuditor\Report\SarifReportGenerator;
use Mahdi\HackAuditor\Scanner\Baseline;
use Mahdi\HackAuditor\Scanner\FileCollector;
use Mahdi\HackAuditor\Scanner\HackScanner;
use Mahdi\HackAuditor\Scanner\ScanCoverage;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\AiProviders;
use Mahdi\HackAuditor\Support\ConsoleText;
use Mahdi\HackAuditor\Support\References;
use Mahdi\HackAuditor\Support\ScanHistory;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\UsageLog;
use Mahdi\HackAuditor\Support\UsageTracker;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class HackScanCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'hack:scan
        {--path= : Scan a specific file or directory}
        {--severity= : Minimum severity to report and gate on (default: config severity.minimum_report, else Low)}
        {--fix : Show suggested fixes (only for confirmed findings that carry one)}
        {--json : Output as JSON (alias for --format=json)}
        {--format= : Output format: table, json, sarif or markdown (default: table)}
        {--fail-on=critical : Exit 1 when a confirmed finding at or above this severity remains after filters: critical, high, medium, low or none}
        {--html : Generate an HTML report}
        {--save : Save results to JSON file}
        {--force : Skip confirmation prompt for large scans}
        {--detailed : Show full descriptions in the table instead of truncating}
        {--diff : Only scan files changed in the current git branch}
        {--base= : Base branch for --diff comparison (default: auto-detect main/master)}
        {--baseline : Require the baseline: fail with exit 2 if the baseline file is missing (it is applied automatically whenever it exists)}
        {--no-baseline : Ignore the baseline file}
        {--update-baseline : Save current findings as the new baseline}
        {--limit= : Maximum token budget for this scan (stops scanning when reached)}
        {--verify : Run multi-pass exploit verification on HIGH+ findings (doubles API cost on those findings)}
        {--deterministic : Run only the reproducible access-control engine — no AI request, no API key, no cost}';

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
     * Output formats accepted by --format.
     *
     * @var array<int, string>
     */
    private const array FORMATS = ['table', 'json', 'sarif', 'markdown'];

    /**
     * Resolved --format value.
     */
    private string $format = 'table';

    /**
     * Resolved --severity value.
     */
    private SeverityLevel $minimumSeverity = SeverityLevel::Low;

    /**
     * Resolved --fail-on threshold; null means never fail on findings.
     */
    private ?SeverityLevel $failOnThreshold = SeverityLevel::Critical;

    /**
     * How many findings the baseline suppressed in this run.
     */
    private int $baselineSuppressed = 0;

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $startTime = hrtime(true);

        // Validate every option BEFORE the scan: a typo in --format or
        // --fail-on must not be discovered after paying for the AI requests.
        $optionError = $this->resolveOptions();

        if ($optionError !== null) {
            $this->components->error($optionError);

            return self::INVALID;
        }

        $machineOutput = $this->isMachineOutput();

        if (! $machineOutput) {
            $this->displayBanner();
            $this->line('');

            $provider = config('hack-auditor.ai.provider', 'laravel-ai');
            $model = config('hack-auditor.ai.model', 'default');
            $fileCount = $this->estimateFileCount();

            $this->line('  <fg=gray>target</>   '.$fileCount.' files');
            $this->line('  <fg=gray>engine</>   '.($this->option('deterministic')
                ? 'deterministic access-control engine (no AI, $0)'
                : $provider.' / '.$model));
            $this->line('');
            $this->line('  <fg=yellow>●</> Collecting files...');
        }

        /** @var HackScanner $scanner */
        $scanner = app(HackScanner::class);

        // Set up usage tracking with auto-detected pricing
        $tokenLimit = (int) ($this->option('limit') ?: config('hack-auditor.usage.default_limit', 0));
        $tracker = UsageTracker::forCurrentConfig($tokenLimit);
        $scanner->setUsageTracker($tracker);

        $deterministic = (bool) $this->option('deterministic');
        $scanner->setDeterministic($deterministic);

        $verifyEnabled = ! $deterministic
            && ($this->option('verify') || (bool) config('hack-auditor.verification.enabled', false));
        $scanner->setVerify($verifyEnabled);

        if (! $machineOutput && $tracker->isLimitSet()) {
            $this->line('  <fg=gray>limit</>    '.number_format($tracker->getTokenLimit()).' tokens');
        }

        $path = $this->option('path');

        if (! is_string($path) || $path === '') {
            if (! $machineOutput && ! $this->option('force') && ! $deterministic && ! $this->option('diff')) {
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
                return $scanner->scanDiff($this->diffBaseBranch(), is_string($path) && $path !== '' ? $path : null);
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
            $report = $machineOutput
                ? $scanCallback()
                : spin(
                    callback: $scanCallback,
                    message: $deterministic ? 'Analyzing files...' : 'Analyzing files with AI...',
                );
        } catch (\Throwable $e) {
            $this->logUsage($tracker, null);

            throw $e;
        }

        $elapsedMs = (int) ((hrtime(true) - $startTime) / 1_000_000);

        // Runs before any early return so every output mode still logs spend.
        $this->logUsage($tracker, $report);

        // A missing, refused or unresolvable target means nothing was scanned.
        // Exit 2 in every output mode: a mistyped --path in CI must fail the
        // job, not pass it with an empty "0 vulnerabilities" report. Such a run
        // is never saved, so it cannot become the "previous scan" either.
        if ($report->getTargetError() !== null) {
            return $this->outputTargetError($report, $elapsedMs);
        }

        $filteredVulnerabilities = $this->filterBySeverity($report->vulnerabilities, $this->minimumSeverity);
        $filteredVulnerabilities = $this->applyBaseline($filteredVulnerabilities, $report);

        // Two classes, never mixed: assertions the analyzer can back with an
        // evidence chain, and questions it wants a human to answer. Only the
        // first list is counted, scored or allowed to fail the build.
        $confirmed = $this->onlyConfirmed($filteredVulnerabilities);
        $reviewItems = $this->onlyReviewItems($filteredVulnerabilities);

        // The build gate sees exactly what the user sees: confirmed findings
        // that survived --severity and the baseline, at or above --fail-on.
        $exitCode = $this->exitCodeFor($confirmed);

        // Read the previous scan BEFORE saving this one — otherwise --save makes
        // this scan its own predecessor and the delta is always 0.
        $previousScan = $this->latestSavedScan();

        if ($this->option('save')) {
            $this->saveResults($report, $elapsedMs);
        }

        if ($this->option('update-baseline')) {
            $this->updateBaseline($report);
        }

        if ($this->option('html')) {
            $this->generateHtmlReport($report, $elapsedMs);
        }

        if ($this->format === 'json') {
            $this->outputJson($report, $confirmed, $reviewItems, $elapsedMs);

            return $exitCode;
        }

        if ($this->format === 'sarif') {
            $this->writeRaw((new SarifReportGenerator)->generate($report, $confirmed, $reviewItems));

            return $exitCode;
        }

        if ($this->format === 'markdown') {
            $this->writeRaw((new MarkdownReportGenerator)->generate($report, $confirmed, $reviewItems));

            return $exitCode;
        }

        $this->line('  <fg=green>✓</> Scan complete <fg=gray>('.round($elapsedMs / 1000, 1).'s)</>');
        $this->newLine();
        $this->displayAnalyzedPaths();

        $this->displayFileSummary($confirmed, $reviewItems);
        $this->newLine();
        $this->displayCoverage($report);
        $this->displayScore($report);
        $this->newLine();
        $this->displaySummary($report->summary);
        $this->newLine();

        $this->displayConfirmedSection($report, $confirmed);
        $this->displayReviewSection($reviewItems);

        $this->displayStats($confirmed, $reviewItems, $this->minimumSeverity);
        $this->newLine();

        if ($this->option('fix') && count($confirmed) > 0) {
            $this->displayFixes($confirmed);
            $this->newLine();
        }

        $this->displayScanComparison($report, $previousScan);

        $this->displayVerificationSummary($report);

        $this->displayUsageSummary($report);

        $this->displaySkipRemediation($report);

        $this->components->info('Run `<fg=cyan>php artisan hack:ctf</>` to generate CTF challenges from these findings');

        return $exitCode;
    }

    /**
     * The --diff base: --base, else the configured diff base, else null to
     * auto-detect main/master.
     */
    private function diffBaseBranch(): ?string
    {
        $base = $this->option('base');

        if (is_string($base) && trim($base) !== '') {
            return trim($base);
        }

        /** @var ?string $configured */
        $configured = config('hack-auditor.scan.diff_base_branch');

        return is_string($configured) && $configured !== '' ? $configured : null;
    }

    /**
     * Resolve and validate --format, --json, --severity, --fail-on and the
     * baseline flags. Returns an error message, or null when all are valid.
     */
    private function resolveOptions(): ?string
    {
        $format = $this->option('format');
        $format = is_string($format) && $format !== '' ? strtolower(trim($format)) : null;

        if ($this->option('json')) {
            if ($format !== null && $format !== 'json') {
                return "--json conflicts with --format={$format}. Use one or the other.";
            }

            $format = 'json';
        }

        $format ??= 'table';

        if (! in_array($format, self::FORMATS, true)) {
            return "Unknown --format '{$format}'. Use one of: ".implode(', ', self::FORMATS).'.';
        }

        $this->format = $format;

        $severityOption = $this->option('severity');
        $configSeverity = config('hack-auditor.severity.minimum_report', 'Low');
        $severity = is_string($severityOption) && $severityOption !== ''
            ? $severityOption
            : (is_string($configSeverity) && $configSeverity !== '' ? $configSeverity : 'Low');

        $resolvedSeverity = $this->parseSeverity($severity);

        if ($resolvedSeverity === null) {
            return "Unknown severity '{$severity}'. Use one of: ".$this->severityNames().'.';
        }

        $this->minimumSeverity = $resolvedSeverity;

        $failOn = $this->option('fail-on');
        $failOn = is_string($failOn) && $failOn !== '' ? strtolower(trim($failOn)) : 'critical';

        if ($failOn === 'none') {
            $this->failOnThreshold = null;
        } else {
            $threshold = $this->parseSeverity($failOn);

            if ($threshold === null) {
                return "Unknown --fail-on '{$failOn}'. Use one of: ".$this->severityNames().', none.';
            }

            $this->failOnThreshold = $threshold;
        }

        if ($this->option('baseline') && $this->option('no-baseline')) {
            return '--baseline and --no-baseline contradict each other. Use one.';
        }

        if ($this->option('baseline')) {
            $baseline = new Baseline;

            if (! $baseline->exists()) {
                return 'No baseline file at '.$baseline->resolvePath().'. --baseline requires one; create it with --update-baseline.';
            }
        }

        return null;
    }

    /**
     * Parse a severity name strictly. SeverityLevel::fromString() falls back
     * to Low on a typo, which would silently turn "--fail-on=hgih" into the
     * strictest possible gate.
     */
    private function parseSeverity(string $value): ?SeverityLevel
    {
        return SeverityLevel::tryFrom(strtolower(trim($value)));
    }

    /**
     * Comma-separated list of valid severity values.
     */
    private function severityNames(): string
    {
        return implode(', ', array_map(static fn (SeverityLevel $s): string => $s->value, SeverityLevel::cases()));
    }

    /**
     * Whether stdout carries a machine-readable document that must contain
     * nothing but that document.
     */
    private function isMachineOutput(): bool
    {
        return $this->format !== 'table';
    }

    /**
     * Decide the exit code from the findings that survived every filter.
     *
     * Previously the gate read the UNFILTERED report, so a critical finding
     * the team had accepted into the baseline — or one hidden by --severity —
     * still failed the build while the output showed nothing wrong.
     *
     * @param  array<int, Vulnerability>  $confirmed
     */
    private function exitCodeFor(array $confirmed): int
    {
        if ($this->failOnThreshold === null) {
            return self::SUCCESS;
        }

        // Ranked by the scoring weight so any severity level SeverityLevel
        // defines is ordered correctly without a second lookup table.
        $thresholdWeight = $this->failOnThreshold->weight();

        foreach ($confirmed as $finding) {
            if ($finding->isConfirmedVulnerability() && $finding->severity->weight() >= $thresholdWeight) {
                return self::FAILURE;
            }
        }

        return self::SUCCESS;
    }

    /**
     * Report a scan whose target could not be analysed, and exit 2.
     */
    private function outputTargetError(VulnerabilityReport $report, int $elapsedMs): int
    {
        if ($this->format === 'json') {
            $this->outputJson($report, [], [], $elapsedMs);

            return self::INVALID;
        }

        if ($this->format === 'sarif') {
            $this->writeRaw((new SarifReportGenerator)->generate($report, [], []));

            return self::INVALID;
        }

        if ($this->format === 'markdown') {
            $this->writeRaw((new MarkdownReportGenerator)->generate($report, [], []));

            return self::INVALID;
        }

        $this->newLine();
        $this->components->error('Nothing was scanned: '.ConsoleText::clean((string) $report->getTargetError()));

        return self::INVALID;
    }

    /**
     * Write a machine-readable document to stdout exactly as given.
     *
     * OUTPUT_RAW bypasses the console formatter: through line(), a finding
     * description containing "<error>" or "<href=…>" would be interpreted as a
     * style tag and silently removed from the JSON/SARIF, corrupting the data.
     */
    private function writeRaw(string $document): void
    {
        $this->output->writeln($document, OutputInterface::OUTPUT_RAW);
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
     * the quiet ones. The build gate (exitCodeFor) then reads only the
     * CONFIRMED findings that survived this filter, so no --severity value can
     * ever promote a question into a failure.
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
     *
     * Counts the same filtered lists as displayStats() and the exit code. It
     * used to count the unfiltered report, so the header said "3
     * vulnerabilities" while the footer, after --severity or the baseline,
     * said 1.
     *
     * @param  array<int, Vulnerability>  $confirmed
     * @param  array<int, Vulnerability>  $reviewItems
     */
    private function displayFileSummary(array $confirmed, array $reviewItems): void
    {
        $findings = count($confirmed);
        $uniqueLocations = count(array_unique(array_map(
            fn (Vulnerability $v): string => $v->location,
            $confirmed,
        )));

        // "affected files", not "files" — this counts files with findings, not
        // files scanned. Sitting next to the coverage line, the old wording
        // ("0 vulnerabilities across 0 files") read as "0 files were scanned".
        $this->components->info("Found <options=bold>{$findings}</> vulnerabilities in <options=bold>{$uniqueLocations}</> affected file(s)");

        $reviewCount = count($reviewItems);

        if ($reviewCount > 0) {
            $this->line("  <fg=gray>plus</>     <fg=yellow>{$reviewCount}</> item(s) flagged for human review <fg=gray>(not counted as vulnerabilities)</>");
        }

        if ($this->baselineSuppressed > 0) {
            $this->line("  <fg=gray>baseline</> {$this->baselineSuppressed} known finding(s) suppressed");
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
                $this->line('    <fg=gray>-</> <fg=cyan>'.ConsoleText::clean($path).'</>');
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

        $this->displayScoreBreakdown($report);
    }

    /**
     * Show how the score was derived, so it can be checked by hand.
     *
     * Only printed when the breakdown reproduces the reported score: a
     * derivation that does not add up would be worse than none.
     */
    private function displayScoreBreakdown(VulnerabilityReport $report): void
    {
        $breakdown = $report->scoreBreakdown();

        if ($breakdown === null || $breakdown['score'] !== $report->overallScore) {
            return;
        }

        $terms = [];

        foreach ($breakdown['severities'] as $entry) {
            if ($entry['count'] > 0) {
                $terms[] = "{$entry['count']}×{$entry['weight']} {$entry['severity']}";
            }
        }

        $derivation = $terms === []
            ? '100 − 0 (no confirmed vulnerabilities)'
            : 'max(0, 100 − '.implode(' − ', $terms).')';

        $this->line("  <fg=gray>score = {$derivation}</>");
    }

    /**
     * Display the summary paragraphs from the AI analysis, word-wrapped for readability.
     */
    private function displaySummary(string $summary): void
    {
        $paragraphs = preg_split('/\n{2,}/', trim($summary));

        foreach ($paragraphs as $index => $paragraph) {
            $paragraph = (string) preg_replace('/\s+/', ' ', trim(ConsoleText::stripControlCharacters($paragraph)));
            $wrapped = wordwrap($paragraph, 100);

            foreach (explode("\n", $wrapped) as $line) {
                $this->line('  <fg=gray>'.ConsoleText::clean($line).'</>');
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
                $this->line('  <fg=gray>'.ConsoleText::clean($line).'</>');
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

            $location = ConsoleText::clean("{$item->location}:{$item->line}");

            $this->line("  <fg=yellow>?</> <options=bold>#{$number} {$item->type->label()}</> <fg=cyan>{$location}</>");
            $this->line("    <fg=gray>Impact if real:</> {$item->severity->label()}  <fg=gray>Confidence:</> <fg=yellow>{$item->confidence->label()}</>");

            foreach (explode("\n", wordwrap($this->asQuestion(ConsoleText::stripControlCharacters($item->description)), 96)) as $line) {
                $this->line('    <fg=gray>'.ConsoleText::clean($line).'</>');
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
     * Every cell of finding text is escaped: the table renderer runs cells
     * through the console formatter, so an unescaped "<href=…>" in an AI
     * description becomes a live terminal hyperlink.
     *
     * @param  array<int, Vulnerability>  $vulnerabilities
     */
    private function displayVulnerabilityTable(array $vulnerabilities): void
    {
        $sorted = $this->sortBySeverity($vulnerabilities);
        $isVerbose = $this->option('detailed');

        $rows = [];
        foreach ($sorted as $index => $vuln) {
            $description = ConsoleText::stripControlCharacters($vuln->description);
            $description = $isVerbose
                ? $description
                : $this->truncateDescription($description, 120);

            $rows[] = [
                '<fg=gray>'.($index + 1).'</>',
                $vuln->severity->label(),
                "<options=bold>{$vuln->type->label()}</>",
                '<fg=cyan>'.ConsoleText::clean("{$vuln->location}:{$vuln->line}").'</>',
                $vuln->confidence->label(),
                $vuln->type->cweId(),
                ConsoleText::clean($description),
            ];
        }

        $this->table(
            ['<options=bold>#</>', '<options=bold>Severity</>', '<options=bold>Type</>', '<options=bold>Location:Line</>', '<options=bold>Confidence</>', '<options=bold>CWE</>', '<options=bold>Description</>'],
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
            $this->line('  <fg=gray>Location:</> <fg=cyan>'.ConsoleText::clean("{$vuln->location}:{$vuln->line}").'</>');
            $this->line("  <fg=gray>Severity:</> {$vuln->severity->label()}");
            $this->line("  <fg=gray>Confidence:</> {$vuln->confidence->label()} <fg=gray>— {$vuln->confidence->explanation()}</>");
            $this->line("  <fg=gray>CWE:</> {$vuln->type->cweId()} <fg=gray>({$vuln->type->owaspCategory()})</>");

            $cweUrl = References::cweUrl($vuln->type);

            if ($cweUrl !== null) {
                $this->line("  <fg=gray>Reference:</> {$cweUrl}");
            }

            $this->newLine();
            $this->line('  <fg=white;options=bold>Description:</>');

            foreach (explode("\n", wordwrap(ConsoleText::stripControlCharacters($vuln->description), 100)) as $descLine) {
                $this->line('    <fg=gray>'.ConsoleText::clean($descLine).'</>');
            }

            if ($vuln->taintTrace !== null && trim($vuln->taintTrace) !== '') {
                $this->newLine();
                $this->line('  <fg=white;options=bold>Taint trace:</>');

                foreach (explode("\n", ConsoleText::stripControlCharacters($vuln->taintTrace)) as $traceLine) {
                    $this->line('    <fg=gray>'.ConsoleText::clean($traceLine).'</>');
                }
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
            $this->line('  <fg=gray>Location:</> <fg=cyan>'.ConsoleText::clean("{$vuln->location}:{$vuln->line}").'</>');
            $this->line("  <fg=gray>Severity:</> {$vuln->severity->label()}");
            $this->newLine();
            $this->line('  <fg=green;options=bold>Recommended fix:</>');
            $this->newLine();

            foreach (explode("\n", ConsoleText::stripControlCharacters($vuln->fix)) as $fixLine) {
                $this->line('    <fg=green>'.ConsoleText::clean($fixLine).'</>');
            }

            $this->newLine();
        }
    }

    /**
     * Output the report as JSON.
     *
     * Built from VulnerabilityReport::toArray() so every field the report
     * knows about (fingerprints, references, score breakdown, target error,
     * coverage, usage, verification) is emitted, then narrowed to the findings
     * that survived --severity and the baseline. `vulnerabilities` carries
     * assertions only; questions live under `review_items` so an existing
     * consumer that counts `vulnerabilities` cannot be handed a number
     * inflated by things nobody proved.
     *
     * @param  array<int, Vulnerability>  $confirmed
     * @param  array<int, Vulnerability>  $reviewItems
     */
    private function outputJson(VulnerabilityReport $report, array $confirmed, array $reviewItems, int $elapsedMs): void
    {
        $output = $report->toArray();

        $output['scan_duration_ms'] = $elapsedMs;
        $output['counts'] = [
            'total' => count($confirmed),
            'critical' => count(array_filter($confirmed, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::Critical)),
            'high' => count(array_filter($confirmed, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::High)),
            'medium' => count(array_filter($confirmed, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::Medium)),
            'low' => count(array_filter($confirmed, fn (Vulnerability $v): bool => $v->severity === SeverityLevel::Low)),
            'review' => count($reviewItems),
        ];
        $output['vulnerabilities'] = $report->findingsToArray($confirmed);
        $output['review_items'] = $report->findingsToArray($reviewItems);
        $output['filters'] = [
            'minimum_severity' => $this->minimumSeverity->value,
            'baseline_suppressed' => $this->baselineSuppressed,
            'fail_on' => $this->failOnThreshold === null ? 'none' : $this->failOnThreshold->value,
        ];

        // Invalid UTF-8 in AI-quoted source used to make json_encode() return
        // false, which printed an EMPTY line and exited 0 — CI saw no findings.
        $this->writeRaw(json_encode(
            $output,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR,
        ));
    }

    /**
     * Save scan results to a JSON file.
     *
     * The full report array is saved — coverage, usage, verification counts,
     * fingerprints and every finding field — so hack:report can regenerate
     * exactly what this scan showed.
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

            $id = $history->save($data);

            if (! $this->isMachineOutput()) {
                $this->components->info("Scan saved: <fg=cyan>{$id}</>");
            }
        } catch (\Throwable $e) {
            $this->errorOutput("Failed to save results: {$e->getMessage()}");
        }
    }

    /**
     * The most recent saved scan, or null when there is none or it is unreadable.
     *
     * @return array<string, mixed>|null
     */
    private function latestSavedScan(): ?array
    {
        try {
            return (new ScanHistory)->latest();
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Print an error without corrupting a machine-readable stdout document.
     */
    private function errorOutput(string $message): void
    {
        if ($this->isMachineOutput() && $this->output->getOutput() instanceof ConsoleOutputInterface) {
            $this->output->getOutput()->getErrorOutput()->writeln('<error>'.ConsoleText::clean($message).'</error>');

            return;
        }

        if (! $this->isMachineOutput()) {
            $this->components->error(ConsoleText::clean($message));
        }
    }

    /**
     * Apply baseline filtering to suppress known findings.
     *
     * Findings are matched by the fingerprint the full report assigned them
     * (see Baseline), so filtering a subset cannot renumber duplicates.
     *
     * @param  array<int, Vulnerability>  $vulnerabilities
     * @return array<int, Vulnerability>
     */
    private function applyBaseline(array $vulnerabilities, VulnerabilityReport $report): array
    {
        $this->baselineSuppressed = 0;

        if ($this->option('no-baseline')) {
            return $vulnerabilities;
        }

        $baseline = new Baseline;

        if (! $baseline->exists()) {
            return $vulnerabilities;
        }

        $baseline->load();
        $result = $baseline->filter($vulnerabilities, $report);
        $this->baselineSuppressed = $result['suppressed'];

        if ($result['suppressed'] > 0 && ! $this->isMachineOutput()) {
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
        $baseline->save($report);

        if (! $this->isMachineOutput()) {
            $this->components->info("Baseline updated with {$report->allFindingsCount()} findings");
        }
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
                'provider' => (string) config('hack-auditor.ai.provider', 'default'),
                'model' => (string) config('hack-auditor.ai.model', 'default'),
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

            if (! $this->isMachineOutput()) {
                $this->components->info("HTML report saved to <fg=cyan>{$fullPath}</>");
            }
        } catch (\Throwable $e) {
            $this->errorOutput("Failed to generate HTML report: {$e->getMessage()}");
        }
    }

    /**
     * Display the change since the previous saved scan.
     *
     * $previousScan is read before this run is saved; reading it afterwards
     * compared the scan with itself. Findings are matched by fingerprint, so
     * the new/resolved counts survive AI rewording and code moving around.
     *
     * @param  array<string, mixed>|null  $previousScan
     */
    private function displayScanComparison(VulnerabilityReport $report, ?array $previousScan): void
    {
        if ($previousScan === null) {
            return;
        }

        try {
            $previous = VulnerabilityReport::fromArray($previousScan);
            $comparison = $report->compareWith($previous);
        } catch (\Throwable) {
            // History comparison is best-effort
            return;
        }

        $this->newLine();

        // A suppressed score on either side makes the delta meaningless —
        // comparing "no score" against a number invents a trend.
        if ($comparison['score_delta'] !== null) {
            $delta = $comparison['score_delta'];
            $deltaSign = $delta > 0 ? '+' : '';
            $deltaColor = $delta > 0 ? 'green' : ($delta < 0 ? 'red' : 'gray');

            $this->line("  <fg={$deltaColor}>Score: {$report->overallScore}/100 ({$deltaSign}{$delta} since last scan)</>");
        }

        $this->line(sprintf(
            '  <fg=gray>Since last scan:</> %d new, %d resolved, %d unchanged confirmed finding(s)',
            count($comparison['new_findings']),
            count($comparison['resolved_findings']),
            count($comparison['unchanged_findings']),
        ));
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
        $pathOption = $this->option('path');

        /** @var array<int, string> $paths */
        $paths = is_string($pathOption) && $pathOption !== ''
            ? [$pathOption]
            : config('hack-auditor.scan.paths', []);

        if ($paths === []) {
            return;
        }

        $this->line('  <fg=gray>analyzed</>  '.ConsoleText::clean(implode(', ', $paths)));
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
