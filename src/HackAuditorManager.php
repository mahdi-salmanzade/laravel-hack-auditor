<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor;

use Illuminate\Contracts\Container\Container;
use Mahdi\HackAuditor\CTF\CTFGenerator;
use Mahdi\HackAuditor\Report\HtmlReportGenerator;
use Mahdi\HackAuditor\Scanner\HackScanner;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\ScanHistory;
use Mahdi\HackAuditor\Support\UsageTracker;

final class HackAuditorManager
{
    private readonly HackScanner $scanner;

    private readonly CTFGenerator $ctfGenerator;

    /**
     * Create a new HackAuditorManager instance.
     */
    public function __construct(private readonly Container $container)
    {
        $this->scanner = $this->container->make(HackScanner::class);
        $this->ctfGenerator = $this->container->make(CTFGenerator::class);
    }

    /**
     * Run a security scan on the application or a specific file.
     *
     * When a path is provided, only that file is scanned. Otherwise,
     * a full application scan is performed using configured paths.
     * An optional UsageTracker can be provided to monitor token consumption.
     */
    public function scan(?string $path = null, ?UsageTracker $tracker = null, bool $deterministic = false): VulnerabilityReport
    {
        if ($tracker !== null) {
            $this->scanner->setUsageTracker($tracker);
        }

        // The scanner is a container singleton, and an MCP server is one long
        // process: set the mode on every call so one request cannot leave it
        // switched on (or off) for the next.
        $this->scanner->setDeterministic($deterministic);

        if ($path !== null) {
            return $this->scanner->scanFile($path);
        }

        return $this->scanner->scan();
    }

    /**
     * Scan only the PHP files changed on the current branch versus a base branch.
     *
     * @param  string|null  $baseBranch  Null auto-detects main/master.
     * @param  string|null  $path  Optional app-relative file or directory to narrow the diff to.
     */
    public function scanDiff(?string $baseBranch = null, ?string $path = null, ?UsageTracker $tracker = null, bool $deterministic = false): VulnerabilityReport
    {
        if ($tracker !== null) {
            $this->scanner->setUsageTracker($tracker);
        }

        $this->scanner->setDeterministic($deterministic);

        return $this->scanner->scanDiff($baseBranch, $path);
    }

    /**
     * Scan a raw code string for security vulnerabilities.
     */
    public function scanCode(string $code): VulnerabilityReport
    {
        return $this->scanner->scanCode($code);
    }

    /**
     * Generate a Capture-The-Flag challenge for a given vulnerability type.
     *
     * Optionally accepts source code to base the challenge on real application code.
     */
    public function generateCTF(string $type, ?string $code = null): string
    {
        return $this->ctfGenerator->generate($type, $code);
    }

    /**
     * Generate an HTML security report from a vulnerability report.
     *
     * @param  array<string, mixed>  $meta
     */
    public function generateReport(VulnerabilityReport $report, array $meta = []): string
    {
        /** @var HtmlReportGenerator $generator */
        $generator = $this->container->make(HtmlReportGenerator::class);

        return $generator->generate($report, $meta);
    }

    /**
     * Return the security score from the latest saved scan.
     *
     * Returns null when no scan has been saved, or when the saved scan withheld
     * its score because coverage was incomplete. Returning 0 in those cases
     * would be indistinguishable from a genuinely catastrophic result.
     */
    public function score(): ?int
    {
        $history = new ScanHistory;
        $latest = $history->latest();

        if ($latest === null || ! isset($latest['overall_score'])) {
            return null;
        }

        return (int) $latest['overall_score'];
    }

    /**
     * Get the scan history instance.
     */
    public function history(): ScanHistory
    {
        return new ScanHistory;
    }
}
