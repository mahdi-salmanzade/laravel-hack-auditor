<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor;

use Illuminate\Contracts\Container\Container;
use Mahdi\HackAuditor\CTF\CTFGenerator;
use Mahdi\HackAuditor\Models\ScanResult;
use Mahdi\HackAuditor\Report\HtmlReportGenerator;
use Mahdi\HackAuditor\Scanner\HackScanner;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;

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
     */
    public function scan(?string $path = null): VulnerabilityReport
    {
        if ($path !== null) {
            return $this->scanner->scanFile($path);
        }

        return $this->scanner->scan();
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
     * Return the security score from the latest scan, or 0 if no scans exist.
     */
    public function score(): int
    {
        /** @var ScanResult|null $latest */
        $latest = ScanResult::query()->latest()->first();

        return $latest?->score ?? 0;
    }
}
