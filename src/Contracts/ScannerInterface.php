<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Contracts;

use Mahdi\HackAuditor\Scanner\VulnerabilityReport;

interface ScannerInterface
{
    /**
     * Scan the entire application for vulnerabilities.
     */
    public function scan(): VulnerabilityReport;

    /**
     * Scan a specific file for vulnerabilities.
     */
    public function scanFile(string $path): VulnerabilityReport;

    /**
     * Scan a raw code string for vulnerabilities.
     */
    public function scanCode(string $code): VulnerabilityReport;
}
