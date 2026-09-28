<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Report\MarkdownReportGenerator;
use Mahdi\HackAuditor\Scanner\ScanCoverage;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\Confidence;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

it('renders score, coverage, severity tables and the review section', function (): void {
    $report = new VulnerabilityReport([
        new Vulnerability(VulnerabilityType::SqlInjection, 'app/A.php', 3, SeverityLevel::Critical, 'Raw | SQL <b>', 'p', 'use bindings'),
        new Vulnerability(VulnerabilityType::Idor, 'app/B.php', 9, SeverityLevel::High, 'Is it owner-checked?', 'p', '', confidence: Confidence::Possible),
    ], 60, 'Summary text.', '');
    $report->setCoverage(ScanCoverage::complete(2));

    $markdown = (new MarkdownReportGenerator)->generate($report);

    expect($markdown)->toContain('**Security score:** 60/100')
        ->toContain('All 2 discovered file(s) were analysed.')
        ->toContain('### Critical (1)')
        ->toContain('Raw \| SQL &lt;b&gt;')
        ->toContain('[CWE-89](https://cwe.mitre.org/data/definitions/89.html)')
        ->toContain('## Needs review (1)')
        ->toContain('Is it owner-checked?')
        ->toContain('Suggested fixes (1)');
});

it('states why the score is withheld and lists skipped files', function (): void {
    $report = new VulnerabilityReport([], 100, '', '');
    $report->setCoverage(new ScanCoverage(2, 1, [['path' => 'app/Skipped.php', 'reason' => ScanCoverage::REASON_AI_FAILURE]]));

    $markdown = (new MarkdownReportGenerator)->generate($report);

    expect($markdown)->toContain('**Security score:** withheld')
        ->not->toContain('100/100')
        ->toContain('Files NOT analysed (1)')
        ->toContain('app/Skipped.php');
});
