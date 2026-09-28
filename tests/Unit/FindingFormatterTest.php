<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Mcp\Support\FindingFormatter;
use Mahdi\HackAuditor\Scanner\ScanCoverage;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\Confidence;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

it('includes fingerprint, class, confidence and references for every finding', function (): void {
    $report = new VulnerabilityReport([
        new Vulnerability(VulnerabilityType::SqlInjection, 'app/A.php', 3, SeverityLevel::High, 'd', 'p', 'f', confidence: Confidence::Proven),
    ], 80, '', '');
    $report->setCoverage(ScanCoverage::complete(1));

    $structured = FindingFormatter::report($report, 'app')->getStructuredContent();
    $finding = $structured['findings'][0];

    expect($finding['fingerprint'])->toBe($report->fingerprintOf($report->vulnerabilities[0]))
        ->and($finding['class'])->toBe('vulnerability')
        ->and($finding['confidence'])->toBe('proven')
        ->and($finding['references'][0]['url'])->toBe('https://cwe.mitre.org/data/definitions/89.html')
        ->and($structured['score_breakdown']['score'])->toBe(80);
});

it('respects a suppressed score', function (): void {
    $report = (new VulnerabilityReport([], 100, '', ''))->setTargetError('Refused to scan "/etc"');

    $structured = FindingFormatter::report($report, '/etc')->getStructuredContent();

    expect($structured['overall_score'])->toBeNull()
        ->and($structured['score_breakdown'])->toBeNull()
        ->and($structured['target_error'])->toBe('Refused to scan "/etc"');
});
