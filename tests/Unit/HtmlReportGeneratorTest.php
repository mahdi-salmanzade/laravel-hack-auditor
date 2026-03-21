<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Report\HtmlReportGenerator;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

function makeReportVulnerability(
    VulnerabilityType $type = VulnerabilityType::SqlInjection,
    string $location = 'app/Http/Controllers/UserController.php',
    int $line = 42,
    SeverityLevel $severity = SeverityLevel::Critical,
    string $description = 'Raw SQL query with user input.',
    string $proof = 'DB::select("SELECT * FROM users WHERE id = $id")',
    string $fix = 'Use parameterized queries.',
): Vulnerability {
    return new Vulnerability(
        type: $type,
        location: $location,
        line: $line,
        severity: $severity,
        description: $description,
        proof: $proof,
        fix: $fix,
    );
}

it('generates a string containing HTML', function (): void {
    $report = new VulnerabilityReport(
        vulnerabilities: [],
        overallScore: 100,
        summary: 'No issues found.',
        ctfIdea: '',
    );

    $generator = new HtmlReportGenerator;
    $html = $generator->generate($report);

    expect($html)->toBeString()
        ->and($html)->toContain('<html')
        ->and($html)->toContain('</html>');
});

it('contains valid self-contained HTML structure', function (): void {
    $report = new VulnerabilityReport(
        vulnerabilities: [],
        overallScore: 100,
        summary: 'No issues found.',
        ctfIdea: '',
    );

    $generator = new HtmlReportGenerator;
    $html = $generator->generate($report);

    expect($html)->toContain('<!DOCTYPE html')
        ->and($html)->toContain('<head>')
        ->and($html)->toContain('</head>')
        ->and($html)->toContain('<body')
        ->and($html)->toContain('</body>');
});

it('contains the overall score', function (): void {
    $report = new VulnerabilityReport(
        vulnerabilities: [],
        overallScore: 73,
        summary: 'Some issues.',
        ctfIdea: '',
    );

    $generator = new HtmlReportGenerator;
    $html = $generator->generate($report);

    expect($html)->toContain('73');
});

it('contains severity counts', function (): void {
    $vulns = [
        makeReportVulnerability(severity: SeverityLevel::Critical),
        makeReportVulnerability(
            type: VulnerabilityType::Xss,
            severity: SeverityLevel::High,
            description: 'XSS issue.',
        ),
        makeReportVulnerability(
            type: VulnerabilityType::MassAssignment,
            severity: SeverityLevel::Medium,
            location: 'app/Models/User.php',
            description: 'Mass assignment.',
        ),
        makeReportVulnerability(
            type: VulnerabilityType::MissingValidation,
            severity: SeverityLevel::Low,
            location: 'app/Http/Controllers/PostController.php',
            description: 'Missing validation.',
        ),
    ];

    $report = new VulnerabilityReport(
        vulnerabilities: $vulns,
        overallScore: 30,
        summary: 'Multiple issues found.',
        ctfIdea: '',
    );

    $generator = new HtmlReportGenerator;
    $html = $generator->generate($report);

    // The HTML should contain the total count and individual severity counts
    expect($html)->toContain((string) $report->criticalCount())
        ->and($html)->toContain((string) $report->highCount())
        ->and($html)->toContain((string) $report->mediumCount())
        ->and($html)->toContain((string) $report->lowCount());
});

it('contains vulnerability finding cards', function (): void {
    $vuln = makeReportVulnerability();

    $report = new VulnerabilityReport(
        vulnerabilities: [$vuln],
        overallScore: 25,
        summary: 'Critical SQL injection found.',
        ctfIdea: '',
    );

    $generator = new HtmlReportGenerator;
    $html = $generator->generate($report);

    expect($html)->toContain('finding-card')
        ->and($html)->toContain('SQL Injection')
        ->and($html)->toContain('app/Http/Controllers/UserController.php')
        ->and($html)->toContain('CRITICAL');
});

it('generates valid output for empty vulnerability report', function (): void {
    $report = new VulnerabilityReport(
        vulnerabilities: [],
        overallScore: 100,
        summary: 'No issues found.',
        ctfIdea: '',
    );

    $generator = new HtmlReportGenerator;
    $html = $generator->generate($report);

    expect($html)->toContain('No vulnerabilities found.')
        ->and($html)->toContain('100')
        ->and($html)->toContain('<html');
});

it('generates output with multiple vulnerabilities at different severities', function (): void {
    $vulns = [
        makeReportVulnerability(
            type: VulnerabilityType::SqlInjection,
            severity: SeverityLevel::Critical,
            description: 'SQL injection in user query.',
        ),
        makeReportVulnerability(
            type: VulnerabilityType::Xss,
            severity: SeverityLevel::High,
            location: 'app/Http/Controllers/PostController.php',
            description: 'XSS in post display.',
        ),
        makeReportVulnerability(
            type: VulnerabilityType::MissingRateLimit,
            severity: SeverityLevel::Medium,
            location: 'app/Http/Controllers/AuthController.php',
            description: 'Missing rate limit on login.',
        ),
        makeReportVulnerability(
            type: VulnerabilityType::MissingValidation,
            severity: SeverityLevel::Low,
            location: 'app/Http/Controllers/SettingsController.php',
            description: 'Missing validation on settings update.',
        ),
    ];

    $report = new VulnerabilityReport(
        vulnerabilities: $vulns,
        overallScore: 20,
        summary: 'Multiple critical issues found.',
        ctfIdea: '',
    );

    $generator = new HtmlReportGenerator;
    $html = $generator->generate($report);

    expect($html)->toContain('SQL Injection')
        ->and($html)->toContain('Cross-Site Scripting (XSS)')
        ->and($html)->toContain('Missing Rate Limiting')
        ->and($html)->toContain('Missing Input Validation')
        ->and($html)->toContain('CRITICAL')
        ->and($html)->toContain('HIGH')
        ->and($html)->toContain('MEDIUM')
        ->and($html)->toContain('LOW');
});
