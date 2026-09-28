<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Report\HtmlReportGenerator;
use Mahdi\HackAuditor\Scanner\ScanCoverage;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\Confidence;
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

it('html-escapes a vulnerability description containing a script tag', function (): void {
    $report = new VulnerabilityReport(
        vulnerabilities: [
            makeReportVulnerability(
                description: 'XSS demo: <script>alert("xss")</script> injected here.',
            ),
        ],
        overallScore: 40,
        summary: 'One finding.',
        ctfIdea: '',
    );

    $generator = new HtmlReportGenerator;
    $html = $generator->generate($report);

    expect($html)->toContain('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;')
        ->and($html)->not->toContain('<script>alert("xss")</script>');
});

// Regression: ring geometry, placeholder re-expansion, invalid UTF-8, coverage

it('uses the circumference of the stub ring radius (r=80) for the score ring', function (): void {
    $report = new VulnerabilityReport([], 60, '', '');
    $report->setCoverage(ScanCoverage::complete(1));

    $html = (new HtmlReportGenerator)->generate($report);
    $circumference = number_format(2 * M_PI * 80, 3, '.', '');
    $expectedOffset = number_format(2 * M_PI * 80 * 0.4, 3, '.', '');

    expect($html)->toContain('r="80"')
        ->toContain("stroke-dasharray: {$circumference};")
        ->toContain("stroke-dashoffset: {$expectedOffset};")
        ->not->toContain('{{RING_CIRCUMFERENCE}}');
});

it('renders an empty ring when the score is withheld', function (): void {
    $report = new VulnerabilityReport([], 100, '', '');
    $report->setCoverage(ScanCoverage::none());

    $html = (new HtmlReportGenerator)->generate($report);
    $circumference = number_format(2 * M_PI * 80, 3, '.', '');

    preg_match_all('/stroke-dashoffset: ([0-9.]+);/', $html, $offsets);

    expect(array_unique($offsets[1]))->toBe([$circumference])
        ->and($html)->toContain('var scoreMeaningful = false;');
});

it('does not re-expand placeholders that appear inside finding text', function (): void {
    $report = new VulnerabilityReport([
        makeReportVulnerability(description: 'desc {{USAGE_SECTION}} {{FINDINGS}} {{SCORE}}'),
    ], 60, 'summary {{FINDINGS}}', '');

    $html = (new HtmlReportGenerator)->generate($report);

    expect(substr_count($html, 'Confirmed vulnerabilities (1)'))->toBe(1)
        ->and($html)->toContain('desc {{USAGE_SECTION}} {{FINDINGS}} {{SCORE}}')
        ->toContain('summary {{FINDINGS}}');
});

it('keeps finding text containing invalid UTF-8 instead of blanking it', function (): void {
    $report = new VulnerabilityReport([
        makeReportVulnerability(proof: "caf\xE9 unserialize(\$_GET['d'])"),
    ], 60, '', '');

    expect((new HtmlReportGenerator)->generate($report))->toContain('unserialize(');
});

it('shows Files Analyzed from coverage, not the number of files with findings', function (): void {
    $report = new VulnerabilityReport([], 100, '', '');
    $report->setCoverage(ScanCoverage::complete(40));

    $html = (new HtmlReportGenerator)->generate($report);

    expect($html)->toMatch('/Files Analyzed<\/div>\s*<div class="meta-value">40</');
});

it('shows confidence, CWE, references and the taint trace on confirmed cards', function (): void {
    $vulnerability = new Vulnerability(
        type: VulnerabilityType::SqlInjection,
        location: 'app/A.php',
        line: 3,
        severity: SeverityLevel::High,
        description: 'd',
        proof: 'p',
        fix: 'f',
        taintTrace: '$request->input("q") <script> -> DB::select',
        confidence: Confidence::Proven,
    );

    $html = (new HtmlReportGenerator)->generate(new VulnerabilityReport([$vulnerability], 80, '', ''));

    expect($html)->toContain('confidence: proven')
        ->toContain('>CWE-89<')
        ->toContain('Taint Trace')
        ->toContain('$request-&gt;input(&quot;q&quot;) &lt;script&gt;')
        ->toContain('href="https://cwe.mitre.org/data/definitions/89.html"');
});

it('copies only confirmed findings for AI and never prints n/a/100', function (): void {
    $html = (new HtmlReportGenerator)->generate(new VulnerabilityReport([], 100, '', ''));

    expect($html)->toContain("querySelectorAll('.finding-card:not(.review-card)')")
        ->not->toContain("'Score: ' + score + '/100 — ' + findings.length + ' issues found");
});
