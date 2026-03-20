<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\ShareHelper;
use Mahdi\HackAuditor\Support\VulnerabilityType;

function buildTestReport(int $score = 45, array $severities = []): VulnerabilityReport
{
    if (empty($severities)) {
        $severities = [
            SeverityLevel::Critical,
            SeverityLevel::Critical,
            SeverityLevel::High,
            SeverityLevel::Medium,
            SeverityLevel::Low,
        ];
    }

    $vulnerabilities = [];
    foreach ($severities as $index => $severity) {
        $vulnerabilities[] = new Vulnerability(
            type: VulnerabilityType::SqlInjection,
            location: "file{$index}.php",
            line: ($index + 1) * 10,
            severity: $severity,
            description: "Vulnerability {$index}",
            proof: "proof {$index}",
            fix: "fix {$index}",
        );
    }

    return new VulnerabilityReport(
        vulnerabilities: $vulnerabilities,
        overallScore: $score,
        summary: 'Test summary of security posture.',
        ctfIdea: 'Test CTF idea',
    );
}

beforeEach(function (): void {
    $this->helper = new ShareHelper();
});

// Twitter URL tests

it('generates a properly encoded Twitter URL', function (): void {
    $report = buildTestReport();
    $url = $this->helper->twitterUrl($report);

    expect($url)->toStartWith('https://twitter.com/intent/tweet?text=')
        ->and($url)->toContain(rawurlencode('45/100'));
});

it('twitter URL contains the score', function (): void {
    $report = buildTestReport(72);
    $url = $this->helper->twitterUrl($report);
    $decodedText = rawurldecode(str_replace('https://twitter.com/intent/tweet?text=', '', $url));

    expect($decodedText)->toContain('72/100');
});

it('twitter URL contains vulnerability count', function (): void {
    $report = buildTestReport();
    $url = $this->helper->twitterUrl($report);
    $decodedText = rawurldecode(str_replace('https://twitter.com/intent/tweet?text=', '', $url));

    expect($decodedText)->toContain('5 vulnerabilities');
});

it('twitter URL contains critical count when there are critical vulnerabilities', function (): void {
    $report = buildTestReport(20, [SeverityLevel::Critical, SeverityLevel::Critical, SeverityLevel::High]);
    $url = $this->helper->twitterUrl($report);
    $decodedText = rawurldecode(str_replace('https://twitter.com/intent/tweet?text=', '', $url));

    expect($decodedText)->toContain('2 Critical');
});

it('twitter URL omits critical label when no critical vulnerabilities exist', function (): void {
    $report = buildTestReport(80, [SeverityLevel::Medium, SeverityLevel::Low]);
    $url = $this->helper->twitterUrl($report);
    $decodedText = rawurldecode(str_replace('https://twitter.com/intent/tweet?text=', '', $url));

    expect($decodedText)->not->toContain('Critical');
});

it('twitter URL contains default hashtags', function (): void {
    $report = buildTestReport();
    $url = $this->helper->twitterUrl($report);
    $decodedText = rawurldecode(str_replace('https://twitter.com/intent/tweet?text=', '', $url));

    expect($decodedText)->toContain('#LaravelSecurity')
        ->and($decodedText)->toContain('#HackAuditor')
        ->and($decodedText)->toContain('#CTF');
});

it('twitter URL contains the package name', function (): void {
    $report = buildTestReport();
    $url = $this->helper->twitterUrl($report);
    $decodedText = rawurldecode(str_replace('https://twitter.com/intent/tweet?text=', '', $url));

    expect($decodedText)->toContain('mahdisphp/laravel-hack-auditor');
});

it('twitter URL contains the artisan command', function (): void {
    $report = buildTestReport();
    $url = $this->helper->twitterUrl($report);
    $decodedText = rawurldecode(str_replace('https://twitter.com/intent/tweet?text=', '', $url));

    expect($decodedText)->toContain('php artisan hack:scan');
});

// Markdown summary tests

it('markdown summary includes score', function (): void {
    $report = buildTestReport(67);
    $markdown = $this->helper->markdownSummary($report);

    expect($markdown)->toContain('67');
});

it('markdown summary includes vulnerability counts', function (): void {
    $report = buildTestReport();
    $markdown = $this->helper->markdownSummary($report);

    expect($markdown)->toContain('Critical')
        ->and($markdown)->toContain('High')
        ->and($markdown)->toContain('Medium')
        ->and($markdown)->toContain('Low')
        ->and($markdown)->toContain('Total');
});

it('markdown summary includes a shields.io badge', function (): void {
    $report = buildTestReport(85);
    $markdown = $this->helper->markdownSummary($report);

    expect($markdown)->toContain('img.shields.io/badge/security%20score')
        ->and($markdown)->toContain('85');
});

it('markdown summary badge color is brightgreen for score >= 80', function (): void {
    $report = buildTestReport(80);
    $markdown = $this->helper->markdownSummary($report);

    expect($markdown)->toContain('brightgreen');
});

it('markdown summary badge color is yellow for score >= 60', function (): void {
    $report = buildTestReport(65);
    $markdown = $this->helper->markdownSummary($report);

    expect($markdown)->toContain('yellow');
});

it('markdown summary badge color is orange for score >= 40', function (): void {
    $report = buildTestReport(45);
    $markdown = $this->helper->markdownSummary($report);

    expect($markdown)->toContain('orange');
});

it('markdown summary badge color is red for score < 40', function (): void {
    $report = buildTestReport(20);
    $markdown = $this->helper->markdownSummary($report);

    expect($markdown)->toContain('red');
});

it('markdown summary includes the report summary text', function (): void {
    $report = buildTestReport();
    $markdown = $this->helper->markdownSummary($report);

    expect($markdown)->toContain('Test summary of security posture.');
});

it('markdown summary includes correct count values', function (): void {
    $report = buildTestReport(45, [
        SeverityLevel::Critical,
        SeverityLevel::High,
        SeverityLevel::High,
        SeverityLevel::Medium,
    ]);
    $markdown = $this->helper->markdownSummary($report);

    // 1 critical, 2 high, 1 medium, 0 low, 4 total
    expect($markdown)->toContain('| 1 |')  // critical
        ->and($markdown)->toContain('| 2 |')  // high
        ->and($markdown)->toContain('| **4** |');  // total
});

// Console share block tests

it('console share block contains box-drawing characters', function (): void {
    $report = buildTestReport();
    $block = $this->helper->consoleShareBlock($report);

    // UTF-8 box drawing: top-left corner, horizontal line, vertical line
    expect($block)->toContain("\xE2\x94\x8C")  // top-left corner
        ->and($block)->toContain("\xE2\x94\x90")  // top-right corner
        ->and($block)->toContain("\xE2\x94\x94")  // bottom-left corner
        ->and($block)->toContain("\xE2\x94\x98")  // bottom-right corner
        ->and($block)->toContain("\xE2\x94\x82")  // vertical line
        ->and($block)->toContain("\xE2\x94\x80");  // horizontal line
});

it('console share block contains score', function (): void {
    $report = buildTestReport(73);
    $block = $this->helper->consoleShareBlock($report);

    expect($block)->toContain('73/100');
});

it('console share block contains vulnerability counts', function (): void {
    $report = buildTestReport(45, [
        SeverityLevel::Critical,
        SeverityLevel::Critical,
        SeverityLevel::High,
        SeverityLevel::Medium,
        SeverityLevel::Low,
    ]);
    $block = $this->helper->consoleShareBlock($report);

    expect($block)->toContain('Critical: 2')
        ->and($block)->toContain('High:     1')
        ->and($block)->toContain('Medium:   1')
        ->and($block)->toContain('Low:      1');
});

it('console share block contains Hack Auditor title', function (): void {
    $report = buildTestReport();
    $block = $this->helper->consoleShareBlock($report);

    expect($block)->toContain('Hack Auditor Scan Results');
});

it('console share block contains share prompt', function (): void {
    $report = buildTestReport();
    $block = $this->helper->consoleShareBlock($report);

    expect($block)->toContain('Share your results!')
        ->and($block)->toContain('php artisan hack:share');
});

it('console share block contains total vulnerability count', function (): void {
    $report = buildTestReport(50, [SeverityLevel::High, SeverityLevel::Medium]);
    $block = $this->helper->consoleShareBlock($report);

    expect($block)->toContain('Vulnerabilities Found: 2');
});
