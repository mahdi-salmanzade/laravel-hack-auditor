<?php

declare(strict_types=1);

use Mahdi\HackAuditor\AI\ResponseParser;
use Mahdi\HackAuditor\Exceptions\InvalidAIResponseException;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

beforeEach(function (): void {
    $this->parser = new ResponseParser;
});

function validJsonResponse(array $overrides = []): string
{
    $default = [
        'vulnerabilities' => [
            [
                'type' => 'sql_injection',
                'location' => 'app/Http/Controllers/UserController.php',
                'line' => 42,
                'severity' => 'critical',
                'description' => 'Raw SQL injection.',
                'proof' => 'DB::select("SELECT * FROM users WHERE id = $id")',
                'fix' => 'DB::select("SELECT * FROM users WHERE id = ?", [$id])',
            ],
        ],
        'overall_score' => 25,
        'summary' => 'Critical vulnerability found.',
        'ctf_idea' => 'SQL Injection challenge',
    ];

    return json_encode(array_merge($default, $overrides), JSON_THROW_ON_ERROR);
}

it('parses valid JSON and returns a VulnerabilityReport', function (): void {
    $response = validJsonResponse();
    $report = $this->parser->parse($response);

    expect($report)->toBeInstanceOf(VulnerabilityReport::class)
        ->and($report->overallScore)->toBe(25)
        ->and($report->summary)->toBe('Critical vulnerability found.')
        ->and($report->ctfIdea)->toBe('SQL Injection challenge')
        ->and($report->vulnerabilities)->toHaveCount(1);
});

it('parses vulnerability fields correctly', function (): void {
    $response = validJsonResponse();
    $report = $this->parser->parse($response);

    $vuln = $report->vulnerabilities[0];

    expect($vuln)->toBeInstanceOf(Vulnerability::class)
        ->and($vuln->type)->toBe(VulnerabilityType::SqlInjection)
        ->and($vuln->location)->toBe('app/Http/Controllers/UserController.php')
        ->and($vuln->line)->toBe(42)
        ->and($vuln->severity)->toBe(SeverityLevel::Critical)
        ->and($vuln->description)->toBe('Raw SQL injection.')
        ->and($vuln->proof)->toBe('DB::select("SELECT * FROM users WHERE id = $id")')
        ->and($vuln->fix)->toBe('DB::select("SELECT * FROM users WHERE id = ?", [$id])');
});

it('handles markdown-fenced JSON responses', function (): void {
    $json = validJsonResponse();
    $wrapped = "```json\n{$json}\n```";

    $report = $this->parser->parse($wrapped);

    expect($report)->toBeInstanceOf(VulnerabilityReport::class)
        ->and($report->overallScore)->toBe(25)
        ->and($report->vulnerabilities)->toHaveCount(1);
});

it('handles markdown-fenced JSON without language tag', function (): void {
    $json = validJsonResponse();
    $wrapped = "```\n{$json}\n```";

    $report = $this->parser->parse($wrapped);

    expect($report)->toBeInstanceOf(VulnerabilityReport::class)
        ->and($report->overallScore)->toBe(25);
});

it('throws InvalidAIResponseException for malformed JSON', function (): void {
    $this->parser->parse('this is not valid json at all');
})->throws(InvalidAIResponseException::class);

it('throws InvalidAIResponseException for empty string', function (): void {
    $this->parser->parse('');
})->throws(InvalidAIResponseException::class);

it('throws InvalidAIResponseException when vulnerabilities field is missing', function (): void {
    $response = json_encode([
        'overall_score' => 100,
        'summary' => 'Clean.',
    ], JSON_THROW_ON_ERROR);

    $this->parser->parse($response);
})->throws(InvalidAIResponseException::class, 'vulnerabilities');

it('throws InvalidAIResponseException when overall_score field is missing', function (): void {
    $response = json_encode([
        'vulnerabilities' => [],
        'summary' => 'Clean.',
    ], JSON_THROW_ON_ERROR);

    $this->parser->parse($response);
})->throws(InvalidAIResponseException::class, 'overall_score');

it('throws InvalidAIResponseException when summary field is missing', function (): void {
    $response = json_encode([
        'vulnerabilities' => [],
        'overall_score' => 100,
    ], JSON_THROW_ON_ERROR);

    $this->parser->parse($response);
})->throws(InvalidAIResponseException::class, 'summary');

it('throws InvalidAIResponseException when vulnerabilities is not an array', function (): void {
    $response = json_encode([
        'vulnerabilities' => 'not an array',
        'overall_score' => 100,
        'summary' => 'Clean.',
    ], JSON_THROW_ON_ERROR);

    $this->parser->parse($response);
})->throws(InvalidAIResponseException::class, 'vulnerabilities');

it('throws InvalidAIResponseException when vulnerability type field is missing', function (): void {
    $response = json_encode([
        'vulnerabilities' => [
            [
                'location' => 'test.php',
                'line' => 1,
                'severity' => 'low',
                'description' => 'desc',
                'proof' => 'code',
                'fix' => 'fix',
            ],
        ],
        'overall_score' => 50,
        'summary' => 'Issues found.',
    ], JSON_THROW_ON_ERROR);

    $this->parser->parse($response);
})->throws(InvalidAIResponseException::class, 'type');

it('throws InvalidAIResponseException for invalid vulnerability type string', function (): void {
    $response = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'totally_fake_vulnerability',
                'location' => 'test.php',
                'line' => 1,
                'severity' => 'low',
                'description' => 'desc',
                'proof' => 'code',
                'fix' => 'fix',
            ],
        ],
        'overall_score' => 50,
        'summary' => 'Issues found.',
    ], JSON_THROW_ON_ERROR);

    $this->parser->parse($response);
})->throws(InvalidAIResponseException::class, 'totally_fake_vulnerability');

it('handles case-insensitive vulnerability type via enum name', function (): void {
    $response = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'SqlInjection',
                'location' => 'test.php',
                'line' => 1,
                'severity' => 'High',
                'description' => 'desc',
                'proof' => 'code',
                'fix' => 'fix',
            ],
        ],
        'overall_score' => 50,
        'summary' => 'Issues found.',
    ], JSON_THROW_ON_ERROR);

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities[0]->type)->toBe(VulnerabilityType::SqlInjection);
});

it('handles unknown severity gracefully by falling back to Low', function (): void {
    $response = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'xss',
                'location' => 'test.php',
                'line' => 1,
                'severity' => 'unknown_severity',
                'description' => 'desc',
                'proof' => 'code',
                'fix' => 'fix',
            ],
        ],
        'overall_score' => 50,
        'summary' => 'Issues found.',
    ], JSON_THROW_ON_ERROR);

    $report = $this->parser->parse($response);

    // SeverityLevel::fromString falls back to Low for unknown values
    expect($report->vulnerabilities[0]->severity)->toBe(SeverityLevel::Low);
});

it('returns score 100 with empty vulnerabilities array', function (): void {
    $response = json_encode([
        'vulnerabilities' => [],
        'overall_score' => 100,
        'summary' => 'No vulnerabilities found.',
        'ctf_idea' => '',
    ], JSON_THROW_ON_ERROR);

    $report = $this->parser->parse($response);

    expect($report->overallScore)->toBe(100)
        ->and($report->vulnerabilities)->toBeEmpty()
        ->and($report->totalCount())->toBe(0);
});

it('clamps overall_score to 0-100 range', function (): void {
    $responseHigh = json_encode([
        'vulnerabilities' => [],
        'overall_score' => 150,
        'summary' => 'Over 100.',
    ], JSON_THROW_ON_ERROR);

    $responseLow = json_encode([
        'vulnerabilities' => [],
        'overall_score' => -50,
        'summary' => 'Below 0.',
    ], JSON_THROW_ON_ERROR);

    $reportHigh = $this->parser->parse($responseHigh);
    $reportLow = $this->parser->parse($responseLow);

    expect($reportHigh->overallScore)->toBe(100)
        ->and($reportLow->overallScore)->toBe(0);
});

it('throws InvalidAIResponseException when overall_score is not numeric', function (): void {
    $response = json_encode([
        'vulnerabilities' => [],
        'overall_score' => 'not a number',
        'summary' => 'Score is invalid.',
    ], JSON_THROW_ON_ERROR);

    $this->parser->parse($response);
})->throws(InvalidAIResponseException::class, 'overall_score');

it('throws InvalidAIResponseException when summary is not a string', function (): void {
    $response = json_encode([
        'vulnerabilities' => [],
        'overall_score' => 100,
        'summary' => 12345,
    ], JSON_THROW_ON_ERROR);

    $this->parser->parse($response);
})->throws(InvalidAIResponseException::class, 'summary');

it('handles missing ctf_idea field gracefully as empty string', function (): void {
    $response = json_encode([
        'vulnerabilities' => [],
        'overall_score' => 100,
        'summary' => 'No issues.',
    ], JSON_THROW_ON_ERROR);

    $report = $this->parser->parse($response);

    expect($report->ctfIdea)->toBe('');
});

it('parses multiple vulnerabilities correctly', function (): void {
    $response = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'sql_injection',
                'location' => 'file1.php',
                'line' => 10,
                'severity' => 'critical',
                'description' => 'SQL injection.',
                'proof' => 'proof1',
                'fix' => 'fix1',
            ],
            [
                'type' => 'xss',
                'location' => 'file2.php',
                'line' => 20,
                'severity' => 'high',
                'description' => 'XSS.',
                'proof' => 'proof2',
                'fix' => 'fix2',
            ],
            [
                'type' => 'csrf',
                'location' => 'file3.php',
                'line' => 30,
                'severity' => 'medium',
                'description' => 'CSRF.',
                'proof' => 'proof3',
                'fix' => 'fix3',
            ],
        ],
        'overall_score' => 35,
        'summary' => 'Multiple vulnerabilities.',
    ], JSON_THROW_ON_ERROR);

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(3)
        ->and($report->vulnerabilities[0]->type)->toBe(VulnerabilityType::SqlInjection)
        ->and($report->vulnerabilities[1]->type)->toBe(VulnerabilityType::Xss)
        ->and($report->vulnerabilities[2]->type)->toBe(VulnerabilityType::Csrf);
});

it('throws InvalidAIResponseException when vulnerability location is not a string', function (): void {
    $response = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'xss',
                'location' => 12345,
                'line' => 1,
                'severity' => 'high',
                'description' => 'desc',
                'proof' => 'code',
                'fix' => 'fix',
            ],
        ],
        'overall_score' => 50,
        'summary' => 'Issues found.',
    ], JSON_THROW_ON_ERROR);

    $this->parser->parse($response);
})->throws(InvalidAIResponseException::class, 'location');

it('accepts float line numbers and casts to int', function (): void {
    $response = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'xss',
                'location' => 'test.php',
                'line' => 42.5,
                'severity' => 'high',
                'description' => 'desc',
                'proof' => 'code',
                'fix' => 'fix',
            ],
        ],
        'overall_score' => 50,
        'summary' => 'Issues found.',
    ], JSON_THROW_ON_ERROR);

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities[0]->line)->toBe(42);
});

it('handles whitespace around JSON response', function (): void {
    $json = validJsonResponse();
    $padded = "  \n  {$json}  \n  ";

    $report = $this->parser->parse($padded);

    expect($report)->toBeInstanceOf(VulnerabilityReport::class)
        ->and($report->overallScore)->toBe(25);
});
