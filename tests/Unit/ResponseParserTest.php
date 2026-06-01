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

it('extracts JSON when prose appears before the JSON block', function (): void {
    $json = validJsonResponse();
    $response = "Looking at this controller, I found the following issues:\n\n{$json}";

    $report = $this->parser->parse($response);

    expect($report)->toBeInstanceOf(VulnerabilityReport::class)
        ->and($report->overallScore)->toBe(25)
        ->and($report->vulnerabilities)->toHaveCount(1);
});

it('extracts JSON when prose appears before and after the JSON block', function (): void {
    $json = validJsonResponse();
    $response = "Here's my analysis of the code:\n\n{$json}\n\nLet me know if you need more details about any of these findings.";

    $report = $this->parser->parse($response);

    expect($report)->toBeInstanceOf(VulnerabilityReport::class)
        ->and($report->overallScore)->toBe(25)
        ->and($report->vulnerabilities)->toHaveCount(1)
        ->and($report->summary)->toBe('Critical vulnerability found.');
});

it('handles JSON with unbalanced braces inside string values', function (): void {
    $json = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'sql_injection',
                'location' => 'app/Http/Controllers/UserController.php',
                'line' => 42,
                'severity' => 'critical',
                'description' => 'Raw SQL injection via user input.',
                'proof' => 'if ($x) {',
                'fix' => 'Use parameterized queries: DB::select("SELECT * FROM users WHERE id = ?", [$id])',
            ],
        ],
        'overall_score' => 25,
        'summary' => 'Critical vulnerability found.',
        'ctf_idea' => 'SQL Injection challenge',
    ], JSON_THROW_ON_ERROR);

    $response = "Analysis results:\n\n{$json}";

    $report = $this->parser->parse($response);

    expect($report)->toBeInstanceOf(VulnerabilityReport::class)
        ->and($report->overallScore)->toBe(25)
        ->and($report->vulnerabilities)->toHaveCount(1)
        ->and($report->vulnerabilities[0]->proof)->toBe('if ($x) {');
});

it('handles JSON with balanced braces inside string values like PHP code', function (): void {
    $json = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'sql_injection',
                'location' => 'app/Http/Controllers/UserController.php',
                'line' => 42,
                'severity' => 'critical',
                'description' => 'Concatenated input in query.',
                'proof' => 'if ($x) { return DB::select("SELECT * FROM users WHERE id = " . $id); }',
                'fix' => 'if ($x) { return DB::select("SELECT * FROM users WHERE id = ?", [$id]); }',
            ],
        ],
        'overall_score' => 25,
        'summary' => 'Critical vulnerability found.',
    ], JSON_THROW_ON_ERROR);

    $response = "Here is the security report:\n\n{$json}\n\nEnd of report.";

    $report = $this->parser->parse($response);

    expect($report)->toBeInstanceOf(VulnerabilityReport::class)
        ->and($report->overallScore)->toBe(25)
        ->and($report->vulnerabilities)->toHaveCount(1);
});

it('skips non-target JSON objects and finds the one with vulnerabilities key', function (): void {
    $smallJson = json_encode(['note' => 'preliminary analysis']);
    $realJson = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'xss',
                'location' => 'resources/views/profile.blade.php',
                'line' => 15,
                'severity' => 'high',
                'description' => 'Unescaped output.',
                'proof' => '{!! $user->bio !!}',
                'fix' => '{{ $user->bio }}',
            ],
        ],
        'overall_score' => 60,
        'summary' => 'XSS found.',
    ], JSON_THROW_ON_ERROR);

    $response = "Let me first note: {$smallJson}\n\nNow for the full analysis:\n\n{$realJson}";

    $report = $this->parser->parse($response);

    expect($report)->toBeInstanceOf(VulnerabilityReport::class)
        ->and($report->overallScore)->toBe(60)
        ->and($report->vulnerabilities)->toHaveCount(1)
        ->and($report->vulnerabilities[0]->type)->toBe(VulnerabilityType::Xss);
});

it('handles JSON with newlines in string values', function (): void {
    $json = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'sql_injection',
                'location' => 'app/Http/Controllers/UserController.php',
                'line' => 42,
                'severity' => 'critical',
                'description' => "Raw SQL injection.\nUser input is concatenated directly.\nThis allows arbitrary queries.",
                'proof' => "Line 42: \$query = \"SELECT * FROM users WHERE id = \" . \$id;\nLine 43: DB::select(\$query);",
                'fix' => "Use parameterized queries:\nDB::select(\"SELECT * FROM users WHERE id = ?\", [\$id]);",
            ],
        ],
        'overall_score' => 25,
        'summary' => "Multiple issues detected.\nSee details above.",
    ], JSON_THROW_ON_ERROR);

    $response = "Security analysis complete:\n\n{$json}";

    $report = $this->parser->parse($response);

    expect($report)->toBeInstanceOf(VulnerabilityReport::class)
        ->and($report->overallScore)->toBe(25)
        ->and($report->vulnerabilities)->toHaveCount(1)
        ->and($report->vulnerabilities[0]->description)->toContain("\n");
});

describe('parseVerification substantive-exploit guard', function (): void {
    it('rejects a bare URL as a non-substantive exploit', function (): void {
        $json = json_encode([
            'verified' => true,
            'exploit' => 'https://example.com/admin?id=1',
            'reasoning' => 'A link was provided.',
        ], JSON_THROW_ON_ERROR);

        $result = $this->parser->parseVerification($json);

        expect($result['verified'])->toBeFalse()
            ->and($result['exploit'])->toBeNull();
    });

    it('rejects a lone HTML tag placeholder', function (): void {
        $json = json_encode([
            'verified' => true,
            'exploit' => '<payload>',
            'reasoning' => '',
        ], JSON_THROW_ON_ERROR);

        $result = $this->parser->parseVerification($json);

        expect($result['verified'])->toBeFalse()
            ->and($result['exploit'])->toBeNull();
    });

    it('rejects a refusal token such as "not vulnerable"', function (): void {
        $json = json_encode([
            'verified' => true,
            'exploit' => 'Not Vulnerable',
            'reasoning' => '',
        ], JSON_THROW_ON_ERROR);

        $result = $this->parser->parseVerification($json);

        expect($result['verified'])->toBeFalse()
            ->and($result['exploit'])->toBeNull();
    });

    it('rejects an exploit shorter than the minimum substantive length', function (): void {
        $json = json_encode([
            'verified' => true,
            'exploit' => 'a=1',
            'reasoning' => '',
        ], JSON_THROW_ON_ERROR);

        $result = $this->parser->parseVerification($json);

        expect($result['verified'])->toBeFalse()
            ->and($result['exploit'])->toBeNull();
    });

    it('accepts a real SQL injection payload', function (): void {
        $json = json_encode([
            'verified' => true,
            'exploit' => "' OR 1=1--",
            'reasoning' => 'Auth bypass via tautology.',
        ], JSON_THROW_ON_ERROR);

        $result = $this->parser->parseVerification($json);

        expect($result['verified'])->toBeTrue()
            ->and($result['exploit'])->toBe("' OR 1=1--");
    });

    it('accepts a real XSS script payload that contains more than a bare tag', function (): void {
        $json = json_encode([
            'verified' => true,
            'exploit' => '<script>alert(1)</script>',
            'reasoning' => 'Reflected XSS.',
        ], JSON_THROW_ON_ERROR);

        $result = $this->parser->parseVerification($json);

        expect($result['verified'])->toBeTrue()
            ->and($result['exploit'])->toBe('<script>alert(1)</script>');
    });
});
