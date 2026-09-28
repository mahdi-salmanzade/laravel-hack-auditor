<?php

declare(strict_types=1);

use Mahdi\HackAuditor\AI\ResponseParser;
use Mahdi\HackAuditor\Exceptions\InvalidAIResponseException;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

beforeEach(function (): void {
    $this->parser = new ResponseParser;
});

/**
 * One well-formed finding, with overrides applied on top.
 *
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function toleranceFinding(array $overrides = []): array
{
    return array_merge([
        'type' => 'sql_injection',
        'location' => 'app/Http/Controllers/A.php',
        'line' => 10,
        'severity' => 'high',
        'description' => 'User input reaches sink.',
        'proof' => 'x',
        'fix' => 'y',
    ], $overrides);
}

/**
 * @param  array<int, mixed>  $findings
 */
function toleranceReport(array $findings, mixed $score = 40): string
{
    return json_encode([
        'vulnerabilities' => $findings,
        'overall_score' => $score,
        'summary' => 's',
        'ctf_idea' => '',
    ], JSON_THROW_ON_ERROR);
}

/**
 * @param  array<int, Vulnerability>  $findings
 * @return array<int, string>
 */
function toleranceTypes(array $findings): array
{
    return array_map(static fn (Vulnerability $v): string => $v->type->value, $findings);
}

it('keeps the whole chunk when one entry uses a type the enum now knows', function (string $type, VulnerabilityType $expected): void {
    $report = $this->parser->parse(toleranceReport([
        toleranceFinding(),
        toleranceFinding(['type' => $type, 'line' => 20]),
    ]));

    expect($report->vulnerabilities)->toHaveCount(2)
        ->and($report->vulnerabilities[1]->type)->toBe($expected);
})->with([
    'path traversal' => ['path_traversal', VulnerabilityType::PathTraversal],
    'directory traversal' => ['Directory-Traversal', VulnerabilityType::PathTraversal],
    'unrestricted file upload' => ['unrestricted_file_upload', VulnerabilityType::UnrestrictedFileUpload],
    'hardcoded credentials' => ['hardcoded_credentials', VulnerabilityType::HardcodedSecret],
    'xxe' => ['XXE', VulnerabilityType::Xxe],
]);

it('skips only the entry with an unresolvable type and keeps the rest', function (): void {
    $report = $this->parser->parse(toleranceReport([
        toleranceFinding(),
        toleranceFinding(['type' => 'quantum_flux_injection']),
        toleranceFinding(['type' => 'xss', 'line' => 30]),
    ]));

    expect(toleranceTypes($report->vulnerabilities))->toBe(['sql_injection', 'xss'])
        ->and($this->parser->lastSkippedFindings())->toHaveCount(1)
        ->and($this->parser->lastSkippedFindings()[0])->toContain('quantum_flux_injection');
});

it('skips a non-object entry and keeps the rest', function (): void {
    $report = $this->parser->parse(toleranceReport([toleranceFinding(), 'oops']));

    expect($report->vulnerabilities)->toHaveCount(1);
});

it('coerces line numbers', function (mixed $line, int $expected): void {
    $report = $this->parser->parse(toleranceReport([toleranceFinding(['line' => $line])]));

    expect($report->vulnerabilities[0]->line)->toBe($expected);
})->with([
    'numeric string' => ['42', 42],
    'padded numeric string' => [' 42 ', 42],
    'range' => ['42-45', 42],
    'null' => [null, 1],
    'zero' => [0, 1],
    'negative' => [-7, 1],
    'negative string' => ['-7', 1],
    'prose' => ['unknown', 1],
]);

it('defaults a missing line to 1', function (): void {
    $finding = toleranceFinding();
    unset($finding['line']);

    expect($this->parser->parse(toleranceReport([$finding]))->vulnerabilities[0]->line)->toBe(1);
});

it('defaults null or missing proof and fix to empty strings', function (): void {
    $withoutProof = toleranceFinding(['fix' => null]);
    unset($withoutProof['proof']);

    $finding = $this->parser->parse(toleranceReport([$withoutProof]))->vulnerabilities[0];

    expect($finding->proof)->toBe('')
        ->and($finding->fix)->toBe('');
});

it('falls back to the type description when the description is missing', function (): void {
    $finding = toleranceFinding();
    unset($finding['description']);

    expect($this->parser->parse(toleranceReport([$finding]))->vulnerabilities[0]->description)
        ->toBe(VulnerabilityType::SqlInjection->description());
});

it('coerces a numeric-string overall_score', function (): void {
    expect($this->parser->parse(toleranceReport([toleranceFinding()], '40'))->overallScore)->toBe(40);
});

it('derives the score from the findings when overall_score is unusable', function (): void {
    $report = $this->parser->parse(toleranceReport([
        toleranceFinding(['severity' => 'critical']),
        toleranceFinding(['severity' => 'high', 'line' => 20]),
    ], null));

    expect($report->overallScore)->toBe(100 - 40 - 20);
});

it('maps severity aliases instead of silently demoting them to low', function (): void {
    $report = $this->parser->parse(toleranceReport([
        toleranceFinding(['severity' => 'Severe']),
        toleranceFinding(['severity' => 'moderate', 'line' => 2]),
        toleranceFinding(['severity' => 'Critical ', 'line' => 3]),
    ]));

    expect(array_map(static fn (Vulnerability $v): SeverityLevel => $v->severity, $report->vulnerabilities))
        ->toBe([SeverityLevel::Critical, SeverityLevel::Medium, SeverityLevel::Critical]);
});

it('finds the report after an unbalanced brace in leading prose', function (): void {
    $response = "I looked at the { handler first.\n".toleranceReport([
        toleranceFinding(),
        toleranceFinding(['type' => 'xss', 'line' => 9]),
    ]);

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(2)
        ->and($this->parser->lastParseWasTruncated())->toBeFalse();
});

it('salvages every complete finding from a response truncated at max_tokens', function (): void {
    $full = toleranceReport([
        toleranceFinding(['line' => 5, 'fix' => 'if ($x) { return "}"; }']),
        toleranceFinding(['type' => 'xss', 'line' => 9]),
        toleranceFinding(['type' => 'idor', 'line' => 20]),
    ]);
    $truncated = substr($full, 0, strrpos($full, '{"type":"idor"') + 40);

    $report = $this->parser->parse($truncated);

    expect(toleranceTypes($report->vulnerabilities))->toBe(['sql_injection', 'xss'])
        ->and($report->vulnerabilities[0]->fix)->toBe('if ($x) { return "}"; }')
        ->and($this->parser->lastParseWasTruncated())->toBeTrue()
        ->and($report->overallScore)->toBe(60)
        ->and($report->summary)->toContain('truncated');
});

it('resets the truncated flag on the next parse', function (): void {
    $full = toleranceReport([toleranceFinding(), toleranceFinding(['line' => 20])]);
    $this->parser->parse(substr($full, 0, strlen($full) - 60));

    expect($this->parser->lastParseWasTruncated())->toBeTrue();

    $this->parser->parse($full);

    expect($this->parser->lastParseWasTruncated())->toBeFalse();
});

it('still throws when truncation cut off before any finding completed', function (): void {
    $this->parser->parse('{"vulnerabilities": [{"type": "sql_injection", "location": "app/A.ph');
})->throws(InvalidAIResponseException::class);

it('still throws when there is no JSON object at all', function (): void {
    $this->parser->parse('I could not analyse this file, sorry.');
})->throws(InvalidAIResponseException::class);

it('salvages findings from a closed but malformed report without marking it truncated', function (): void {
    $response = '{"vulnerabilities": ['.json_encode(toleranceFinding()).',], "overall_score": 60, "summary": "s",}';

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(1)
        ->and($this->parser->lastParseWasTruncated())->toBeFalse();
});

it('accepts a bare JSON list of findings', function (): void {
    $report = $this->parser->parse(json_encode([toleranceFinding()], JSON_THROW_ON_ERROR));

    expect($report->vulnerabilities)->toHaveCount(1);
});

it('rewrites a location to the canonical chunk path and clamps the line to the file length', function (): void {
    $files = [
        ['path' => 'app/Http/Controllers/Api/UserController.php', 'content' => "<?php\n\nclass UserController {}\n", 'type' => 'controller'],
        ['path' => 'app/Http/Controllers/ReportController.php', 'content' => "<?php\n", 'type' => 'controller'],
    ];

    $report = $this->parser->parse(toleranceReport([
        toleranceFinding(['location' => './app\\Http\\Controllers\\Api\\UserController.php', 'line' => 999]),
        toleranceFinding(['location' => 'ReportController.php', 'line' => 3]),
        toleranceFinding(['location' => base_path('app/Http/Controllers/ReportController.php'), 'line' => 1]),
    ]), $files);

    expect(array_map(static fn (Vulnerability $v): string => $v->location, $report->vulnerabilities))
        ->toBe([
            'app/Http/Controllers/Api/UserController.php',
            'app/Http/Controllers/ReportController.php',
            'app/Http/Controllers/ReportController.php',
        ])
        ->and($report->vulnerabilities[0]->line)->toBe(4)
        ->and($report->vulnerabilities[1]->line)->toBe(2);
});

it('drops a finding whose location is not one of the chunk files', function (): void {
    $files = [['path' => 'app/Http/Controllers/A.php', 'content' => "<?php\n", 'type' => 'controller']];

    $report = $this->parser->parse(toleranceReport([
        toleranceFinding(),
        toleranceFinding(['location' => 'app/Http/Controllers/Elsewhere.php']),
    ]), $files);

    expect($report->vulnerabilities)->toHaveCount(1)
        ->and($this->parser->lastSkippedFindings()[0])->toContain('Elsewhere.php');
});

it('refuses to guess between two chunk files that share a basename', function (): void {
    $files = [
        ['path' => 'app/Http/Controllers/Api/UserController.php', 'content' => "<?php\n", 'type' => 'controller'],
        ['path' => 'app/Http/Controllers/Admin/UserController.php', 'content' => "<?php\n", 'type' => 'controller'],
    ];

    $report = $this->parser->parse(toleranceReport([toleranceFinding(['location' => 'UserController.php'])]), $files);

    expect($report->vulnerabilities)->toBe([]);
});

it('does not validate locations when no chunk files are given', function (): void {
    $report = $this->parser->parse(toleranceReport([toleranceFinding(['location' => 'anything.php', 'line' => 5000])]));

    expect($report->vulnerabilities[0]->location)->toBe('anything.php')
        ->and($report->vulnerabilities[0]->line)->toBe(5000);
});
