<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Benchmark\GroundTruth;

it('loads the packaged ground-truth fixture', function (): void {
    $groundTruth = GroundTruth::default();

    expect($groundTruth->samples)->not->toBeEmpty()
        ->and($groundTruth->lineTolerance)->toBeGreaterThan(0);
});

it('every packaged sample file exists on disk', function (): void {
    $groundTruth = GroundTruth::default();
    $samplesDir = GroundTruth::defaultSamplesPath();

    foreach ($groundTruth->files() as $file) {
        expect(is_file($samplesDir.DIRECTORY_SEPARATOR.$file))->toBeTrue("Missing sample: {$file}");
    }
});

it('labels the command-injection sample as command_injection without lenient stand-ins', function (): void {
    $groundTruth = GroundTruth::default();

    $sample = collect($groundTruth->samples)
        ->firstWhere('file', 'CommandInjectionController.php');

    expect($sample)->not->toBeNull();

    $expected = $sample['expected'][0];

    expect($expected['type'])->toBe('command_injection')
        ->and($expected['accepted_types'])->toBe(['command_injection'])
        ->and($expected['accepted_types'])->not->toContain('missing_validation')
        ->and($expected['accepted_types'])->not->toContain('insecure_deserialization');
});

it('counts labeled vulnerabilities and clean samples', function (): void {
    $groundTruth = GroundTruth::fromArray([
        'line_tolerance' => 2,
        'samples' => [
            ['file' => 'A.php', 'expected' => [['type' => 'xss', 'line' => 5, 'accepted_types' => ['xss']]]],
            ['file' => 'B.php', 'expected' => [['type' => 'idor', 'line' => 9, 'accepted_types' => ['idor']]]],
            ['file' => 'Clean.php', 'expected' => []],
        ],
    ]);

    expect($groundTruth->expectedVulnerabilityCount())->toBe(2)
        ->and($groundTruth->cleanSampleCount())->toBe(1)
        ->and($groundTruth->lineTolerance)->toBe(2)
        ->and($groundTruth->files())->toBe(['A.php', 'B.php', 'Clean.php']);
});

it('always includes the canonical type within accepted_types', function (): void {
    $groundTruth = GroundTruth::fromArray([
        'samples' => [
            ['file' => 'A.php', 'expected' => [['type' => 'sql_injection', 'line' => 1, 'accepted_types' => ['dynamic_column_injection']]]],
        ],
    ]);

    $accepted = $groundTruth->samples[0]['expected'][0]['accepted_types'];

    expect($accepted)->toContain('sql_injection')
        ->and($accepted)->toContain('dynamic_column_injection');
});

it('normalizes type and accepted_types to lowercase', function (): void {
    $groundTruth = GroundTruth::fromArray([
        'samples' => [
            ['file' => 'A.php', 'expected' => [['type' => 'SQL_Injection', 'line' => 1, 'accepted_types' => ['XSS']]]],
        ],
    ]);

    $entry = $groundTruth->samples[0]['expected'][0];

    expect($entry['type'])->toBe('sql_injection')
        ->and($entry['accepted_types'])->toContain('xss');
});

it('defaults line tolerance to 3 when omitted', function (): void {
    $groundTruth = GroundTruth::fromArray(['samples' => []]);

    expect($groundTruth->lineTolerance)->toBe(3);
});

it('throws when the ground-truth file is missing', function (): void {
    GroundTruth::fromFile('/nonexistent/ground-truth.json');
})->throws(RuntimeException::class);

it('skips entries with empty file or type', function (): void {
    $groundTruth = GroundTruth::fromArray([
        'samples' => [
            ['file' => '', 'expected' => []],
            ['file' => 'A.php', 'expected' => [['type' => '', 'line' => 1, 'accepted_types' => []]]],
        ],
    ]);

    expect($groundTruth->files())->toBe(['A.php'])
        ->and($groundTruth->expectedVulnerabilityCount())->toBe(0);
});
