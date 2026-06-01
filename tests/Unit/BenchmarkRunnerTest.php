<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Benchmark\BenchmarkRunner;
use Mahdi\HackAuditor\Benchmark\GroundTruth;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * Build a Vulnerability finding with only the fields the matcher cares about.
 */
function benchFinding(string $location, VulnerabilityType $type, int $line): Vulnerability
{
    return new Vulnerability(
        type: $type,
        location: $location,
        line: $line,
        severity: SeverityLevel::High,
        description: 'test finding',
        proof: 'proof',
        fix: 'fix',
    );
}

/**
 * A small two-sample ground truth: one SQLi label, one clean file.
 */
function benchGroundTruth(): GroundTruth
{
    return GroundTruth::fromArray([
        'line_tolerance' => 3,
        'samples' => [
            [
                'file' => 'SqlInjectionController.php',
                'expected' => [
                    ['type' => 'sql_injection', 'line' => 16, 'accepted_types' => ['sql_injection', 'dynamic_column_injection']],
                ],
            ],
            [
                'file' => 'XssController.php',
                'expected' => [
                    ['type' => 'xss', 'line' => 15, 'accepted_types' => ['xss']],
                ],
            ],
            [
                'file' => 'CleanController.php',
                'expected' => [],
            ],
        ],
    ]);
}

it('scores a perfect run as precision/recall/f1 of 1.0', function (): void {
    $runner = new BenchmarkRunner(benchGroundTruth());

    $result = $runner->score([
        benchFinding('app/Http/Controllers/SqlInjectionController.php', VulnerabilityType::SqlInjection, 16),
        benchFinding('app/Http/Controllers/XssController.php', VulnerabilityType::Xss, 15),
    ]);

    expect($result['true_positives'])->toBe(2)
        ->and($result['false_positives'])->toBe(0)
        ->and($result['false_negatives'])->toBe(0)
        ->and($result['precision'])->toBe(1.0)
        ->and($result['recall'])->toBe(1.0)
        ->and($result['f1'])->toBe(1.0);
});

it('counts a missed label as a false negative', function (): void {
    $runner = new BenchmarkRunner(benchGroundTruth());

    $result = $runner->score([
        benchFinding('app/Http/Controllers/SqlInjectionController.php', VulnerabilityType::SqlInjection, 16),
    ]);

    expect($result['true_positives'])->toBe(1)
        ->and($result['false_negatives'])->toBe(1)
        ->and($result['false_positives'])->toBe(0)
        ->and($result['precision'])->toBe(1.0)
        ->and($result['recall'])->toBe(0.5)
        ->and($result['f1'])->toBe(0.6667);
});

it('counts a finding on a clean file as a false positive', function (): void {
    $runner = new BenchmarkRunner(benchGroundTruth());

    $result = $runner->score([
        benchFinding('app/Http/Controllers/SqlInjectionController.php', VulnerabilityType::SqlInjection, 16),
        benchFinding('app/Http/Controllers/XssController.php', VulnerabilityType::Xss, 15),
        benchFinding('app/Http/Controllers/CleanController.php', VulnerabilityType::Idor, 9),
    ]);

    expect($result['true_positives'])->toBe(2)
        ->and($result['false_positives'])->toBe(1)
        ->and($result['false_negatives'])->toBe(0)
        ->and($result['precision'])->toBe(0.6667)
        ->and($result['recall'])->toBe(1.0);
});

it('counts a wrong-type finding on a labeled file as a false positive and the label as a false negative', function (): void {
    $runner = new BenchmarkRunner(benchGroundTruth());

    // Reports XSS where SQLi is expected — wrong type, same file.
    $result = $runner->score([
        benchFinding('app/Http/Controllers/SqlInjectionController.php', VulnerabilityType::Xss, 16),
    ]);

    expect($result['true_positives'])->toBe(0)
        ->and($result['false_positives'])->toBe(1)
        ->and($result['false_negatives'])->toBe(2);
});

it('accepts a synonym type listed in accepted_types', function (): void {
    $runner = new BenchmarkRunner(benchGroundTruth());

    // dynamic_column_injection is an accepted synonym for the sql_injection label.
    $result = $runner->score([
        benchFinding('app/Http/Controllers/SqlInjectionController.php', VulnerabilityType::DynamicColumnInjection, 16),
    ]);

    expect($result['true_positives'])->toBe(1)
        ->and($result['false_positives'])->toBe(0);

    // The TP is credited under the label's canonical type.
    expect($result['per_type'])->toHaveKey('sql_injection')
        ->and($result['per_type']['sql_injection']['true_positives'])->toBe(1);
});

it('treats a finding outside the line tolerance as a miss plus a false positive', function (): void {
    $runner = new BenchmarkRunner(benchGroundTruth());

    // Expected at line 16, tolerance 3 — reporting line 25 is too far.
    $result = $runner->score([
        benchFinding('app/Http/Controllers/SqlInjectionController.php', VulnerabilityType::SqlInjection, 25),
    ]);

    expect($result['true_positives'])->toBe(0)
        ->and($result['false_positives'])->toBe(1)
        ->and($result['false_negatives'])->toBe(2);
});

it('matches within the line tolerance window', function (): void {
    $runner = new BenchmarkRunner(benchGroundTruth());

    // Expected at line 16, reported at 18 — within tolerance of 3.
    $result = $runner->score([
        benchFinding('app/Http/Controllers/SqlInjectionController.php', VulnerabilityType::SqlInjection, 18),
    ]);

    expect($result['true_positives'])->toBe(1)
        ->and($result['false_positives'])->toBe(0);
});

it('ignores findings on files outside the corpus', function (): void {
    $runner = new BenchmarkRunner(benchGroundTruth());

    $result = $runner->score([
        benchFinding('app/Http/Controllers/SqlInjectionController.php', VulnerabilityType::SqlInjection, 16),
        benchFinding('app/Http/Controllers/XssController.php', VulnerabilityType::Xss, 15),
        benchFinding('app/Services/UnrelatedService.php', VulnerabilityType::Idor, 3),
    ]);

    expect($result['true_positives'])->toBe(2)
        ->and($result['false_positives'])->toBe(0)
        ->and($result['false_negatives'])->toBe(0);
});

it('credits at most one true positive per label when duplicate findings are reported', function (): void {
    $runner = new BenchmarkRunner(benchGroundTruth());

    $result = $runner->score([
        benchFinding('app/Http/Controllers/SqlInjectionController.php', VulnerabilityType::SqlInjection, 16),
        benchFinding('app/Http/Controllers/SqlInjectionController.php', VulnerabilityType::SqlInjection, 17),
    ]);

    // One label, two findings → one TP, one duplicate FP.
    expect($result['true_positives'])->toBe(1)
        ->and($result['false_positives'])->toBe(1);
});

it('returns zero metrics for an empty finding set against a labeled corpus', function (): void {
    $runner = new BenchmarkRunner(benchGroundTruth());

    $result = $runner->score([]);

    expect($result['true_positives'])->toBe(0)
        ->and($result['false_positives'])->toBe(0)
        ->and($result['false_negatives'])->toBe(2)
        ->and($result['precision'])->toBe(0.0)
        ->and($result['recall'])->toBe(0.0)
        ->and($result['f1'])->toBe(0.0);
});

it('reports a clean-only corpus with no findings as perfect (no false positives)', function (): void {
    $cleanOnly = GroundTruth::fromArray([
        'line_tolerance' => 3,
        'samples' => [
            ['file' => 'CleanController.php', 'expected' => []],
        ],
    ]);

    $result = (new BenchmarkRunner($cleanOnly))->score([]);

    expect($result['false_positives'])->toBe(0)
        ->and($result['false_negatives'])->toBe(0)
        ->and($result['true_positives'])->toBe(0);
});

it('scores duplicate basenames in different subdirectories independently', function (): void {
    $runner = new BenchmarkRunner(GroundTruth::fromArray([
        'line_tolerance' => 3,
        'samples' => [
            [
                'file' => 'a/Controller.php',
                'expected' => [
                    ['type' => 'sql_injection', 'line' => 10, 'accepted_types' => ['sql_injection']],
                ],
            ],
            [
                'file' => 'b/Controller.php',
                'expected' => [
                    ['type' => 'xss', 'line' => 20, 'accepted_types' => ['xss']],
                ],
            ],
        ],
    ]));

    // Each finding lands on its own subdir file; basename alone would collide.
    $result = $runner->score([
        benchFinding('a/Controller.php', VulnerabilityType::SqlInjection, 10),
        benchFinding('b/Controller.php', VulnerabilityType::Xss, 20),
    ]);

    expect($result['true_positives'])->toBe(2)
        ->and($result['false_positives'])->toBe(0)
        ->and($result['false_negatives'])->toBe(0);
});

it('does not let a finding in one subdir satisfy a same-basename label in another', function (): void {
    $runner = new BenchmarkRunner(GroundTruth::fromArray([
        'line_tolerance' => 3,
        'samples' => [
            [
                'file' => 'a/Controller.php',
                'expected' => [
                    ['type' => 'sql_injection', 'line' => 10, 'accepted_types' => ['sql_injection']],
                ],
            ],
            [
                'file' => 'b/Controller.php',
                'expected' => [
                    ['type' => 'xss', 'line' => 20, 'accepted_types' => ['xss']],
                ],
            ],
        ],
    ]));

    // Only the a/ file is reported correctly; b/ is missed. Under basename keying
    // the SQLi finding could have been mis-bucketed against b/Controller.php.
    $result = $runner->score([
        benchFinding('a/Controller.php', VulnerabilityType::SqlInjection, 10),
    ]);

    expect($result['true_positives'])->toBe(1)
        ->and($result['false_positives'])->toBe(0)
        ->and($result['false_negatives'])->toBe(1);
});

it('credits a command_injection finding under the relabeled corpus sample', function (): void {
    $runner = new BenchmarkRunner(GroundTruth::fromArray([
        'line_tolerance' => 3,
        'samples' => [
            [
                'file' => 'CommandInjectionController.php',
                'expected' => [
                    ['type' => 'command_injection', 'line' => 15, 'accepted_types' => ['command_injection']],
                ],
            ],
        ],
    ]));

    $matched = $runner->score([
        benchFinding('app/Http/Controllers/CommandInjectionController.php', VulnerabilityType::CommandInjection, 15),
    ]);

    expect($matched['true_positives'])->toBe(1)
        ->and($matched['per_type']['command_injection']['true_positives'])->toBe(1);

    // missing_validation is no longer an accepted stand-in for command injection.
    $standIn = $runner->score([
        benchFinding('app/Http/Controllers/CommandInjectionController.php', VulnerabilityType::MissingValidation, 15),
    ]);

    expect($standIn['true_positives'])->toBe(0)
        ->and($standIn['false_positives'])->toBe(1)
        ->and($standIn['false_negatives'])->toBe(1);
});

it('exposes the expected and reported totals', function (): void {
    $runner = new BenchmarkRunner(benchGroundTruth());

    $result = $runner->score([
        benchFinding('app/Http/Controllers/SqlInjectionController.php', VulnerabilityType::SqlInjection, 16),
        benchFinding('app/Http/Controllers/CleanController.php', VulnerabilityType::Idor, 9),
    ]);

    expect($result['expected_total'])->toBe(2)
        ->and($result['reported_total'])->toBe(2);
});
