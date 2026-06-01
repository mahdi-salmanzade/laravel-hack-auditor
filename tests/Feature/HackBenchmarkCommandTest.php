<?php

declare(strict_types=1);

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\Artisan;
use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\Benchmark\GroundTruth;
use Mahdi\HackAuditor\Console\HackBenchmarkCommand;
use Mockery\MockInterface;

beforeEach(function (): void {
    // The command is not registered by the service provider yet (pending the
    // commands([...]) wiring noted in the build report), so register a fresh
    // instance on the console kernel for these tests.
    $this->app[Kernel::class]->registerCommand(
        $this->app->make(HackBenchmarkCommand::class),
    );
});

/**
 * Build a mock AIAdapter that returns the same canned response for every chunk.
 */
function mockBenchmarkAdapter(string $response): MockInterface
{
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('send')->andReturn($response);
    $mock->shouldReceive('sendWithUsage')->andReturn([
        'text' => $response,
        'usage' => ['prompt_tokens' => 100, 'completion_tokens' => 50],
    ]);

    return $mock;
}

/**
 * Run hack:benchmark and capture its exit code and textual output.
 *
 * Uses Artisan::call rather than the PendingCommand assertions so the captured
 * stdout is the command's real, complete output.
 *
 * @param  array<string, mixed>  $arguments
 * @return array{code: int, output: string}
 */
function runBenchmark(array $arguments = []): array
{
    $code = Artisan::call('hack:benchmark', $arguments);

    return ['code' => $code, 'output' => Artisan::output()];
}

/**
 * A faked AI response that correctly identifies every labeled vulnerability in
 * the corpus at its ground-truth line — a perfect run.
 *
 * @param  array<int, array{type: string, location: string, line: int}>  $extra
 */
function perfectBenchmarkResponse(array $extra = []): string
{
    $base = [
        ['type' => 'sql_injection', 'location' => 'SqlInjectionController.php', 'line' => 16],
        ['type' => 'xss', 'location' => 'XssController.php', 'line' => 15],
        ['type' => 'idor', 'location' => 'IdorController.php', 'line' => 14],
        ['type' => 'command_injection', 'location' => 'CommandInjectionController.php', 'line' => 15],
        ['type' => 'mass_assignment', 'location' => 'MassAssignmentModel.php', 'line' => 11],
        ['type' => 'ssrf', 'location' => 'SsrfController.php', 'line' => 16],
        ['type' => 'sensitive_data_exposure', 'location' => 'SensitiveDataController.php', 'line' => 18],
        ['type' => 'auth_bypass', 'location' => 'BrokenAccessControlController.php', 'line' => 16],
    ];

    $vulnerabilities = array_map(static function (array $v): array {
        return [
            'type' => $v['type'],
            'location' => $v['location'],
            'line' => $v['line'],
            'severity' => 'high',
            'description' => 'Benchmark fixture finding.',
            'proof' => 'proof',
            'fix' => 'fix',
        ];
    }, array_merge($base, $extra));

    return json_encode([
        'vulnerabilities' => $vulnerabilities,
        'overall_score' => 30,
        'summary' => 'Benchmark corpus analysis.',
        'ctf_idea' => '',
    ], JSON_THROW_ON_ERROR);
}

it('reports a perfect score when the AI finds every labeled vulnerability', function (): void {
    $this->app->instance(AIAdapter::class, mockBenchmarkAdapter(perfectBenchmarkResponse()));

    $result = runBenchmark(['--json' => true]);

    expect($result['output'])
        ->toContain('"precision": 1')
        ->toContain('"recall": 1')
        ->toContain('"f1": 1')
        ->and($result['code'])->toBe(0);
});

it('passes the CI gate when F1 meets the threshold', function (): void {
    $this->app->instance(AIAdapter::class, mockBenchmarkAdapter(perfectBenchmarkResponse()));

    $result = runBenchmark(['--min-f1' => '0.9', '--json' => true]);

    expect($result['output'])->toContain('"passed": true')
        ->and($result['code'])->toBe(0);
});

it('fails the CI gate when F1 is below the threshold', function (): void {
    // Only report 2 of the 8 labeled vulns → recall 0.25, F1 well below 0.9.
    $partial = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'sql_injection',
                'location' => 'SqlInjectionController.php',
                'line' => 16,
                'severity' => 'high',
                'description' => 'partial',
                'proof' => 'p',
                'fix' => 'f',
            ],
            [
                'type' => 'xss',
                'location' => 'XssController.php',
                'line' => 15,
                'severity' => 'high',
                'description' => 'partial',
                'proof' => 'p',
                'fix' => 'f',
            ],
        ],
        'overall_score' => 60,
        'summary' => 'partial',
        'ctf_idea' => '',
    ], JSON_THROW_ON_ERROR);

    $this->app->instance(AIAdapter::class, mockBenchmarkAdapter($partial));

    $result = runBenchmark(['--min-f1' => '0.9', '--json' => true]);

    expect($result['output'])->toContain('"passed": false')
        ->and($result['code'])->toBe(1);
});

it('penalizes false positives on clean samples in precision', function (): void {
    // Perfect recall, but also flags a clean controller → one false positive.
    $response = perfectBenchmarkResponse([
        ['type' => 'idor', 'location' => 'CleanController.php', 'line' => 14],
    ]);

    $this->app->instance(AIAdapter::class, mockBenchmarkAdapter($response));

    $result = runBenchmark(['--json' => true]);

    expect($result['output'])
        ->toContain('"false_positives": 1')
        ->toContain('"recall": 1');
});

it('renders a human-readable table without --json', function (): void {
    $this->app->instance(AIAdapter::class, mockBenchmarkAdapter(perfectBenchmarkResponse()));

    $result = runBenchmark();

    expect($result['output'])
        ->toContain('Accuracy Benchmark')
        ->toContain('Precision')
        ->toContain('F1 Score')
        ->and($result['code'])->toBe(0);
});

it('shows a PASS line when a threshold is met in table mode', function (): void {
    $this->app->instance(AIAdapter::class, mockBenchmarkAdapter(perfectBenchmarkResponse()));

    $result = runBenchmark(['--min-f1' => '0.5']);

    expect($result['output'])->toContain('PASS')
        ->and($result['code'])->toBe(0);
});

it('errors when the samples directory does not exist', function (): void {
    $result = runBenchmark(['--samples' => '/nonexistent/samples/dir']);

    expect($result['code'])->toBe(1);
});

it('includes a per-type breakdown in JSON output', function (): void {
    $this->app->instance(AIAdapter::class, mockBenchmarkAdapter(perfectBenchmarkResponse()));

    $result = runBenchmark(['--json' => true]);

    expect($result['output'])
        ->toContain('"per_type"')
        ->toContain('sql_injection')
        ->and($result['code'])->toBe(0);
});

it('uses the packaged corpus by default', function (): void {
    $groundTruth = GroundTruth::default();

    expect($groundTruth->expectedVulnerabilityCount())->toBe(8)
        ->and($groundTruth->cleanSampleCount())->toBe(2);
});
