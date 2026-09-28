<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\Scanner\HackScanner;
use Mahdi\HackAuditor\Support\Fingerprint;
use Mahdi\HackAuditor\Support\ScanHistory;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * Regression tests for hack:scan / hack:report output, exit codes and
 * persistence. Each test names the defect it pins.
 */
function reportingAdapter(array $vulnerabilities, int $score = 60, string $summary = 'summary'): AIAdapter
{
    $response = json_encode([
        'vulnerabilities' => $vulnerabilities,
        'overall_score' => $score,
        'summary' => $summary,
        'ctf_idea' => '',
    ], JSON_THROW_ON_ERROR);

    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('send')->andReturn($response);
    $mock->shouldReceive('sendWithUsage')->andReturn([
        'text' => $response,
        'usage' => ['prompt_tokens' => 100, 'completion_tokens' => 10],
    ]);

    return $mock;
}

function reportingFinding(string $severity = 'critical', string $description = 'SQL injection via raw query', int $line = 3, string $type = 'sql_injection'): array
{
    return [
        'type' => $type,
        'location' => 'app/Http/Controllers/A.php',
        'line' => $line,
        'severity' => $severity,
        'description' => $description,
        'proof' => 'DB::select($q)',
        'fix' => 'bind it',
    ];
}

/**
 * Swap the AI adapter. HackScanner is a container singleton, so it has to be
 * forgotten too or the next scan silently reuses the previous adapter.
 */
function useReportingAdapter(AIAdapter $adapter): void
{
    app()->instance(AIAdapter::class, $adapter);
    app()->forgetInstance(HackScanner::class);
}

/**
 * Run hack:scan and return [exit code, stdout].
 *
 * @return array{0: int, 1: string}
 */
function runScan(array $options = []): array
{
    $output = new BufferedOutput;
    $code = Artisan::call('hack:scan', ['--force' => true] + $options, $output);

    return [$code, $output->fetch()];
}

beforeEach(function (): void {
    $this->scanDir = realpath(sys_get_temp_dir()).'/hack-auditor-reporting-'.uniqid();
    mkdir($this->scanDir.'/app/Http/Controllers', 0755, true);
    file_put_contents(
        $this->scanDir.'/app/Http/Controllers/A.php',
        "<?php\nnamespace App\\Http\\Controllers;\nclass A { public function i(\$q) { return \\DB::select(\$q); } }\n",
    );

    (new ReflectionProperty($this->app, 'basePath'))->setValue($this->app, $this->scanDir);
    $this->app->useStoragePath($this->scanDir.'/storage');

    config([
        'hack-auditor.scan.paths' => ['app/Http/Controllers'],
        'hack-auditor.scan.baseline_path' => $this->scanDir.'/baseline.json',
        'hack-auditor.usage.log_enabled' => false,
    ]);

    Fingerprint::flushCache();
});

afterEach(function (): void {
    exec('rm -rf '.escapeshellarg($this->scanDir));
});

// 1. Exit code vs. filters

it('does not fail the build on a critical finding the baseline accepted', function (): void {
    useReportingAdapter(reportingAdapter([reportingFinding()]));

    [$before] = runScan(['--json' => true]);
    runScan(['--update-baseline' => true]);
    [$after, $json] = runScan(['--json' => true]);

    expect($before)->toBe(1)
        ->and($after)->toBe(0)
        ->and(json_decode($json, true)['filters']['baseline_suppressed'])->toBe(1);
});

it('keeps an accepted finding accepted when the AI rewords it', function (): void {
    useReportingAdapter(reportingAdapter([reportingFinding(description: 'SQL injection via raw query')]));
    runScan(['--update-baseline' => true]);

    useReportingAdapter(reportingAdapter([reportingFinding(description: 'Raw SQL built from request input')]));
    [$code, $json] = runScan(['--json' => true]);

    expect($code)->toBe(0)
        ->and(json_decode($json, true)['vulnerabilities'])->toBe([]);
});

it('does not gate on a finding --severity hid from the output', function (): void {
    // The gate used to read the unfiltered report: a finding the user filtered
    // out of view could still fail the build with nothing on screen to explain it.
    useReportingAdapter(reportingAdapter([reportingFinding('high')]));

    expect(runScan(['--json' => true, '--fail-on' => 'high'])[0])->toBe(1)
        ->and(runScan(['--json' => true, '--fail-on' => 'high', '--severity' => 'Critical'])[0])->toBe(0);
});

it('gates on --fail-on against the filtered list', function (): void {
    useReportingAdapter(reportingAdapter([reportingFinding('high')]));

    expect(runScan(['--json' => true])[0])->toBe(0)
        ->and(runScan(['--json' => true, '--fail-on' => 'high'])[0])->toBe(1)
        ->and(runScan(['--json' => true, '--fail-on' => 'medium'])[0])->toBe(1)
        ->and(runScan(['--json' => true, '--fail-on' => 'none'])[0])->toBe(0);
});

it('rejects an unknown --fail-on, --format or --severity with exit 2 before scanning', function (array $options): void {
    $adapter = Mockery::mock(AIAdapter::class);
    $adapter->shouldNotReceive('send', 'sendWithUsage');
    $this->app->instance(AIAdapter::class, $adapter);

    expect(runScan($options)[0])->toBe(2);
})->with([
    'fail-on typo' => [['--fail-on' => 'hgih']],
    'format typo' => [['--format' => 'xml']],
    'severity typo' => [['--severity' => 'Severe']],
    'json + other format' => [['--json' => true, '--format' => 'sarif']],
]);

it('uses severity.minimum_report as the --severity default', function (): void {
    config(['hack-auditor.severity.minimum_report' => 'High']);
    useReportingAdapter(reportingAdapter([reportingFinding('high'), reportingFinding('low', line: 2)]));

    [, $json] = runScan(['--json' => true]);
    $decoded = json_decode($json, true);

    expect($decoded['filters']['minimum_severity'])->toBe('high')
        ->and($decoded['counts']['total'])->toBe(1);
});

it('reports the same counts in the header and the footer after filtering', function (): void {
    useReportingAdapter(reportingAdapter([reportingFinding('critical'), reportingFinding('low', line: 2)]));

    [, $output] = runScan(['--severity' => 'Critical']);

    expect($output)->toContain('Found 1 vulnerabilities in 1 affected file(s)')
        ->toContain('Found 1 vulnerabilities (filtered to Critical+)');
});

// 9. Bad inputs

it('exits 2 when --path does not exist', function (string $format): void {
    useReportingAdapter(reportingAdapter([]));

    [$code, $output] = runScan(['--path' => 'app/Nope.php', '--format' => $format]);

    expect($code)->toBe(2);

    if ($format === 'json') {
        $decoded = json_decode($output, true);

        expect($decoded['target_error'])->toContain('app/Nope.php')
            ->and($decoded['overall_score'])->toBeNull();
    }
})->with(['table', 'json', 'sarif', 'markdown']);

it('exits 2 when --baseline is required but the file is missing', function (): void {
    useReportingAdapter(reportingAdapter([]));

    [$code, $output] = runScan(['--baseline' => true]);

    expect($code)->toBe(2)
        ->and($output)->toContain('--baseline requires one');
});

// 3/4. Output safety

it('neutralises terminal escape and formatter injection in finding text', function (): void {
    $hostile = "Click <href=https://evil.example/x>docs</> \e]0;pwned\x07 then <error>boom</error>";
    useReportingAdapter(reportingAdapter([reportingFinding(description: $hostile)], summary: "sum \e[2J <href=https://e.x>y</>"));

    $output = new BufferedOutput(decorated: true);
    Artisan::call('hack:scan', ['--force' => true, '--detailed' => true], $output);
    $text = $output->fetch();

    expect($text)->not->toContain("\e]8;;https://evil.example")
        ->not->toContain("\e]0;pwned")
        ->not->toContain("\e[2J")
        ->toContain('<error>boom</error>');
});

it('emits valid JSON when report text contains invalid UTF-8', function (): void {
    // A Latin-1 --path ends up verbatim in target_error. json_encode() used to
    // return false on it and the command printed an empty line.
    useReportingAdapter(reportingAdapter([]));

    [$code, $json] = runScan(['--json' => true, '--path' => "app/caf\xE9.php"]);
    $decoded = json_decode($json, true);

    expect($code)->toBe(2)
        ->and($decoded)->toBeArray()
        ->and($decoded['target_error'])->toContain('caf');
});

it('writes JSON raw, so formatter-like tags in finding text survive', function (): void {
    useReportingAdapter(reportingAdapter([reportingFinding(description: 'tainted <error>tag</error> <href=x>y</>')]));

    [, $json] = runScan(['--json' => true]);
    $decoded = json_decode($json, true);

    expect($decoded['vulnerabilities'][0]['description'])->toBe('tainted <error>tag</error> <href=x>y</>')
        ->and($decoded['vulnerabilities'][0]['fingerprint'])->toMatch('/^[0-9a-f]{32}$/')
        ->and($decoded['vulnerabilities'][0]['references'][0]['title'])->toBe('CWE-89')
        ->and($decoded)->toHaveKeys(['score_breakdown', 'target_error', 'coverage', 'filters']);
});

// 14. Formats

it('outputs SARIF 2.1.0 with --format=sarif', function (): void {
    useReportingAdapter(reportingAdapter([reportingFinding()]));

    [$code, $output] = runScan(['--format' => 'sarif']);
    $sarif = json_decode($output, true);

    expect($code)->toBe(1)
        ->and($sarif['version'])->toBe('2.1.0')
        ->and($sarif['runs'][0]['results'][0]['ruleId'])->toBe('sql_injection');
});

it('outputs Markdown with --format=markdown', function (): void {
    useReportingAdapter(reportingAdapter([reportingFinding()]));

    [, $output] = runScan(['--format' => 'markdown']);

    expect($output)->toStartWith('# Laravel Hack Auditor')
        ->toContain('## Confirmed vulnerabilities (1)');
});

// 8. Since-last-scan delta

it('compares against the previous saved scan, not the one it just saved', function (): void {
    useReportingAdapter(reportingAdapter([reportingFinding('high')], score: 80));
    runScan(['--save' => true]);

    useReportingAdapter(reportingAdapter([reportingFinding('high'), reportingFinding('critical', type: 'xss')], score: 40));
    [, $output] = runScan(['--save' => true]);

    expect($output)->toContain('since last scan')
        ->toContain('Since last scan: 1 new, 0 resolved, 1 unchanged')
        ->not->toContain('(+0 since last scan)')
        ->and((new ScanHistory)->count())->toBe(2);
});

// 7/10. hack:report

it('regenerates a saved scan with coverage-based Files Analyzed and every finding field', function (): void {
    useReportingAdapter(reportingAdapter([reportingFinding()]));
    runScan(['--save' => true]);

    $this->artisan('hack:report', ['--output' => 'report.html'])->assertSuccessful();
    $html = file_get_contents($this->scanDir.'/report.html');

    expect($html)->toMatch('/Files Analyzed<\/div>\s*<div class="meta-value">1</')
        ->toContain('confidence: probable')
        ->toContain('Token Usage');
});

it('writes SARIF and Markdown from a saved scan', function (string $format, string $needle): void {
    useReportingAdapter(reportingAdapter([reportingFinding()]));
    runScan(['--save' => true]);

    $this->artisan('hack:report', ['--format' => $format, '--output' => "out.{$format}"])->assertSuccessful();

    expect(file_get_contents($this->scanDir."/out.{$format}"))->toContain($needle);
})->with([
    ['sarif', '"version": "2.1.0"'],
    ['markdown', '## Confirmed vulnerabilities (1)'],
]);

it('rejects an unknown hack:report --format', function (): void {
    $this->artisan('hack:report', ['--format' => 'pdf'])->assertExitCode(2);
});
