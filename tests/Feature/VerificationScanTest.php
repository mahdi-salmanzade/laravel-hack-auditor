<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\Scanner\HackScanner;

function makeScanResponse(array $vulns, int $score = 30): string
{
    return json_encode([
        'vulnerabilities' => $vulns,
        'overall_score' => $score,
        'summary' => 'Scan complete.',
        'ctf_idea' => '',
    ], JSON_THROW_ON_ERROR);
}

function makeVerifyResponse(bool $verified, string $exploit = '', string $reasoning = ''): string
{
    return json_encode([
        'verified' => $verified,
        'exploit' => $exploit,
        'reasoning' => $reasoning,
    ], JSON_THROW_ON_ERROR);
}

function buildHighVuln(string $file = 'app/Http/Controllers/TestController.php'): array
{
    return [
        'type' => 'sql_injection',
        'location' => $file,
        'line' => 10,
        'severity' => 'high',
        'description' => 'Raw SQL concatenation with user input.',
        'proof' => 'DB::select("SELECT * FROM users WHERE id = $id")',
        'fix' => 'DB::select("SELECT * FROM users WHERE id = ?", [$id])',
    ];
}

function buildCriticalVuln(string $file = 'app/Http/Controllers/TestController.php'): array
{
    return [
        'type' => 'auth_bypass',
        'location' => $file,
        'line' => 20,
        'severity' => 'critical',
        'description' => 'Broken authentication: hardcoded admin bypass.',
        'proof' => "if (\$user === 'admin') Auth::loginUsingId(1);",
        'fix' => 'Remove the hardcoded check and use proper credential verification.',
    ];
}

function buildLowVuln(string $file = 'app/Http/Controllers/TestController.php'): array
{
    return [
        'type' => 'mass_assignment',
        'location' => $file,
        'line' => 30,
        'severity' => 'low',
        'description' => 'Model may be mass-assigned.',
        'proof' => 'User::create($request->all())',
        'fix' => 'Use $request->validated().',
    ];
}

function bindAI(array $textQueue): void
{
    $mock = Mockery::mock(AIAdapter::class);

    foreach ($textQueue as $text) {
        $mock->shouldReceive('sendWithUsage')
            ->once()
            ->andReturn([
                'text' => $text,
                'usage' => ['prompt_tokens' => 100, 'completion_tokens' => 50],
            ]);
    }

    $mock->shouldReceive('send')->andReturn($textQueue[0] ?? '{}');
    app()->instance(AIAdapter::class, $mock);
    app()->forgetInstance(HackScanner::class);
}

function runScanJson(array $arguments = []): string
{
    Artisan::call('hack:scan', array_merge(['--json' => true], $arguments));

    return Artisan::output();
}

beforeEach(function (): void {
    $this->tempDir = sys_get_temp_dir().'/hack-auditor-verify-'.uniqid();
    $controllerDir = $this->tempDir.'/app/Http/Controllers';
    mkdir($controllerDir, 0755, true);
    $this->tempDir = realpath($this->tempDir);
    file_put_contents(
        $this->tempDir.'/app/Http/Controllers/TestController.php',
        '<?php class TestController { function handle($request) { /* vulnerable */ } }',
    );

    $reflector = new ReflectionProperty($this->app, 'basePath');
    $reflector->setValue($this->app, $this->tempDir);
    $this->app['config']->set('hack-auditor.scan.paths', ['app/Http/Controllers']);
});

afterEach(function (): void {
    if (is_dir($this->tempDir)) {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->tempDir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($iterator as $file) {
            $file->isDir() ? rmdir($file->getRealPath()) : unlink($file->getRealPath());
        }

        rmdir($this->tempDir);
    }

    Mockery::close();
    $this->app->forgetInstance(HackScanner::class);
});

it('without --verify does not call verification and leaves fields null', function (): void {
    bindAI([makeScanResponse([buildHighVuln()])]);

    $output = runScanJson();

    expect($output)->toContain('"verification"')
        ->and($output)->toContain('"attempted": false')
        ->and($output)->toContain('"verified": 0')
        ->and($output)->toContain('"downgraded": 0');
});

it('with --verify calls verification only on HIGH+ findings', function (): void {
    bindAI([
        makeScanResponse([buildHighVuln(), buildLowVuln()]),
        makeVerifyResponse(true, 'GET /?id=1 UNION SELECT password FROM users'),
    ]);

    $output = runScanJson(['--verify' => true]);

    expect($output)->toContain('"attempted": true')
        ->and($output)->toContain('"verified": 1')
        ->and($output)->toContain('"downgraded": 0')
        ->and($output)->toContain('"exploit_proof"');
});

it('with --verify and verified=true retains original severity', function (): void {
    bindAI([
        makeScanResponse([buildCriticalVuln()]),
        makeVerifyResponse(true, 'POST /login\nusername=admin&password=anything'),
    ]);

    $output = runScanJson(['--verify' => true]);

    expect($output)->toContain('"severity": "critical"')
        ->and($output)->toContain('"exploit_verified": true')
        ->and($output)->toContain('"verified": 1');
});

it('with --verify and verified=false downgrades Critical to High', function (): void {
    bindAI([
        makeScanResponse([buildCriticalVuln()]),
        makeVerifyResponse(false, '', 'Validation middleware blocks the exploit path.'),
    ]);

    $output = runScanJson(['--verify' => true]);

    expect($output)->toContain('"severity": "high"')
        ->and($output)->toContain('"original_severity": "critical"')
        ->and($output)->toContain('"exploit_verified": false')
        ->and($output)->toContain('"downgraded": 1');
});

it('with --verify and verified=false downgrades High to Medium', function (): void {
    bindAI([
        makeScanResponse([buildHighVuln()]),
        makeVerifyResponse(false, '', 'Input is sanitized before reaching the sink.'),
    ]);

    $output = runScanJson(['--verify' => true]);

    expect($output)->toContain('"severity": "medium"')
        ->and($output)->toContain('"original_severity": "high"')
        ->and($output)->toContain('"downgraded": 1');
});

it('with --verify where model verifies all findings records zero downgrades', function (): void {
    bindAI([
        makeScanResponse([buildHighVuln(), buildCriticalVuln()], score: 20),
        makeVerifyResponse(true, 'exploit-payload-A'),
        makeVerifyResponse(true, 'exploit-payload-B'),
    ]);

    $output = runScanJson(['--verify' => true]);

    expect($output)->toContain('"verified": 2')
        ->and($output)->toContain('"downgraded": 0');
});

it('with --verify where model verifies none sets all downgraded', function (): void {
    bindAI([
        makeScanResponse([buildHighVuln(), buildCriticalVuln()], score: 20),
        makeVerifyResponse(false, '', 'no exploit'),
        makeVerifyResponse(false, '', 'no exploit'),
    ]);

    $output = runScanJson(['--verify' => true]);

    expect($output)->toContain('"verified": 0')
        ->and($output)->toContain('"downgraded": 2');
});

it('verification JSON has correct shape with token counts', function (): void {
    bindAI([
        makeScanResponse([buildHighVuln()]),
        makeVerifyResponse(true, 'payload here'),
    ]);

    $output = runScanJson(['--verify' => true]);

    expect($output)->toContain('"verification"')
        ->and($output)->toContain('"attempted": true')
        ->and($output)->toContain('"input_tokens": 100')
        ->and($output)->toContain('"output_tokens": 50');
});

it('verification is disabled by default so cost stays flat', function (): void {
    bindAI([makeScanResponse([buildHighVuln()])]);

    $output = runScanJson();

    expect($output)->toContain('"input_tokens": 0')
        ->and($output)->toContain('"output_tokens": 0');
});
