<?php

declare(strict_types=1);

it('demo runs successfully without an API key', function (): void {
    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->assertSuccessful();
});

it('demo output contains the banner', function (): void {
    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->expectsOutputToContain('HACK AUDITOR');
});

it('demo output contains the security score 8/100', function (): void {
    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->expectsOutputToContain('8/100');
});

it('demo output contains vulnerability types', function (): void {
    $result = $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true]);

    $result->expectsOutputToContain('SQL Injection')
        ->expectsOutputToContain('Cross-Site Scripting')
        ->expectsOutputToContain('Mass Assignment');
});

it('demo output contains the critical warning box', function (): void {
    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->expectsOutputToContain('CRITICAL');
});

it('demo cleans up temp files after run', function (): void {
    $demoFile = storage_path('hack-auditor/demo/InsecureController.php');

    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->assertSuccessful();

    expect(file_exists($demoFile))->toBeFalse();
});

it('demo cleans up temp directory after run', function (): void {
    $demoDir = storage_path('hack-auditor/demo');

    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->assertSuccessful();

    // The directory may or may not exist (rmdir may fail if parent dirs remain),
    // but the controller file should definitely be gone
    if (is_dir($demoDir)) {
        $files = array_diff(scandir($demoDir), ['.', '..']);
        expect($files)->toBeEmpty();
    }
});

it('demo --quick flag skips animations and completes rapidly', function (): void {
    $start = hrtime(true);

    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->assertSuccessful();

    $elapsedMs = (hrtime(true) - $start) / 1_000_000;

    // With --quick, should complete in well under 5 seconds (no usleep delays)
    expect($elapsedMs)->toBeLessThan(5000);
});

it('demo output contains vulnerability count statistics', function (): void {
    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->expectsOutputToContain('12')
        ->expectsOutputToContain('vulnerabilities');
});

it('demo output mentions the hack:scan command', function (): void {
    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->expectsOutputToContain('hack:scan');
});

it('demo output contains scanning animation steps', function (): void {
    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->expectsOutputToContain('Initializing AI security engine')
        ->expectsOutputToContain('Running vulnerability analysis');
});

it('demo returns success exit code', function (): void {
    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->assertExitCode(0);
});
