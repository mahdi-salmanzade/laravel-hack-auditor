<?php

declare(strict_types=1);

it('demo runs successfully without an API key', function (): void {
    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->assertSuccessful();
});

it('demo output contains the banner', function (): void {
    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->expectsOutputToContain('InsecureController.php (12 planted flaws)');
});

it('demo score is computed with the real formula, not typed in', function (): void {
    // 5 critical (40) + 4 high (20) + 2 medium (10) = 300 penalty -> max(0, 100 - 300) = 0.
    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->expectsOutputToContain('SECURITY SCORE:  0/100')
        ->expectsOutputToContain('score = max(0, 100 − 5×40 critical − 4×20 high − 2×10 medium)');
});

it('demo says its findings are pre-recorded and never claims an AI ran', function (): void {
    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->expectsOutputToContain('pre-recorded demo findings — no AI call')
        ->doesntExpectOutputToContain('Just watched AI hack my Laravel app')
        ->assertSuccessful();
});

it('demo shows the confirmed / review split, coverage and confidence like a real scan', function (): void {
    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->expectsOutputToContain('Confirmed vulnerabilities (11)')
        ->expectsOutputToContain('Needs review (1)')
        ->expectsOutputToContain('coverage  1/1 files analyzed (100%)')
        ->expectsOutputToContain('Confidence')
        ->expectsOutputToContain('proven');
});

it('demo does not touch the clipboard unless --copy is passed', function (): void {
    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->expectsOutputToContain('Run with --copy to copy this to your clipboard.')
        ->doesntExpectOutputToContain('Copied to clipboard.');
});

it('demo output contains vulnerability types', function (): void {
    $result = $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true]);

    $result->expectsOutputToContain('SQL Injection')
        ->expectsOutputToContain('Authentication Bypass')
        ->expectsOutputToContain('and 5 more');
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
        ->expectsOutputToContain('Found 11 confirmed vulnerabilities: 5 Critical, 4 High, 2 Medium, 0 Low (+1 for review)');
});

it('demo output mentions the hack:scan command', function (): void {
    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->expectsOutputToContain('hack:scan');
});

it('demo output contains scanning animation steps', function (): void {
    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->expectsOutputToContain('Loading vulnerable controller...')
        ->expectsOutputToContain('Replaying pre-recorded findings (no AI request is made)...');
});

it('demo returns success exit code', function (): void {
    $this->artisan('hack:demo', ['--quick' => true, '--no-interaction' => true])
        ->assertExitCode(0);
});
