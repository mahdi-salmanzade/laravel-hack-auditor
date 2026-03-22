<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Support\UsageLog;

it('usage command runs successfully', function (): void {
    $this->artisan('hack:usage')
        ->assertSuccessful();
});

it('usage command shows summary', function (): void {
    $this->artisan('hack:usage')
        ->expectsOutputToContain('Total Scans');
});

it('usage command json output', function (): void {
    $this->artisan('hack:usage', ['--json' => true])
        ->expectsOutputToContain('total_scans');
});

it('usage command clear removes log', function (): void {
    $this->artisan('hack:usage', ['--clear' => true])
        ->expectsOutputToContain('Usage log cleared');
});

it('usage command days filter', function (): void {
    $this->artisan('hack:usage', ['--days' => 7])
        ->assertSuccessful();
});

it('usage command shows empty state when no history', function (): void {
    // Ensure a fresh UsageLog with no data is bound
    $this->app->bind(UsageLog::class, function (): UsageLog {
        $tempPath = sys_get_temp_dir().'/hack-usage-test-'.uniqid().'.json';

        return new UsageLog($tempPath);
    });

    $this->artisan('hack:usage')
        ->expectsOutputToContain('0');
});
