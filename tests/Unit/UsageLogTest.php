<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Support\UsageLog;
use Mahdi\HackAuditor\Support\UsageTracker;

beforeEach(function (): void {
    $this->tempDir = sys_get_temp_dir().'/hack-auditor-usage-'.uniqid();
    mkdir($this->tempDir, 0755, true);
    $this->logPath = $this->tempDir.'/usage.json';
});

afterEach(function (): void {
    if (is_dir($this->tempDir)) {
        array_map('unlink', glob($this->tempDir.'/*') ?: []);
        rmdir($this->tempDir);
    }
});

function createTrackerWithUsage(int $prompt, int $completion): UsageTracker
{
    $tracker = new UsageTracker;
    $tracker->record($prompt, $completion);

    return $tracker;
}

it('record creates json file', function (): void {
    $log = new UsageLog($this->logPath);
    $log->record(createTrackerWithUsage(500, 200));

    expect(file_exists($this->logPath))->toBeTrue();
});

it('record appends entries', function (): void {
    $log = new UsageLog($this->logPath);
    $log->record(createTrackerWithUsage(500, 200));
    $log->record(createTrackerWithUsage(300, 100));

    expect($log->all())->toHaveCount(2);
});

it('all returns empty when no file', function (): void {
    $log = new UsageLog($this->tempDir.'/nonexistent.json');

    expect($log->all())->toBe([]);
});

it('all returns entries', function (): void {
    $log = new UsageLog($this->logPath);
    $log->record(createTrackerWithUsage(100, 50));
    $log->record(createTrackerWithUsage(200, 100));
    $log->record(createTrackerWithUsage(300, 150));

    $entries = $log->all();

    expect($entries)->toHaveCount(3)
        ->and($entries[0])->toHaveKeys(['timestamp', 'total_tokens'])
        ->and($entries[1])->toHaveKeys(['timestamp', 'total_tokens'])
        ->and($entries[2])->toHaveKeys(['timestamp', 'total_tokens']);
});

it('total tokens sums correctly', function (): void {
    $log = new UsageLog($this->logPath);
    $log->record(createTrackerWithUsage(1000, 500));
    $log->record(createTrackerWithUsage(2000, 1000));

    expect($log->totalTokens())->toBe(4500);
});

it('total cost sums correctly', function (): void {
    $tracker1 = createTrackerWithUsage(1000, 500);
    $tracker2 = createTrackerWithUsage(2000, 1000);

    $log = new UsageLog($this->logPath);
    $log->record($tracker1);
    $log->record($tracker2);

    $expectedCost = $tracker1->estimateCost() + $tracker2->estimateCost();

    expect($log->totalCost())->toBe($expectedCost);
});

it('scan count returns correct count', function (): void {
    $log = new UsageLog($this->logPath);
    $log->record(createTrackerWithUsage(100, 50));
    $log->record(createTrackerWithUsage(200, 100));
    $log->record(createTrackerWithUsage(300, 150));
    $log->record(createTrackerWithUsage(400, 200));

    expect($log->scanCount())->toBe(4);
});

it('since filters by date', function (): void {
    $oldEntries = [
        [
            'timestamp' => now()->subWeek()->toIso8601String(),
            'prompt_tokens' => 100,
            'completion_tokens' => 50,
            'total_tokens' => 150,
            'requests' => 1,
            'estimated_cost_usd' => 0.001,
            'elapsed_seconds' => 1.0,
            'token_limit' => null,
            'files_scanned' => null,
            'files_skipped' => 0,
            'path' => null,
            'score' => null,
        ],
        [
            'timestamp' => now()->subMonth()->toIso8601String(),
            'prompt_tokens' => 200,
            'completion_tokens' => 100,
            'total_tokens' => 300,
            'requests' => 1,
            'estimated_cost_usd' => 0.002,
            'elapsed_seconds' => 2.0,
            'token_limit' => null,
            'files_scanned' => null,
            'files_skipped' => 0,
            'path' => null,
            'score' => null,
        ],
    ];

    file_put_contents(
        $this->logPath,
        json_encode($oldEntries, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
    );

    $log = new UsageLog($this->logPath);
    $log->record(createTrackerWithUsage(500, 250));

    $recent = $log->since(now()->subDay());

    expect($recent)->toHaveCount(1)
        ->and($recent[0]['total_tokens'])->toBe(750);
});

it('summary returns aggregated data', function (): void {
    $log = new UsageLog($this->logPath);
    $log->record(createTrackerWithUsage(1000, 500));
    $log->record(createTrackerWithUsage(2000, 1000));

    $summary = $log->summary();

    expect($summary['total_scans'])->toBe(2)
        ->and($summary['total_tokens'])->toBe(4500)
        ->and($summary['total_prompt_tokens'])->toBe(3000)
        ->and($summary['total_completion_tokens'])->toBe(1500);
});

it('clear removes file', function (): void {
    $log = new UsageLog($this->logPath);
    $log->record(createTrackerWithUsage(500, 200));
    $log->clear();

    expect(file_exists($this->logPath))->toBeFalse()
        ->and($log->all())->toBe([]);
});

it('handles corrupted json gracefully', function (): void {
    file_put_contents($this->logPath, '{not valid json!!!');

    $log = new UsageLog($this->logPath);

    expect($log->all())->toBe([]);
});

it('creates directory if not exists', function (): void {
    $nestedPath = $this->tempDir.'/deep/nested/dir/usage.json';
    $log = new UsageLog($nestedPath);
    $log->record(createTrackerWithUsage(100, 50));

    expect(file_exists($nestedPath))->toBeTrue();

    // Clean up nested directories
    unlink($nestedPath);
    rmdir(dirname($nestedPath));
    rmdir(dirname($nestedPath, 2));
    rmdir(dirname($nestedPath, 3));
});
