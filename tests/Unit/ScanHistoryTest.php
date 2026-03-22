<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Support\ScanHistory;

beforeEach(function (): void {
    $this->tempDir = sys_get_temp_dir().'/hack-auditor-history-'.uniqid();
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
});

it('save creates json file with ulid', function (): void {
    $history = new ScanHistory($this->tempDir);

    $history->save(['score' => 85]);

    $files = glob($this->tempDir.'/*.json');

    expect($files)->toHaveCount(1)
        ->and($files[0])->toEndWith('.json');
});

it('save returns ulid string', function (): void {
    $history = new ScanHistory($this->tempDir);

    $id = $history->save(['score' => 90]);

    expect($id)->toBeString()
        ->not->toBeEmpty()
        ->and(strlen($id))->toBe(26);
});

it('find returns saved scan', function (): void {
    $history = new ScanHistory($this->tempDir);

    $id = $history->save(['score' => 75, 'summary' => 'Test scan']);
    $found = $history->find($id);

    expect($found)->toBeArray()
        ->and($found['score'])->toBe(75)
        ->and($found['summary'])->toBe('Test scan')
        ->and($found['id'])->toBe($id);
});

it('find returns null for missing id', function (): void {
    $history = new ScanHistory($this->tempDir);

    expect($history->find('nonexistent'))->toBeNull();
});

it('latest returns most recent scan', function (): void {
    $history = new ScanHistory($this->tempDir);

    $history->save(['score' => 50]);
    usleep(1000);
    $secondId = $history->save(['score' => 80]);

    $latest = $history->latest();

    expect($latest)->toBeArray()
        ->and($latest['id'])->toBe($secondId)
        ->and($latest['score'])->toBe(80);
});

it('latest returns null when empty', function (): void {
    $history = new ScanHistory($this->tempDir);

    expect($history->latest())->toBeNull();
});

it('all returns scans newest first', function (): void {
    $history = new ScanHistory($this->tempDir);

    $id1 = $history->save(['score' => 10]);
    usleep(1000);
    $id2 = $history->save(['score' => 20]);
    usleep(1000);
    $id3 = $history->save(['score' => 30]);

    $all = $history->all();

    expect($all)->toHaveCount(3)
        ->and($all[0]['id'])->toBe($id3)
        ->and($all[1]['id'])->toBe($id2)
        ->and($all[2]['id'])->toBe($id1);
});

it('recent limits results', function (): void {
    $history = new ScanHistory($this->tempDir);

    for ($i = 0; $i < 5; $i++) {
        $history->save(['score' => $i * 10]);
        usleep(1000);
    }

    $recent = $history->recent(3);

    expect($recent)->toHaveCount(3);
});

it('with critical filters correctly', function (): void {
    $history = new ScanHistory($this->tempDir);

    $criticalId = $history->save(['score' => 30, 'counts' => ['critical' => 2, 'high' => 1]]);
    $safeId = $history->save(['score' => 90, 'counts' => ['critical' => 0, 'high' => 0]]);

    $critical = $history->withCritical();

    expect($critical)->toHaveCount(1)
        ->and($critical[0]['id'])->toBe($criticalId)
        ->and($critical[0]['counts']['critical'])->toBe(2);
});

it('count returns number of scans', function (): void {
    $history = new ScanHistory($this->tempDir);

    $history->save(['score' => 10]);
    $history->save(['score' => 20]);
    $history->save(['score' => 30]);

    expect($history->count())->toBe(3);
});

it('delete removes scan file', function (): void {
    $history = new ScanHistory($this->tempDir);

    $id = $history->save(['score' => 50]);

    expect($history->delete($id))->toBeTrue()
        ->and($history->find($id))->toBeNull()
        ->and($history->count())->toBe(0);
});

it('clear removes all files', function (): void {
    $history = new ScanHistory($this->tempDir);

    $history->save(['score' => 10]);
    $history->save(['score' => 20]);
    $history->save(['score' => 30]);

    $deleted = $history->clear();

    expect($deleted)->toBe(3)
        ->and($history->count())->toBe(0);
});

it('handles missing directory gracefully', function (): void {
    $history = new ScanHistory($this->tempDir.'/nonexistent/deep');

    expect($history->all())->toBe([])
        ->and($history->latest())->toBeNull()
        ->and($history->count())->toBe(0);
});

it('handles corrupted json gracefully', function (): void {
    mkdir($this->tempDir, 0755, true);
    file_put_contents($this->tempDir.'/corrupted.json', '{not valid json!!!');

    $history = new ScanHistory($this->tempDir);

    expect($history->all())->toBe([]);
});
