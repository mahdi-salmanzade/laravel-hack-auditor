<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\GitDiffCollector;

beforeEach(function (): void {
    $this->tempDir = sys_get_temp_dir().'/hack-auditor-test-'.uniqid();
    mkdir($this->tempDir, 0755, true);
    $this->tempDir = realpath($this->tempDir);
    $this->originalDir = getcwd();
});

afterEach(function (): void {
    chdir($this->originalDir);

    if (is_dir($this->tempDir)) {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->tempDir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($iterator as $file) {
            if ($file->isDir()) {
                rmdir($file->getRealPath());
            } else {
                unlink($file->getRealPath());
            }
        }

        rmdir($this->tempDir);
    }
});

it('returns an array from getChangedFiles in a git repository', function (): void {
    // Initialize a temporary git repo with a commit so getChangedFiles can work
    chdir($this->tempDir);
    exec('git init 2>&1');
    exec('git config user.email "test@test.com" 2>&1');
    exec('git config user.name "Test" 2>&1');
    file_put_contents($this->tempDir.'/test.php', '<?php // initial');
    exec('git add . 2>&1');
    exec('git commit -m "initial" 2>&1');

    $collector = new GitDiffCollector;
    $files = $collector->getChangedFiles();

    expect($files)->toBeArray();
});

it('throws RuntimeException for a non-git directory', function (): void {
    chdir($this->tempDir);

    $collector = new GitDiffCollector;
    $collector->getChangedFiles();
})->throws(RuntimeException::class, 'Not a git repository');
