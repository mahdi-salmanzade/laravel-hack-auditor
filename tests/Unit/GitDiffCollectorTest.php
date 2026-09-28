<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\GitDiffCollector;

beforeEach(function (): void {
    $this->tempDir = sys_get_temp_dir().'/hack-auditor-test-'.uniqid();
    mkdir($this->tempDir, 0755, true);
    $this->tempDir = realpath($this->tempDir);
    $this->originalBasePath = $this->app->basePath();
});

afterEach(function (): void {
    $this->app->setBasePath($this->originalBasePath);

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

/**
 * Run a git command inside the given directory, failing the test on error.
 */
function gitIn(string $directory, string $arguments): void
{
    exec('git -C '.escapeshellarg($directory).' '.$arguments.' 2>&1', $output, $exitCode);

    if ($exitCode !== 0) {
        throw new RuntimeException("git {$arguments} failed: ".implode("\n", $output));
    }
}

/**
 * Write a file, creating its directory.
 */
function writeFileIn(string $path, string $contents): void
{
    if (! is_dir(dirname($path))) {
        mkdir(dirname($path), 0755, true);
    }

    file_put_contents($path, $contents);
}

/**
 * Initialise a repository on `main` with one commit, then check out a feature branch.
 */
function initRepoWithFeatureBranch(string $directory): void
{
    gitIn($directory, 'init -q -b main');
    gitIn($directory, 'config user.email test@test.com');
    gitIn($directory, 'config user.name Test');
    gitIn($directory, 'config commit.gpgsign false');
    writeFileIn($directory.'/README.md', 'base');
    gitIn($directory, 'add .');
    gitIn($directory, 'commit -q -m initial');
    gitIn($directory, 'checkout -q -b feature');
}

it('returns changed php files within the scan paths', function (): void {
    initRepoWithFeatureBranch($this->tempDir);
    writeFileIn($this->tempDir.'/app/Http/Controllers/InvoiceController.php', '<?php // changed');
    writeFileIn($this->tempDir.'/database/seeders/Seeder.php', '<?php // out of scope');
    gitIn($this->tempDir, 'add .');
    gitIn($this->tempDir, 'commit -q -m change');

    $this->app->setBasePath($this->tempDir);

    $collector = new GitDiffCollector;

    expect($collector->getChangedFiles('main'))
        ->toBe([$this->tempDir.'/app/Http/Controllers/InvoiceController.php'])
        ->and($collector->resolvedBase())->toBe('main');
});

it('finds changes when the laravel app lives in a subdirectory of the repository', function (): void {
    // git reports repo-root paths (backend/app/...), which used to fail every
    // scan-path match and report a monorepo PR as "no changed files".
    initRepoWithFeatureBranch($this->tempDir);
    writeFileIn($this->tempDir.'/backend/app/Http/Controllers/AController.php', '<?php // changed');
    writeFileIn($this->tempDir.'/frontend/app/Http/Controllers/Other.php', '<?php // other app');
    gitIn($this->tempDir, 'add .');
    gitIn($this->tempDir, 'commit -q -m change');

    $this->app->setBasePath($this->tempDir.'/backend');

    expect((new GitDiffCollector)->getChangedFiles('main'))
        ->toBe([$this->tempDir.'/backend/app/Http/Controllers/AController.php']);
});

it('narrows the diff to a --path restriction', function (): void {
    initRepoWithFeatureBranch($this->tempDir);
    writeFileIn($this->tempDir.'/app/Http/Controllers/Api/UserController.php', '<?php');
    writeFileIn($this->tempDir.'/app/Models/User.php', '<?php');
    gitIn($this->tempDir, 'add .');
    gitIn($this->tempDir, 'commit -q -m change');

    $this->app->setBasePath($this->tempDir);

    $collector = new GitDiffCollector;

    expect($collector->getChangedFiles('main', 'app/Http/Controllers'))
        ->toBe([$this->tempDir.'/app/Http/Controllers/Api/UserController.php'])
        ->and($collector->getChangedFiles('main', './app/Models/'))
        ->toBe([$this->tempDir.'/app/Models/User.php']);
});

it('throws instead of reporting no changes when the base cannot be resolved', function (): void {
    // A shallow CI checkout has no base ref. This used to return [] and post a
    // green "no changed files" on a PR nobody looked at.
    initRepoWithFeatureBranch($this->tempDir);
    $this->app->setBasePath($this->tempDir);

    (new GitDiffCollector)->getChangedFiles('release');
})->throws(RuntimeException::class, 'fetch-depth: 0');

it('never silently diffs against a different branch than the one requested', function (): void {
    // `--base=develop` used to fall back to main when develop was missing,
    // and report that comparison as if it were the one asked for.
    initRepoWithFeatureBranch($this->tempDir);
    writeFileIn($this->tempDir.'/app/Models/User.php', '<?php');
    gitIn($this->tempDir, 'add .');
    gitIn($this->tempDir, 'commit -q -m change');
    $this->app->setBasePath($this->tempDir);

    expect(fn () => (new GitDiffCollector)->getChangedFiles('develop'))
        ->toThrow(RuntimeException::class, 'develop');
});

it('auto-detects master when main does not exist', function (): void {
    gitIn($this->tempDir, 'init -q -b master');
    gitIn($this->tempDir, 'config user.email test@test.com');
    gitIn($this->tempDir, 'config user.name Test');
    gitIn($this->tempDir, 'config commit.gpgsign false');
    writeFileIn($this->tempDir.'/README.md', 'base');
    gitIn($this->tempDir, 'add .');
    gitIn($this->tempDir, 'commit -q -m initial');
    gitIn($this->tempDir, 'checkout -q -b feature');
    writeFileIn($this->tempDir.'/routes/web.php', '<?php');
    gitIn($this->tempDir, 'add .');
    gitIn($this->tempDir, 'commit -q -m change');
    $this->app->setBasePath($this->tempDir);

    $collector = new GitDiffCollector;

    expect($collector->getChangedFiles())->toBe([$this->tempDir.'/routes/web.php'])
        ->and($collector->resolvedBase())->toBe('master');
});

it('throws RuntimeException for a non-git directory', function (): void {
    $this->app->setBasePath($this->tempDir);

    (new GitDiffCollector)->getChangedFiles();
})->throws(RuntimeException::class, 'Not a git repository');
