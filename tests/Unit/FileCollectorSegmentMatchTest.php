<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\FileCollector;

/**
 * Exclude patterns match whole path segments.
 *
 * Finder::notPath('tests') is a SUBSTRING match, so the default `*\/tests/*`
 * exclusion silently dropped ContestsController.php and LatestsController.php
 * from a security scan, and `*\/node_modules/*` dropped
 * Models/node_modules_helper.php.
 */
beforeEach(function (): void {
    $this->tempDir = sys_get_temp_dir().'/hack-auditor-segments-'.uniqid();
    mkdir($this->tempDir, 0755, true);
    $this->tempDir = realpath($this->tempDir);
    $this->app->setBasePath($this->tempDir);
});

afterEach(function (): void {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($this->tempDir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );

    foreach ($iterator as $file) {
        $file->isDir() ? rmdir($file->getRealPath()) : unlink($file->getRealPath());
    }

    rmdir($this->tempDir);
});

function segmentFixture(string $root, array $files): void
{
    foreach ($files as $file) {
        if (! is_dir(dirname($root.'/'.$file))) {
            mkdir(dirname($root.'/'.$file), 0755, true);
        }

        file_put_contents($root.'/'.$file, '<?php class X {}');
    }
}

/**
 * @return array<int, string>
 */
function segmentCollected(): array
{
    return (new FileCollector)->collect()
        ->map(fn (SplFileInfo $file): string => str_replace(DIRECTORY_SEPARATOR, '/', $file->getRelativePathname()))
        ->sort()
        ->values()
        ->all();
}

it('keeps files whose names merely contain an excluded word', function (): void {
    segmentFixture($this->tempDir, [
        'app/Http/Controllers/ContestsController.php',
        'app/Http/Controllers/LatestsController.php',
        'app/Http/Controllers/tests/Ignored.php',
        'app/Http/Controllers/Admin/vendor/Ignored.php',
        'app/Models/node_modules_helper.php',
        'app/Models/node_modules/Ignored.php',
    ]);

    $this->app['config']->set('hack-auditor.scan.paths', ['app/Http/Controllers', 'app/Models']);
    $this->app['config']->set('hack-auditor.scan.exclude', ['*/vendor/*', '*/node_modules/*', '*/tests/*']);

    expect(segmentCollected())->toBe([
        'ContestsController.php',
        'LatestsController.php',
        'node_modules_helper.php',
    ]);
});

it('supports wildcards and multi-segment excludes without substring matching', function (): void {
    segmentFixture($this->tempDir, [
        'app/Legacy/Old.php',
        'app/LegacyAdapter/Kept.php',
        'app/Views/page.blade.php',
        'app/Views/Kept.php',
    ]);

    $this->app['config']->set('hack-auditor.scan.paths', ['app']);
    $this->app['config']->set('hack-auditor.scan.exclude', ['Legacy/*', '*.blade.php']);

    expect(segmentCollected())->toBe([
        'LegacyAdapter/Kept.php',
        'Views/Kept.php',
    ]);
});

it('anchors directory-style sensitive patterns on segments too', function (): void {
    segmentFixture($this->tempDir, [
        'app/storage/logs/leak.php',
        'app/Http/Controllers/storage_logs_viewer.php',
    ]);

    $this->app['config']->set('hack-auditor.scan.paths', ['app']);
    $this->app['config']->set('hack-auditor.scan.exclude', []);
    $this->app['config']->set('hack-auditor.scan.sensitive_patterns', ['.env*', 'storage/logs/*']);

    expect(segmentCollected())->toBe(['Http/Controllers/storage_logs_viewer.php']);
});

it('refuses sensitive or out-of-tree extra context paths', function (): void {
    file_put_contents($this->tempDir.'/.env', 'DB_PASSWORD=hunter2');
    mkdir($this->tempDir.'/app/Support', 0755, true);
    file_put_contents($this->tempDir.'/app/Support/Tenancy.php', '<?php class Tenancy {}');

    $this->app['config']->set('hack-auditor.context.extra_context_paths', [
        '.env',
        '../../etc/hosts',
        'app/Support/Tenancy.php',
    ]);

    $context = (new FileCollector)->collectContextFiles();

    expect($context['extra'] ?? [])->toBe([$this->tempDir.'/app/Support/Tenancy.php']);
});
