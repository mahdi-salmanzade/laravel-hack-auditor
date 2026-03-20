<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\FileCollector;

beforeEach(function (): void {
    $this->tempDir = sys_get_temp_dir().'/hack-auditor-test-'.uniqid();
    mkdir($this->tempDir, 0755, true);
    $this->tempDir = realpath($this->tempDir);
});

afterEach(function (): void {
    // Recursively clean up temp directory
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

it('collects PHP files from configured paths', function (): void {
    $controllerDir = $this->tempDir.'/app/Http/Controllers';
    mkdir($controllerDir, 0755, true);
    file_put_contents($controllerDir.'/TestController.php', '<?php class TestController {}');

    $this->app['config']->set('hack-auditor.scan.paths', ['app/Http/Controllers']);
    $this->app->setBasePath($this->tempDir);

    $collector = new FileCollector;
    $files = $collector->collect();

    expect($files)->toHaveCount(1)
        ->and($files->first()->getFilename())->toBe('TestController.php');
});

it('collects files from multiple configured paths', function (): void {
    $controllerDir = $this->tempDir.'/app/Http/Controllers';
    $modelDir = $this->tempDir.'/app/Models';
    mkdir($controllerDir, 0755, true);
    mkdir($modelDir, 0755, true);

    file_put_contents($controllerDir.'/UserController.php', '<?php class UserController {}');
    file_put_contents($modelDir.'/User.php', '<?php class User {}');

    $this->app['config']->set('hack-auditor.scan.paths', ['app/Http/Controllers', 'app/Models']);
    $this->app->setBasePath($this->tempDir);

    $collector = new FileCollector;
    $files = $collector->collect();

    expect($files)->toHaveCount(2);
});

it('respects exclude patterns', function (): void {
    $controllerDir = $this->tempDir.'/app/Http/Controllers';
    $vendorDir = $this->tempDir.'/app/Http/Controllers/vendor';
    mkdir($controllerDir, 0755, true);
    mkdir($vendorDir, 0755, true);

    file_put_contents($controllerDir.'/AppController.php', '<?php class AppController {}');
    file_put_contents($vendorDir.'/VendorController.php', '<?php class VendorController {}');

    $this->app['config']->set('hack-auditor.scan.paths', ['app/Http/Controllers']);
    $this->app['config']->set('hack-auditor.scan.exclude', ['*/vendor/*']);
    $this->app->setBasePath($this->tempDir);

    $collector = new FileCollector;
    $files = $collector->collect();

    $filenames = $files->map(fn (SplFileInfo $f): string => $f->getFilename())->toArray();

    expect($filenames)->toContain('AppController.php')
        ->and($filenames)->not->toContain('VendorController.php');
});

it('respects max file size limits', function (): void {
    $controllerDir = $this->tempDir.'/app/Http/Controllers';
    mkdir($controllerDir, 0755, true);

    // Create a small file (should be collected)
    file_put_contents($controllerDir.'/SmallController.php', '<?php class SmallController {}');

    // Create a file larger than 1 KB (set a small max for testing)
    $largeContent = '<?php class LargeController { '.str_repeat('// comment line ', 500).' }';
    file_put_contents($controllerDir.'/LargeController.php', $largeContent);

    $this->app['config']->set('hack-auditor.scan.paths', ['app/Http/Controllers']);
    $this->app['config']->set('hack-auditor.scan.max_file_size_kb', 1);
    $this->app->setBasePath($this->tempDir);

    $collector = new FileCollector;
    $files = $collector->collect();

    $filenames = $files->map(fn (SplFileInfo $f): string => $f->getFilename())->toArray();

    expect($filenames)->toContain('SmallController.php')
        ->and($filenames)->not->toContain('LargeController.php');
});

it('skips files matching sensitive patterns', function (): void {
    $controllerDir = $this->tempDir.'/app/Http/Controllers';
    mkdir($controllerDir, 0755, true);

    file_put_contents($controllerDir.'/AppController.php', '<?php class AppController {}');
    file_put_contents($controllerDir.'/secret.key', 'my-secret-key');
    file_put_contents($controllerDir.'/cert.pem', 'certificate-data');

    $this->app['config']->set('hack-auditor.scan.paths', ['app/Http/Controllers']);
    $this->app['config']->set('hack-auditor.scan.file_extensions', ['.php', '.key', '.pem']);
    $this->app['config']->set('hack-auditor.scan.sensitive_patterns', ['*.key', '*.pem']);
    $this->app->setBasePath($this->tempDir);

    $collector = new FileCollector;
    $files = $collector->collect();

    $filenames = $files->map(fn (SplFileInfo $f): string => $f->getFilename())->toArray();

    expect($filenames)->toContain('AppController.php')
        ->and($filenames)->not->toContain('secret.key')
        ->and($filenames)->not->toContain('cert.pem');
});

it('skips non-existing directories gracefully', function (): void {
    $this->app['config']->set('hack-auditor.scan.paths', ['nonexistent/directory']);
    $this->app->setBasePath($this->tempDir);

    $collector = new FileCollector;
    $files = $collector->collect();

    expect($files)->toBeEmpty();
});

it('returns files sorted by path', function (): void {
    $controllerDir = $this->tempDir.'/app/Http/Controllers';
    mkdir($controllerDir, 0755, true);

    file_put_contents($controllerDir.'/ZebraController.php', '<?php class ZebraController {}');
    file_put_contents($controllerDir.'/AlphaController.php', '<?php class AlphaController {}');
    file_put_contents($controllerDir.'/MiddleController.php', '<?php class MiddleController {}');

    $this->app['config']->set('hack-auditor.scan.paths', ['app/Http/Controllers']);
    $this->app->setBasePath($this->tempDir);

    $collector = new FileCollector;
    $files = $collector->collect();

    $filenames = $files->map(fn (SplFileInfo $f): string => $f->getFilename())->values()->toArray();

    expect($filenames)->toBe(['AlphaController.php', 'MiddleController.php', 'ZebraController.php']);
});

it('skips binary files', function (): void {
    $controllerDir = $this->tempDir.'/app/Http/Controllers';
    mkdir($controllerDir, 0755, true);

    file_put_contents($controllerDir.'/TextController.php', '<?php class TextController {}');
    // Create a file with null bytes to simulate a binary file
    file_put_contents($controllerDir.'/BinaryFile.php', "<?php class Bin\x00ary {}");

    $this->app['config']->set('hack-auditor.scan.paths', ['app/Http/Controllers']);
    $this->app->setBasePath($this->tempDir);

    $collector = new FileCollector;
    $files = $collector->collect();

    $filenames = $files->map(fn (SplFileInfo $f): string => $f->getFilename())->toArray();

    expect($filenames)->toContain('TextController.php')
        ->and($filenames)->not->toContain('BinaryFile.php');
});

it('skips sensitive path-based patterns like storage/logs', function (): void {
    $logsDir = $this->tempDir.'/storage/logs';
    $controllerDir = $this->tempDir.'/app/Http/Controllers';
    mkdir($logsDir, 0755, true);
    mkdir($controllerDir, 0755, true);

    file_put_contents($controllerDir.'/AppController.php', '<?php class AppController {}');
    file_put_contents($logsDir.'/laravel.php', '<?php // log file');

    $this->app['config']->set('hack-auditor.scan.paths', ['app/Http/Controllers', 'storage/logs']);
    $this->app['config']->set('hack-auditor.scan.sensitive_patterns', ['storage/logs/*']);
    $this->app->setBasePath($this->tempDir);

    $collector = new FileCollector;
    $files = $collector->collect();

    $filenames = $files->map(fn (SplFileInfo $f): string => $f->getFilename())->toArray();

    expect($filenames)->toContain('AppController.php')
        ->and($filenames)->not->toContain('laravel.php');
});
