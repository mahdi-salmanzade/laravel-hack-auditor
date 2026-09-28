<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Tests\TestCase;

uses(TestCase::class)->in('Feature', 'Unit');

/**
 * Create stub files at app-relative paths, returning a cleanup closure.
 *
 * The response parser drops AI findings whose location exists nowhere in the
 * application (an invented file), so a test whose fake AI response names a
 * file must make that file exist.
 *
 * @param  array<int, string>  $relativePaths
 */
function createAppStubFiles(array $relativePaths): Closure
{
    $created = [];

    foreach ($relativePaths as $relativePath) {
        $absolute = base_path($relativePath);

        if (file_exists($absolute)) {
            continue;
        }

        if (! is_dir(dirname($absolute))) {
            mkdir(dirname($absolute), 0755, true);
        }

        file_put_contents($absolute, "<?php\n\n".str_repeat("// stub\n", 200));
        $created[] = $absolute;
    }

    return static function () use ($created): void {
        foreach ($created as $absolute) {
            @unlink($absolute);
        }
    };
}
