<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlAnalyzer;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\Php\PhpAstParser;
use Mahdi\HackAuditor\Scanner\Php\SemanticContext;

/**
 * Peak memory must be a function of how many files are OPEN at once, never of
 * how many files the application has.
 *
 * The bug these tests exist for: every ParsedFile produced by a scan was
 * retained — by SemanticContext, by the ClassIndex's ClassShapes, by the
 * per-method taint and assignment caches — so an annotated AST's ~0.2 MB
 * accumulated linearly and crossed PHP's default 128M memory_limit at around
 * 640 files. That is a FATAL: not catchable, not degradable, and every scan of
 * a real Laravel application of that size produced nothing at all.
 *
 * A test that only asserted "the analyzer finishes" would have passed on the
 * broken code at small fixture sizes and failed in production. These assert the
 * SHAPE of the memory curve instead.
 */

/**
 * A synthetic application: controllers that fetch and return records, models
 * that declare $fillable, and policies — enough structure that every detector
 * does real work rather than bailing on the first check.
 *
 * @return array<int, array{path: string, content: string, type: string}>
 */
function syntheticApplication(int $controllers): array
{
    $files = [];

    for ($i = 0; $i < $controllers; $i++) {
        $files[] = [
            'path' => "app/Models/Record{$i}.php",
            'content' => <<<PHP
            <?php

            namespace App\Models;

            use Illuminate\Database\Eloquent\Model;

            class Record{$i} extends Model
            {
                protected \$fillable = ['title', 'body', 'user_id', 'is_admin'];

                public function owner()
                {
                    return \$this->belongsTo(User::class);
                }
            }
            PHP,
            'type' => 'model',
        ];

        $files[] = [
            'path' => "app/Http/Controllers/Record{$i}Controller.php",
            'content' => <<<PHP
            <?php

            namespace App\Http\Controllers;

            use App\Models\Record{$i};
            use Illuminate\Http\Request;

            class Record{$i}Controller extends Controller
            {
                public function show(\$id)
                {
                    \$record = Record{$i}::find(\$id);

                    return response()->json(\$record);
                }

                public function store(Request \$request)
                {
                    \$record = Record{$i}::create(\$request->all());

                    return response()->json(\$record);
                }
            }
            PHP,
            'type' => 'controller',
        ];
    }

    return $files;
}

/**
 * Peak memory attributable to one analyzer run, in bytes.
 */
function peakOfAnalyzing(int $controllers): int
{
    $files = syntheticApplication($controllers);

    // The peak is process-wide and monotonic, so it has to be rebased to the
    // current allocation before each run or the first run would mask the second.
    // Measured in emalloc bytes, not real pages: real-mode figures move in 2 MB
    // arena steps, which is too coarse to see a curve at all.
    memory_reset_peak_usage();
    $baseline = memory_get_usage();

    (new AccessControlAnalyzer)->analyze($files, new AccessControlContext);

    $peak = memory_get_peak_usage() - $baseline;

    unset($files);

    return $peak;
}

it('does not grow peak memory in proportion to application size', function (): void {
    // 100 controllers is 200 files; 600 is 1200 — well past the ~640 files at
    // which the retaining implementation exhausted the default 128M limit and
    // died with a fatal that no try/catch could intercept.
    $small = peakOfAnalyzing(100);
    $large = peakOfAnalyzing(600);

    // Six times the files. Retention showed up as six times the peak; a design
    // bounded by the files open at once shows up as roughly flat, so the headroom
    // is expressed as a fixed slack rather than a multiplier — a multiplier on a
    // single-digit-megabyte baseline is all allocator noise.
    expect($large)->toBeLessThan($small + 24 * 1024 * 1024)
        ->and($large)->toBeLessThan(64 * 1024 * 1024);
})->group('memory');

it('keeps the parser cache inside its byte budget over a whole application', function (): void {
    $parser = new PhpAstParser;
    $files = syntheticApplication(400);

    foreach ($files as $file) {
        $parser->parse($file['path'], $file['content']);
    }

    // The budget is a private constant; what the test asserts is that SOME bound
    // is enforced and that it is far below what 800 retained files would cost.
    expect($parser->cachedFiles())->toBeLessThan(count($files))
        ->and($parser->cachedBytes())->toBeLessThan(48 * 1024 * 1024);
});

it('re-parses an evicted file and still reports its exact declaration lines', function (): void {
    // A bounded cache only works if a re-opened file is indistinguishable from
    // the one that was dropped. Line numbers come from AST nodes, so this is the
    // assertion that eviction cannot silently shift a finding's location.
    $context = SemanticContext::fromSourceFiles(syntheticApplication(400));

    $first = $context->classes()->find('App\Http\Controllers\Record0Controller');

    expect($first)->not->toBeNull()
        ->and($first->method('show')?->declarationLine())->toBe(10)
        ->and($first->method('store')?->declarationLine())->toBe(17)
        ->and($context->classes()->find('App\Models\Record0')?->startLine())->toBe(7);
});

it('exposes files as a stream rather than an array of retained syntax trees', function (): void {
    $context = SemanticContext::fromSourceFiles(syntheticApplication(3));

    expect($context->files())->toBeInstanceOf(Generator::class)
        ->and($context->analysable())->toBeInstanceOf(Generator::class)
        ->and($context->paths())->toHaveCount(6)
        ->and($context->fileCount())->toBe(6);
});
