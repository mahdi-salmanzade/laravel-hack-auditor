<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlAnalyzer;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\Php\PhpAstParser;
use Mahdi\HackAuditor\Scanner\Vulnerability;

/**
 * FALSE-POSITIVE REGRESSION CORPUS.
 *
 * tests/Fixtures/precision holds a small but REALISTIC and entirely CLEAN
 * Laravel application. Every one of these tests asserts the same thing: the
 * deterministic detectors report NOTHING for it.
 *
 * The corpus encodes the five findings a real 73-controller application
 * received, all of which were false, plus the line-attribution defect that made
 * every one of them point at the wrong place. A miss is a bug; a false positive
 * is a broken product, and shipping a "fix" that fatals when applied is worse
 * than shipping no finding at all.
 *
 * These tests are EXPECTED TO FAIL until the detectors are rebuilt on the
 * Scanner\Php semantic layer. Do not weaken them to make them pass.
 */

/**
 * The corpus root.
 */
function precisionCorpusPath(): string
{
    return dirname(__DIR__).'/Fixtures/precision';
}

/**
 * Load the corpus in the array shape the scanner passes around.
 *
 * @param  string|null  $only  Restrict to paths containing this substring
 * @return array<int, array{path: string, content: string, type: string}>
 */
function precisionCorpusFiles(?string $only = null): array
{
    $root = precisionCorpusPath();

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
    );

    $files = [];

    foreach ($iterator as $file) {
        if (! $file instanceof SplFileInfo || $file->getExtension() !== 'php') {
            continue;
        }

        $relative = str_replace($root.DIRECTORY_SEPARATOR, '', $file->getPathname());
        $relative = str_replace(DIRECTORY_SEPARATOR, '/', $relative);

        if ($only !== null && ! str_contains($relative, $only)) {
            continue;
        }

        $files[] = [
            'path' => $relative,
            'content' => (string) file_get_contents($file->getPathname()),
            'type' => precisionFileType($relative),
        ];
    }

    usort($files, static fn (array $a, array $b): int => strcmp($a['path'], $b['path']));

    return $files;
}

function precisionFileType(string $relativePath): string
{
    return match (true) {
        str_contains($relativePath, 'Http/Controllers/') => 'controller',
        str_contains($relativePath, 'Models/') => 'model',
        str_starts_with($relativePath, 'routes/') => 'route',
        default => 'other',
    };
}

/**
 * The context the scanner derives for this app: Room, Invoice and Post each
 * have a Policy class on disk, and the invoice update route carries
 * `can:update,invoice`.
 */
function precisionContext(): AccessControlContext
{
    return new AccessControlContext(
        routedMethods: [
            'App\Http\Controllers\InvoiceController@update' => [
                'route' => 'PUT /invoices/{invoice}',
                'middleware' => ['api', 'auth:sanctum', 'can:update,invoice'],
            ],
            'App\Http\Controllers\RoomController@store' => [
                'route' => 'POST /rooms',
                'middleware' => ['api', 'auth:sanctum'],
            ],
            'App\Http\Controllers\RoomController@update' => [
                'route' => 'PUT /rooms/{room}',
                'middleware' => ['api', 'auth:sanctum'],
            ],
            'App\Http\Controllers\RoomMemberController@store' => [
                'route' => 'POST /rooms/join',
                'middleware' => ['api', 'auth:sanctum'],
            ],
            'App\Http\Controllers\RoomReportController@store' => [
                'route' => 'POST /rooms/reports',
                'middleware' => ['api', 'auth:sanctum'],
            ],
            'App\Http\Controllers\BlockController@store' => [
                'route' => 'POST /blocks',
                'middleware' => ['api', 'auth:sanctum'],
            ],
            'App\Http\Controllers\ArticleController@store' => [
                'route' => 'POST /articles',
                'middleware' => ['api', 'auth:sanctum'],
            ],
        ],
        modelsWithPolicy: ['Room', 'Invoice', 'Post'],
    );
}

/**
 * Run the full deterministic pipeline over part or all of the corpus.
 *
 * @return array<int, Vulnerability>
 */
function precisionFindings(?string $only = null): array
{
    return (new AccessControlAnalyzer)->analyze(precisionCorpusFiles($only), precisionContext());
}

/**
 * Render findings so a failure message names the file, line and claim.
 *
 * @param  array<int, Vulnerability>  $findings
 * @return array<int, string>
 */
function precisionDescribe(array $findings): array
{
    return array_map(
        static fn (Vulnerability $v): string => sprintf(
            '%s:%d [%s] %s',
            $v->location,
            $v->line,
            $v->type->value,
            $v->description,
        ),
        $findings,
    );
}

it('loads a corpus that parses cleanly', function (): void {
    $files = precisionCorpusFiles();

    expect($files)->not->toBeEmpty();

    $parser = new PhpAstParser;
    $unparsable = [];

    foreach ($files as $file) {
        $parsed = $parser->parse($file['path'], $file['content']);

        if (! $parsed->isAnalysable()) {
            $unparsable[] = $file['path'].': '.$parsed->parseError;
        }
    }

    expect($unparsable)->toBe([]);
});

it('reports nothing at all for the whole clean corpus', function (): void {
    $findings = precisionFindings();

    expect(precisionDescribe($findings))->toBe([]);
});

it('does not claim an auth bypass when the Policy defines no store/create ability (FP-1)', function (): void {
    $findings = precisionFindings('RoomController.php');

    expect(precisionDescribe($findings))->toBe([]);
});

it('does not claim an auth bypass for joining a room by invite code (FP-2)', function (): void {
    $findings = precisionFindings('RoomMemberController.php');

    expect(precisionDescribe($findings))->toBe([]);
});

it('does not claim an auth bypass for reporting a room (FP-3)', function (): void {
    $findings = precisionFindings('RoomReportController.php');

    expect(precisionDescribe($findings))->toBe([]);
});

it('never advises an ability the Policy does not define', function (): void {
    $declared = [
        'view', 'viewAny', 'create', 'update', 'delete', 'manageImage',
        'managePassword', 'manageTriggers', 'manageWebhooks', 'manageMembers',
        'viewPrivateLocation',
    ];

    $invented = [];

    foreach (precisionFindings() as $finding) {
        if (preg_match_all("/authorize\(\s*'(\w+)'/", $finding->fix, $matches) === 0) {
            continue;
        }

        foreach ($matches[1] as $ability) {
            if (in_array($ability, $declared, true)) {
                continue;
            }

            $invented[] = sprintf(
                "%s:%d advises authorize('%s'), which no Policy in the corpus declares — applying it would throw",
                $finding->location,
                $finding->line,
                $ability,
            );
        }
    }

    expect($invented)->toBe([]);
});

it('does not treat a local storage service as an HTTP client (FP-4)', function (): void {
    $findings = precisionFindings('AuthController.php');

    expect(precisionDescribe($findings))->toBe([]);
});

it('does not treat an Eloquent read or a Collection lookup as an outbound request (FP-5)', function (): void {
    $findings = precisionFindings('BlockController.php');

    expect(precisionDescribe($findings))->toBe([]);
});

it('does not treat $request->user() as attacker-controlled input', function (): void {
    $offenders = [];

    foreach (precisionFindings() as $finding) {
        $claim = $finding->proof.' '.$finding->description;

        if (! str_contains($claim, '$request->user(') && ! str_contains($claim, 'auth()->user(')) {
            continue;
        }

        $offenders[] = sprintf(
            '%s:%d cites the authenticated user object as an input source',
            $finding->location,
            $finding->line,
        );
    }

    expect($offenders)->toBe([]);
});

it('reports nothing for a controller full of docblocks, closures and awkward signatures', function (): void {
    $findings = precisionFindings('MaintenanceController.php');

    expect(precisionDescribe($findings))->toBe([]);
});

it('resolves every public method to the exact line of its function keyword', function (): void {
    // The location invariant: re-reading the reported file at the reported line
    // must show the construct that was reported. Every line in a finding comes
    // from this path, so this single assertion guards all of them. The regex
    // MethodScanner this replaced invented a method from a commented-out block
    // and missed one whose parameter default contained ')'.
    $path = precisionCorpusPath().'/app/Http/Controllers/MaintenanceController.php';
    $content = (string) file_get_contents($path);

    $parsed = (new PhpAstParser)->parse($path, $content);
    $class = $parsed->primaryClass();

    expect($class)->not->toBeNull();

    $lines = explode("\n", $content);
    $misplaced = [];
    $resolved = [];

    foreach ($class->publicMethods() as $method) {
        $line = $method->declarationLine();
        $resolved[$method->name()] = $line;

        if (! str_contains($lines[$line - 1] ?? '', 'function '.$method->name())) {
            $misplaced[] = sprintf(
                'line %d was reported for %s() but reads: %s',
                $line,
                $method->name(),
                trim($lines[$line - 1] ?? '<past end of file>'),
            );
        }
    }

    expect($misplaced)->toBe([])
        ->and($resolved)->toBe(['index' => 29, 'show' => 57]);
});

it('reports nothing for ordinary clean Laravel controllers', function (): void {
    foreach (['PostController.php', 'InvoiceController.php', 'ArticleController.php'] as $controller) {
        expect(precisionDescribe(precisionFindings($controller)))->toBe([]);
    }
});

it('reports nothing for models, policies, form requests and route files', function (): void {
    foreach (['app/Models/', 'app/Policies/', 'app/Http/Requests/', 'routes/'] as $group) {
        expect(precisionDescribe(precisionFindings($group)))->toBe([]);
    }
});
