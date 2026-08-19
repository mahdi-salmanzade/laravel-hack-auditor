<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\Php\SemanticContext;

function semanticContextOverPrecisionCorpus(): SemanticContext
{
    $root = dirname(__DIR__).'/Fixtures/precision';

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
    );

    $files = [];

    foreach ($iterator as $file) {
        if (! $file instanceof SplFileInfo || $file->getExtension() !== 'php') {
            continue;
        }

        $files[] = [
            'path' => str_replace($root.'/', '', $file->getPathname()),
            'content' => (string) file_get_contents($file->getPathname()),
            'type' => 'other',
        ];
    }

    return SemanticContext::fromSourceFiles($files);
}

it('assembles a class index, a policy index and taint tracking for a whole scan', function (): void {
    $context = semanticContextOverPrecisionCorpus();

    expect($context->unanalysable())->toBe([])
        ->and($context->classes()->find('App\Models\Room'))->not->toBeNull()
        ->and($context->policies()->hasPolicyFor('Room'))->toBeTrue()
        ->and($context->policies()->hasAbility('Room', 'store'))->toBeFalse();
});

it('recognises every controller in the corpus without reading a path', function (): void {
    $names = array_map(
        static fn ($class): string => $class->shortName(),
        semanticContextOverPrecisionCorpus()->controllers(),
    );

    sort($names);

    expect($names)->toBe([
        'ArticleController',
        'AuthController',
        'BlockController',
        'InvoiceController',
        'MaintenanceController',
        'PostController',
        'RoomController',
        'RoomMemberController',
        'RoomReportController',
    ]);
});

it('knows App\Models classes are Eloquent and App\Services classes are not', function (): void {
    $semantics = semanticContextOverPrecisionCorpus()->semantics();

    expect($semantics->isEloquentClass('App\Models\Room'))->toBeTrue()
        ->and($semantics->isEloquentClass('App\Models\User'))->toBeTrue()
        ->and($semantics->isEloquentClass('App\Services\ImageUploadService'))->toBeFalse()
        ->and($semantics->isRequestClass('App\Http\Requests\StoreRoomRequest'))->toBeTrue();
});

it('excludes an unanalysable file from every accessor and names it in the report', function (): void {
    $context = SemanticContext::fromSourceFiles([
        ['path' => 'good.php', 'content' => '<?php class Good { public function go(): void {} }', 'type' => 'other'],
        ['path' => 'bad.php', 'content' => '<?php class Bad { public function ', 'type' => 'other'],
    ]);

    expect($context->paths())->toHaveCount(2)
        ->and(iterator_to_array($context->files()))->toHaveCount(2)
        ->and(iterator_to_array($context->analysable()))->toHaveCount(1)
        ->and(array_keys($context->unanalysable()))->toBe(['bad.php'])
        ->and($context->classes()->find('Bad'))->toBeNull()
        ->and($context->classes()->find('Good'))->not->toBeNull();
});
