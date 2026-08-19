<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\Php\PhpAstParser;

it('parses a file and exposes its namespace, imports and classes', function (): void {
    $source = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\Post;
    use GuzzleHttp\Client as HttpClient;

    class PostController
    {
        public function index(): array
        {
            return Post::all();
        }
    }
    PHP;

    $file = (new PhpAstParser)->parse('app/Http/Controllers/PostController.php', $source);

    expect($file->isAnalysable())->toBeTrue()
        ->and($file->parseError)->toBeNull()
        ->and($file->namespaceName())->toBe('App\Http\Controllers')
        ->and($file->useMap())->toBe([
            'Post' => 'App\Models\Post',
            'HttpClient' => 'GuzzleHttp\Client',
        ])
        ->and($file->classes())->toHaveCount(1)
        ->and($file->primaryClass()?->fqcn())->toBe('App\Http\Controllers\PostController');
});

it('marks a file that cannot be parsed as unanalysable and yields no nodes', function (): void {
    $parser = new PhpAstParser;
    $file = $parser->parse('broken.php', '<?php class Broken { public function ');

    expect($file->isAnalysable())->toBeFalse()
        ->and($file->parseError)->not->toBeNull()
        ->and($file->classes())->toBe([])
        ->and($file->statements())->toBe([])
        ->and($file->primaryClass())->toBeNull()
        ->and($parser->hasErrors())->toBeTrue()
        ->and(array_keys($parser->errors()))->toBe(['broken.php']);
});

it('never guesses at a truncated chunk', function (): void {
    $truncated = (new PhpAstParser)->parse(
        'chunk.php',
        "<?php\nclass Chunk\n{\n    public function store(Request \$request)\n    {\n        Room::create([\n",
    );

    expect($truncated->isAnalysable())->toBeFalse()
        ->and($truncated->classes())->toBe([]);

    // A fragment with no opening tag is valid PHP — it is all inline HTML — so
    // it parses and declares nothing. Either way there is nothing to report.
    $fragment = (new PhpAstParser)->parse('fragment.php', "public function store(Request \$request)\n{\n}");

    expect($fragment->classes())->toBe([])
        ->and($fragment->primaryClass())->toBeNull();
});

it('reuses the cached AST for identical content and reparses when it changes', function (): void {
    $parser = new PhpAstParser;
    $source = '<?php class A { public function b(): void {} }';

    $first = $parser->parse('a.php', $source);
    $second = $parser->parse('a.php', $source);
    $third = $parser->parse('a.php', $source."\n// changed");

    expect($first)->toBe($second)
        ->and($third)->not->toBe($first);
});

it('reports an unreadable file as unanalysable rather than empty', function (): void {
    $parser = new PhpAstParser;
    $file = $parser->parseFile('/definitely/not/a/real/path.php');

    expect($file->isAnalysable())->toBeFalse()
        ->and($parser->hasErrors())->toBeTrue();
});

it('resolves imported and namespaced class names on every Name node', function (): void {
    $source = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\Room;

    class RoomController
    {
        public function show(Room $room, \App\Models\User $user, Support $support): void {}
    }
    PHP;

    $file = (new PhpAstParser)->parse('RoomController.php', $source);
    $method = $file->primaryClass()?->method('show');

    expect($method)->not->toBeNull()
        ->and($method->parameter('room')?->type())->toBe('App\Models\Room')
        ->and($method->parameter('user')?->type())->toBe('App\Models\User')
        ->and($method->parameter('support')?->type())->toBe('App\Http\Controllers\Support');
});
