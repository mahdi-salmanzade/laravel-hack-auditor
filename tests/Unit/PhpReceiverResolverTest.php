<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\Php\MethodShape;
use Mahdi\HackAuditor\Scanner\Php\PhpAstParser;
use Mahdi\HackAuditor\Scanner\Php\ReceiverResolver;
use PhpParser\Node;
use PhpParser\NodeFinder;

function resolverMethod(string $body, string $classBody = ''): MethodShape
{
    $source = <<<PHP
    <?php

    namespace App\Http\Controllers;

    use App\Models\Room;
    use App\Services\ImageUploadService;
    use GuzzleHttp\Client;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Http;

    class SubjectController
    {
    {$classBody}
        public function act(Request \$request, Room \$room, Client \$client, int \$id)
        {
    {$body}
        }
    }
    PHP;

    $method = (new PhpAstParser)->parse('SubjectController.php', $source)->primaryClass()?->method('act');

    expect($method)->not->toBeNull();

    return $method;
}

/**
 * @return array<int, Node\Expr\MethodCall|Node\Expr\StaticCall>
 */
function resolverCalls(MethodShape $method): array
{
    return (new NodeFinder)->find(
        $method->statements(),
        static fn (Node $node): bool => $node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall,
    );
}

function resolverCallNamed(MethodShape $method, string $name): Node\Expr\MethodCall|Node\Expr\StaticCall|null
{
    foreach (resolverCalls($method) as $call) {
        if ($call->name instanceof Node\Identifier && $call->name->toString() === $name) {
            return $call;
        }
    }

    return null;
}

it('resolves $this to the enclosing class', function (): void {
    $method = resolverMethod('        $this->helper();');
    $call = resolverCalls($method)[0];

    $type = (new ReceiverResolver)->resolve($call->var, $method);

    expect($type->class)->toBe('App\Http\Controllers\SubjectController')
        ->and($type->evidence)->toContain('$this');
});

it('resolves $this->property from a constructor-promoted parameter', function (): void {
    $method = resolverMethod(
        '        $this->imageUpload->delete($room->image);',
        "    public function __construct(private readonly ImageUploadService \$imageUpload) {}\n",
    );

    $call = resolverCalls($method)[0];
    $type = (new ReceiverResolver)->resolve($call->var, $method);

    expect($type->class)->toBe('App\Services\ImageUploadService')
        ->and($type->evidence)->toContain('constructor-promoted');
});

it('resolves a parameter receiver from its type hint', function (): void {
    $method = resolverMethod('        $client->get("https://example.test");');
    $call = resolverCalls($method)[0];

    $type = (new ReceiverResolver)->resolve($call->var, $method);

    expect($type->class)->toBe('GuzzleHttp\Client')
        ->and($type->evidence)->toContain('type-hinted');
});

it('resolves a static call target through the file imports', function (): void {
    $method = resolverMethod('        Room::query();');
    $call = resolverCalls($method)[0];

    expect((new ReceiverResolver)->resolve($call, $method)->class)->toBe('App\Models\Room');
});

it('walks a fluent chain back to its root and lists every method along it', function (): void {
    $method = resolverMethod('        $rows = Room::query()->where("id", $id)->lockForUpdate()->get();');
    $resolver = new ReceiverResolver;
    $outermost = resolverCalls($method)[0];

    $chain = $resolver->resolveChain($outermost, $method);

    expect($chain['chain'])->toBe(['query', 'where', 'lockForUpdate', 'get'])
        ->and($resolver->resolve($chain['root'], $method)->class)->toBe('App\Models\Room');
});

it('follows a chain that was split across statements through a local variable', function (): void {
    $method = resolverMethod(<<<'PHP'
            $query = Room::query()->where('id', $id);
            $rows = $query->lockForUpdate()->get();
    PHP);

    $resolver = new ReceiverResolver;
    $outermost = resolverCallNamed($method, 'get');

    expect($outermost)->not->toBeNull();

    $chain = $resolver->resolveChain($outermost, $method);

    expect($chain['chain'])->toBe(['query', 'where', 'lockForUpdate', 'get'])
        ->and($resolver->resolve($chain['root'], $method)->class)->toBe('App\Models\Room');
});

it('never infers a type from the return value of an instance call', function (): void {
    $method = resolverMethod(<<<'PHP'
            $user = $request->user();
            $user->touch();
    PHP);

    $resolver = new ReceiverResolver;
    $touch = resolverCallNamed($method, 'touch');

    expect($touch)->not->toBeNull();

    $type = $resolver->resolve($touch->var, $method);

    expect($type->isKnown())->toBeFalse()
        ->and($type->class)->toBeNull();
});

it('resolves a local variable from the assignment that reaches the use site', function (): void {
    $method = resolverMethod(<<<'PHP'
            $service = new ImageUploadService();
            $service->delete('a.png');
    PHP);

    $resolver = new ReceiverResolver;
    $delete = resolverCallNamed($method, 'delete');

    expect($delete)->not->toBeNull()
        ->and($resolver->resolve($delete->var, $method)->class)->toBe('App\Services\ImageUploadService');
});

it('returns unknown rather than guessing for an untyped receiver', function (): void {
    $method = resolverMethod(
        '        $this->mystery->get($id);',
        "    protected \$mystery;\n",
    );

    $call = resolverCalls($method)[0];
    $type = (new ReceiverResolver)->resolve($call->var, $method);

    expect($type->isKnown())->toBeFalse()
        ->and($type->evidence)->toContain('mystery');
});
