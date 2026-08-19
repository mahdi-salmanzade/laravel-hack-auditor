<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\Php\CallClassification;
use Mahdi\HackAuditor\Scanner\Php\MethodShape;
use Mahdi\HackAuditor\Scanner\Php\ReceiverKind;
use Mahdi\HackAuditor\Scanner\Php\SemanticContext;
use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * Build a controller plus the supporting model and service classes so the
 * class index can resolve ancestry the way a real scan does.
 */
function semanticsContext(string $body, string $classBody = ''): SemanticContext
{
    $controller = <<<PHP
    <?php

    namespace App\Http\Controllers;

    use App\Models\User;
    use App\Services\ImageUploadService;
    use GuzzleHttp\Client;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\DB;
    use Illuminate\Support\Facades\Http;
    use Illuminate\Support\Facades\Storage;

    class SubjectController
    {
    {$classBody}
        public function act(Request \$request, User \$user, Client \$client, int \$id)
        {
    {$body}
        }
    }
    PHP;

    return SemanticContext::fromSourceFiles([
        ['path' => 'app/Http/Controllers/SubjectController.php', 'content' => $controller, 'type' => 'controller'],
        [
            'path' => 'app/Models/User.php',
            'content' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Foundation\\Auth\\User as Authenticatable;\nclass User extends Authenticatable {}\n",
            'type' => 'model',
        ],
        [
            'path' => 'app/Services/ImageUploadService.php',
            'content' => "<?php\nnamespace App\\Services;\nclass ImageUploadService { public function delete(?string \$p): void {} }\n",
            'type' => 'other',
        ],
    ]);
}

function semanticsMethod(SemanticContext $context): MethodShape
{
    $method = $context->classes()->find('App\Http\Controllers\SubjectController')?->method('act');

    expect($method)->not->toBeNull();

    return $method;
}

function semanticsCall(SemanticContext $context, string $name): CallClassification
{
    $method = semanticsMethod($context);

    $calls = (new NodeFinder)->find(
        $method->statements(),
        static fn (Node $node): bool => ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall)
            && $node->name instanceof Node\Identifier
            && $node->name->toString() === $name,
    );

    expect($calls)->not->toBeEmpty();

    return $context->semantics()->classifyCall($calls[0], $method);
}

function semanticsTrust(SemanticContext $context, string $variable): string
{
    $method = semanticsMethod($context);
    $state = $context->taint()->track($method);

    return $state->at($variable)?->trust->value ?? 'missing';
}

it('classifies the Http facade and a Guzzle client as outbound HTTP', function (): void {
    expect(semanticsCall(semanticsContext('        Http::get($request->input("url"));'), 'get')->kind)
        ->toBe(ReceiverKind::HttpClient)
        ->and(semanticsCall(semanticsContext('        Http::withToken("x")->post($request->input("url"));'), 'post')->kind)
        ->toBe(ReceiverKind::HttpClient)
        ->and(semanticsCall(semanticsContext('        $client->delete($request->input("url"));'), 'delete')->kind)
        ->toBe(ReceiverKind::HttpClient);
});

it('classifies an Eloquent read as the database even when the verb is get or delete', function (): void {
    $get = semanticsCall(semanticsContext('        $rows = User::query()->whereIn("id", [$id])->lockForUpdate()->get();'), 'get');
    $delete = semanticsCall(semanticsContext('        User::where("id", $id)->delete();'), 'delete');

    expect($get->kind)->toBe(ReceiverKind::Eloquent)
        ->and($get->isOutboundHttp())->toBeFalse()
        ->and($get->chain)->toBe(['query', 'whereIn', 'lockForUpdate', 'get'])
        ->and($delete->kind)->toBe(ReceiverKind::Eloquent);
});

it('classifies a query builder chain as the database from the chain alone', function (): void {
    // The receiver class is outside App\Models and absent from the scan, so the
    // only evidence available is the shape of the chain itself.
    $context = semanticsContext('        $rows = \App\Domain\Legacy::query()->whereIn("id", [$id])->lockForUpdate()->get();');
    $call = semanticsCall($context, 'get');

    expect($call->kind)->toBe(ReceiverKind::Eloquent)
        ->and($call->evidence)->toContain('query builder');
});

it('trusts a resolvable model type over the shape of the chain', function (): void {
    $context = semanticsContext('        $rows = User::query()->get();');

    expect(semanticsCall($context, 'get')->evidence)->toContain('App\Models\User');
});

it('classifies a local injected service as a local service, never as an HTTP client', function (): void {
    $context = semanticsContext(
        '        $this->imageUpload->delete($user->profile_image);',
        "    public function __construct(private readonly ImageUploadService \$imageUpload) {}\n",
    );

    $call = semanticsCall($context, 'delete');

    expect($call->kind)->toBe(ReceiverKind::LocalService)
        ->and($call->isOutboundHttp())->toBeFalse()
        ->and($call->receiver->class)->toBe('App\Services\ImageUploadService');
});

it('classifies a Collection lookup and a Storage call as neither HTTP nor database', function (): void {
    expect(semanticsCall(semanticsContext('        collect([1])->get($id);'), 'get')->kind)
        ->toBe(ReceiverKind::Collection)
        ->and(semanticsCall(semanticsContext('        Storage::disk("public")->delete($user->profile_image);'), 'delete')->kind)
        ->toBe(ReceiverKind::Storage);
});

it('classifies a request accessor as the request, not as a query builder', function (): void {
    expect(semanticsCall(semanticsContext('        $x = $request->query("endpoint");'), 'query')->kind)
        ->toBe(ReceiverKind::Request);
});

it('refuses to classify an untyped receiver', function (): void {
    $context = semanticsContext(
        '        $this->mystery->get($request->input("url"));',
        "    protected \$mystery;\n",
    );

    $call = semanticsCall($context, 'get');

    expect($call->kind)->toBe(ReceiverKind::Unknown)
        ->and($call->isUnknown())->toBeTrue();
});

it('treats request input as attacker controlled', function (): void {
    foreach ([
        '$request->input("url")',
        '$request->query("url")',
        '$request->all()',
        '$request->json("url")',
        '$request->post("url")',
        '$request->get("url")',
        '$request->route("id")',
        '$request->url',
        'request("url")',
        '$_GET["url"]',
        '$request->validated("url")',
    ] as $expression) {
        $context = semanticsContext(sprintf('        $value = %s;', $expression));

        expect(semanticsTrust($context, 'value'))->toBe('tainted', $expression);
    }
});

it('never treats the authenticated user or server-side state as attacker controlled', function (): void {
    foreach ([
        '$request->user()',
        'auth()->user()',
        '\Illuminate\Support\Facades\Auth::user()',
        '$request->ip()',
        'config("services.partner.url")',
        'route("rooms.show", 1)',
        'url("/health")',
        '$request->isMethod("post")',
    ] as $expression) {
        $context = semanticsContext(sprintf('        $value = %s;', $expression));

        expect(semanticsTrust($context, 'value'))->toBe('trusted', $expression);
    }
});

it('treats an attribute read from the authenticated user as trusted, not as input', function (): void {
    $context = semanticsContext(<<<'PHP'
            $owner = $request->user();
            $path = $owner->profile_image;
    PHP);

    expect(semanticsTrust($context, 'owner'))->toBe('trusted')
        ->and(semanticsTrust($context, 'path'))->toBe('trusted');
});

it('marks a route-model-bound parameter trusted and a bare scalar route parameter tainted', function (): void {
    $method = semanticsMethod(semanticsContext('        $noop = 1;'));
    $semantics = semanticsContext('        $noop = 1;')->semantics();

    expect($semantics->judgeParameter($method->parameter('user'), $method)->isTrusted())->toBeTrue()
        ->and($semantics->judgeParameter($method->parameter('request'), $method)->isTrusted())->toBeTrue()
        ->and($semantics->judgeParameter($method->parameter('id'), $method)->isTainted())->toBeTrue();
});

it('returns unknown rather than tainted for a value it cannot explain', function (): void {
    $context = semanticsContext('        $value = $this->somethingUnmodelled();');

    expect(semanticsTrust($context, 'value'))->toBe('unknown');
});
