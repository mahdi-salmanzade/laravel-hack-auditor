<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\AccessControl\SourceFile;
use Mahdi\HackAuditor\Scanner\AccessControl\SsrfDetector;
use Mahdi\HackAuditor\Scanner\Php\SemanticContext;
use Mahdi\HackAuditor\Scanner\Php\TaintJudgement;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;

/**
 * TEXT-LEVEL CORRECTNESS.
 *
 * A finding may never name an identifier that was not resolved from the file
 * being analysed, and it may never assert a reach the evidence cannot support.
 * Both defects shipped: a proof cited `$request->callback_url` inside a method
 * whose only parameter was `PurchaseRequest $purchaseRequest`, and
 * `config('services.crm.base_url').'/v3/contacts/'.$id` was reported as a
 * client-steerable destination pointed at 169.254.169.254.
 */

/**
 * Build a controller around one method body and return the analysed context.
 */
function fidelityContext(string $body, string $signature = 'Request $request, int $id', string $classBody = ''): SemanticContext
{
    $controller = <<<PHP
    <?php

    namespace App\Http\Controllers;

    use App\Http\Requests\PurchaseRequest;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Http;

    class ProbeController
    {
    {$classBody}
        public function act({$signature})
        {
    {$body}
        }
    }
    PHP;

    return SemanticContext::fromSourceFiles([
        ['path' => 'app/Http/Controllers/ProbeController.php', 'content' => $controller, 'type' => 'controller'],
    ]);
}

/**
 * The verdict recorded for one local variable of that method.
 */
function fidelityJudgement(string $body, string $variable = 'value', string $signature = 'Request $request, int $id', string $classBody = ''): TaintJudgement
{
    $context = fidelityContext($body, $signature, $classBody);
    $method = $context->classes()->find('App\Http\Controllers\ProbeController')?->method('act');

    expect($method)->not->toBeNull();

    $judgement = $context->taint()->track($method)->at($variable);

    expect($judgement)->not->toBeNull();

    return $judgement;
}

// ---------------------------------------------------------------------------
// D-3 — the receiver is quoted as the file writes it
// ---------------------------------------------------------------------------

it('names the real request variable, not a hardcoded $request, when a property is read', function (): void {
    $judgement = fidelityJudgement(
        '        $value = $purchaseRequest->callback_url;',
        signature: 'PurchaseRequest $purchaseRequest',
    );

    expect($judgement->isTainted())->toBeTrue()
        ->and($judgement->source)->toBe('$purchaseRequest->callback_url')
        ->and($judgement->evidence)->toContain('$purchaseRequest->callback_url')
        ->and($judgement->evidence)->not->toContain('$request->')
        ->and($judgement->source)->not->toContain('$request->');
});

it('quotes a request held on a property, not a $request that is not in scope', function (): void {
    $judgement = fidelityJudgement(
        '        $value = $this->httpRequest->callback_url;',
        signature: 'int $id',
        classBody: "    public function __construct(private readonly Request \$httpRequest) {}\n",
    );

    expect($judgement->source)->toBe('$this->httpRequest->callback_url')
        ->and($judgement->evidence)->not->toContain('$request->');
});

it('quotes the Request facade as written instead of inventing a $request variable', function (): void {
    $judgement = fidelityJudgement(
        '        $value = \Illuminate\Support\Facades\Request::input("url");',
        signature: 'int $id',
    );

    expect($judgement->isTainted())->toBeTrue()
        ->and($judgement->source)->toBe('Request::input()')
        ->and($judgement->evidence)->toContain('Request::input()')
        ->and($judgement->evidence)->not->toContain('$request->');
});

it('preserves the spelling of an accessor instead of printing a lower-cased name that does not exist', function (): void {
    $judgement = fidelityJudgement('        $value = $request->getContent();');

    expect($judgement->evidence)->toContain('$request->getContent()')
        ->and($judgement->evidence)->not->toContain('getcontent');
});

it('quotes the auth factory as written rather than assuming the auth() helper', function (): void {
    $judgement = fidelityJudgement(
        '        $value = $this->guard->user();',
        signature: 'int $id',
        classBody: "    public function __construct(private readonly \Illuminate\Contracts\Auth\Factory \$guard) {}\n",
    );

    expect($judgement->isTrusted())->toBeTrue()
        ->and($judgement->evidence)->toContain('$this->guard->user()')
        ->and($judgement->evidence)->not->toContain('auth()');
});

it('renders the config key that was actually read', function (): void {
    $context = fidelityContext('        $value = 1;');
    $semantics = $context->semantics();
    $method = $context->classes()->find('App\Http\Controllers\ProbeController')?->method('act');

    $expression = new FuncCall(
        new Name('config'),
        [new Arg(new String_('services.crm.base_url'))],
    );

    expect($semantics->sourceText($expression))->toBe("config('services.crm.base_url')")
        ->and($semantics->judge($expression, $method)->evidence)->toContain('config()');
});

// ---------------------------------------------------------------------------
// SSRF — a path segment cannot move the authority of a URL
// ---------------------------------------------------------------------------

it('confines taint to the path when a config base URL fixes the scheme and host', function (): void {
    $judgement = fidelityJudgement('        $value = config("services.crm.base_url")."/v3/contacts/".$id;');

    expect($judgement->carriesTaint())->toBeTrue()
        ->and($judgement->isPathOnly())->toBeTrue()
        ->and($judgement->reach)->toBe(TaintJudgement::REACH_PATH)
        ->and($judgement->isTainted())->toBeFalse()
        ->and($judgement->evidence)->toContain("config('services.crm.base_url')")
        ->and($judgement->evidence)->toContain('fixes the scheme, host and port');
});

it('confines taint to the path when a literal origin carries the scheme', function (): void {
    $judgement = fidelityJudgement('        $value = "https://api.example.com/v3/contacts/".$id;');

    expect($judgement->isPathOnly())->toBeTrue()
        ->and($judgement->isTainted())->toBeFalse();
});

it('confines taint to the query string of a fixed origin', function (): void {
    $judgement = fidelityJudgement('        $value = config("services.crm.endpoint")."?contact=".$request->input("contact");');

    expect($judgement->isPathOnly())->toBeTrue()
        ->and($judgement->isTainted())->toBeFalse();
});

it('confines taint inside an interpolated string with a fixed origin', function (): void {
    $judgement = fidelityJudgement(<<<'PHP'
            $base = config("services.crm.base_url");
            $value = "{$base}/v3/contacts/{$id}";
    PHP);

    expect($judgement->isPathOnly())->toBeTrue()
        ->and($judgement->isTainted())->toBeFalse();
});

it('keeps full taint when the client supplies the whole destination', function (): void {
    $judgement = fidelityJudgement('        $value = $request->input("url");');

    expect($judgement->isTainted())->toBeTrue()
        ->and($judgement->reach)->toBe(TaintJudgement::REACH_FULL);
});

it('keeps full taint when the leading segment is not proven server controlled', function (): void {
    $judgement = fidelityJudgement(
        '        $value = $base.$request->input("path");',
        signature: 'Request $request, string $base',
    );

    expect($judgement->isTainted())->toBeTrue()
        ->and($judgement->isPathOnly())->toBeFalse();
});

it('keeps full taint when the leading segment is unresolved', function (): void {
    $judgement = fidelityJudgement(<<<'PHP'
            $base = $this->somethingUnmodelled();
            $value = $base."/v3/".$request->input("path");
    PHP);

    expect($judgement->isTainted())->toBeTrue()
        ->and($judgement->isPathOnly())->toBeFalse();
});

it('keeps full taint when nothing closes the authority before the tainted segment', function (): void {
    // config('...base_url').$request->input('path') can still produce
    // https://api.crm.evil.com/ — the client extends the HOST, not the path.
    $judgement = fidelityJudgement('        $value = config("services.crm.base_url").$request->input("path");');

    expect($judgement->isTainted())->toBeTrue()
        ->and($judgement->isPathOnly())->toBeFalse();
});

it('keeps full taint when the server segment supplies only the scheme', function (): void {
    // '//' contains a slash, but it OPENS the authority instead of closing it:
    // the client is choosing the host here, and that is real SSRF.
    $judgement = fidelityJudgement(<<<'PHP'
            $scheme = config("app.scheme");
            $value = $scheme."//".$request->input("host");
    PHP);

    expect($judgement->isTainted())->toBeTrue()
        ->and($judgement->isPathOnly())->toBeFalse();
});

it('follows one variable hop to recognise a configured base URL', function (): void {
    $judgement = fidelityJudgement(<<<'PHP'
            $base = config("services.crm.base_url");
            $value = $base."/v3/contacts/".$id;
    PHP);

    expect($judgement->isPathOnly())->toBeTrue()
        ->and($judgement->isTainted())->toBeFalse();
});

it('keeps full taint when the client supplies the leading segment', function (): void {
    $judgement = fidelityJudgement('        $value = $request->input("url")."/v3/contacts";');

    expect($judgement->isTainted())->toBeTrue()
        ->and($judgement->isPathOnly())->toBeFalse();
});

it('keeps full taint for a concatenation that is not a URL at all', function (): void {
    $judgement = fidelityJudgement('        $value = "user-".$id;');

    expect($judgement->isTainted())->toBeTrue()
        ->and($judgement->isPathOnly())->toBeFalse();
});

it('confines every tainted segment that follows the closed authority', function (): void {
    // Two tainted segments, both after the "/" — neither can move the host.
    $judgement = fidelityJudgement('        $value = config("services.crm.base_url")."/v3/".$id."/".$request->input("filter");');

    expect($judgement->isPathOnly())->toBeTrue()
        ->and($judgement->isTainted())->toBeFalse();
});

it('lets the widest reach win when two independent branches are combined', function (): void {
    $full = TaintJudgement::tainted('the client chose the whole URL', '$request->input()');
    $path = TaintJudgement::tainted('a path segment', '$id', false, TaintJudgement::REACH_PATH);

    expect(TaintJudgement::combine([$path, $full], 'ternary')->isTainted())->toBeTrue()
        ->and(TaintJudgement::combine([$full, $path], 'ternary')->isTainted())->toBeTrue()
        ->and(TaintJudgement::combine([$path, TaintJudgement::trusted('literal')], 'ternary')->isPathOnly())->toBeTrue();
});

it('never manufactures a taint when narrowing a verdict that has none', function (): void {
    $trusted = TaintJudgement::trusted('config() returns server-side state, not client input');
    $unknown = TaintJudgement::unknown();

    expect($trusted->confinedToPath('anything')->isTrusted())->toBeTrue()
        ->and($trusted->confinedToPath('anything')->carriesTaint())->toBeFalse()
        ->and($unknown->confinedToPath('anything')->isUnknown())->toBeTrue();
});

it('propagates a path-confined verdict through a later concatenation', function (): void {
    $judgement = fidelityJudgement(<<<'PHP'
            $url = config("services.crm.base_url")."/v3/contacts/".$id;
            $value = $url."?include=notes";
    PHP);

    expect($judgement->isPathOnly())->toBeTrue()
        ->and($judgement->isTainted())->toBeFalse();
});

// ---------------------------------------------------------------------------
// End to end: the detector cannot print either defect
// ---------------------------------------------------------------------------

it('never asserts SSRF for a path appended to a server-configured base URL', function (): void {
    $files = [
        new SourceFile(
            'app/Http/Controllers/ContactController.php',
            <<<'PHP'
            <?php

            namespace App\Http\Controllers;

            use Illuminate\Support\Facades\Http;

            class ContactController
            {
                public function show(int $id)
                {
                    return Http::withToken(config('services.crm.token'))
                        ->get(config('services.crm.base_url').'/v3/contacts/'.$id);
                }
            }
            PHP,
            'controller',
        ),
    ];

    expect((new SsrfDetector)->detect($files, new AccessControlContext))->toBe([]);
});

it('still reports SSRF when the client chooses the whole destination, naming the real variable', function (): void {
    $files = [
        new SourceFile(
            'app/Http/Controllers/PurchaseController.php',
            <<<'PHP'
            <?php

            namespace App\Http\Controllers;

            use App\Http\Requests\PurchaseRequest;
            use Illuminate\Support\Facades\Http;

            class PurchaseController
            {
                public function notify(PurchaseRequest $purchaseRequest)
                {
                    return Http::post($purchaseRequest->callback_url, ['ok' => true]);
                }
            }
            PHP,
            'controller',
        ),
    ];

    $findings = (new SsrfDetector)->detect($files, new AccessControlContext);

    expect($findings)->toHaveCount(1);

    $text = $findings[0]->description.$findings[0]->proof.$findings[0]->fix.(string) $findings[0]->taintTrace;

    expect($text)->toContain('$purchaseRequest->callback_url')
        ->and($text)->not->toContain('$request->');
});
