<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\AccessControl\SourceFile;
use Mahdi\HackAuditor\Scanner\AccessControl\UnauthorizedModelFetchDetector;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\Confidence;
use Mahdi\HackAuditor\Support\FindingClass;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * Two coverage extensions to UnauthorizedModelFetchDetector, each held to the
 * detector's existing evidence chain:
 *
 *  - WRITE-SIDE IDOR: `Invoice::findOrFail($id)->update(...)`, `->delete()`, and
 *    `Invoice::destroy($id)` with a client-keyed id and no guard follow exactly
 *    the proven/review rules of the fetch-and-return path.
 *  - ROUTE-MODEL BINDING: `show(Invoice $invoice) { return $invoice; }` on a
 *    confirmed, plumbing-only route is only ever a REVIEW question — never a
 *    vulnerability, never a fix.
 *
 * Every "silent" case below changes exactly one link from the flagged fixture.
 */

/**
 * @param  array<int, array{path: string, content: string, type: string}>  $files
 * @return array<int, Vulnerability>
 */
function writeBindingScan(array $files, AccessControlContext $context): array
{
    $sources = array_map(fn (array $f): SourceFile => SourceFile::fromArray($f), $files);

    return (new UnauthorizedModelFetchDetector)->detect($sources, $context);
}

/**
 * @return array<int, array{path: string, content: string, type: string}>
 */
function writeBindingFiles(string $members, string $model = '', string $imports = '', string $extraFile = ''): array
{
    $files = [
        [
            'path' => 'app/Http/Controllers/InvoiceController.php',
            'type' => 'controller',
            'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Invoice;\nuse Illuminate\\Http\\Request;\nuse Illuminate\\Support\\Facades\\Gate;\n{$imports}\nclass InvoiceController\n{\n{$members}\n}\n",
        ],
        [
            'path' => 'app/Models/Invoice.php',
            'type' => 'model',
            'content' => "<?php\n\nnamespace App\\Models;\n\nuse Illuminate\\Database\\Eloquent\\Model;\n\nclass Invoice extends Model\n{\n    protected \$fillable = ['reference', 'user_id'];\n{$model}\n}\n",
        ],
    ];

    if ($extraFile !== '') {
        $files[] = ['path' => 'app/Http/Requests/ShowInvoiceRequest.php', 'type' => 'request', 'content' => $extraFile];
    }

    return $files;
}

/**
 * @param  array<int, string>  $middleware
 */
function writeBindingRoutes(string $method, string $route, array $middleware = ['web', 'auth']): AccessControlContext
{
    return new AccessControlContext(routedMethods: [
        'App\Http\Controllers\InvoiceController@'.$method => ['route' => $route, 'middleware' => $middleware],
    ]);
}

/**
 * @param  array<int, Vulnerability>  $findings
 * @return array<int, string>
 */
function writeBindingDescribe(array $findings): array
{
    return array_map(static fn (Vulnerability $v): string => sprintf('%d [%s] %s', $v->line, $v->type->value, $v->description), $findings);
}

// ---------------------------------------------------------------------------
// Write-side IDOR
// ---------------------------------------------------------------------------

it('reports a client-keyed findOrFail()->update() as a proven IDOR', function (): void {
    $files = writeBindingFiles(<<<'PHP'
        public function update(Request $request, int $id)
        {
            Invoice::findOrFail($id)->update($request->validated());

            return response()->noContent();
        }
    PHP);

    $findings = writeBindingScan($files, writeBindingRoutes('update', 'PUT invoices/{id}'));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::Idor)
        ->and($findings[0]->findingClass)->toBe(FindingClass::Vulnerability)
        ->and($findings[0]->confidence)->toBe(Confidence::Proven)
        ->and($findings[0]->line)->toBe(11)
        ->and($findings[0]->description)->toContain('updates it')
        ->and($findings[0]->fix)->toStartWith('Establish ownership')->not->toContain("authorize('");
});

it('reports a fetched-then-deleted record and Model::destroy($id)', function (string $body): void {
    $files = writeBindingFiles($body);

    $findings = writeBindingScan($files, writeBindingRoutes('destroy', 'DELETE invoices/{id}'));

    expect(writeBindingDescribe($findings))->toHaveCount(1)
        ->and($findings[0]->findingClass)->toBe(FindingClass::Vulnerability)
        ->and($findings[0]->description)->toContain('deletes it');
})->with([
    'variable then delete' => [<<<'PHP'
        public function destroy(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            $invoice->delete();

            return response()->noContent();
        }
    PHP],
    'destroy' => [<<<'PHP'
        public function destroy(int $id)
        {
            Invoice::destroy($id);

            return response()->noContent();
        }
    PHP],
]);

it('raises a write only for review when no route table is known', function (): void {
    $files = writeBindingFiles(<<<'PHP'
        public function update(Request $request)
        {
            Invoice::findOrFail($request->input('invoice_id'))->update(['paid' => true]);
        }
    PHP);

    $findings = writeBindingScan($files, new AccessControlContext);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->findingClass)->toBe(FindingClass::Review)
        ->and($findings[0]->fix)->toBe('');
});

it('stays silent on a guarded or scoped write', function (string $body, string $middleware): void {
    $files = writeBindingFiles($body);

    expect(writeBindingDescribe(writeBindingScan($files, writeBindingRoutes('update', 'PUT invoices/{id}', explode(',', $middleware)))))->toBe([]);
})->with([
    'authorize()' => [<<<'PHP'
        public function update(Request $request, int $id)
        {
            $invoice = Invoice::findOrFail($id);
            $this->authorize('update', $invoice);
            $invoice->update($request->validated());
        }
    PHP, 'web,auth'],
    'Gate::authorize' => [<<<'PHP'
        public function update(Request $request, int $id)
        {
            $invoice = Invoice::findOrFail($id);
            Gate::authorize('update', $invoice);
            $invoice->update($request->validated());
        }
    PHP, 'web,auth'],
    'ownership comparison' => [<<<'PHP'
        public function update(Request $request, int $id)
        {
            $invoice = Invoice::findOrFail($id);
            abort_if($invoice->user_id !== auth()->id(), 403);
            $invoice->update($request->validated());
        }
    PHP, 'web,auth'],
    'owner-scoped query' => [<<<'PHP'
        public function update(Request $request, int $id)
        {
            Invoice::where('user_id', $request->user()->id)->where('id', $id)->firstOrFail()->update(['paid' => true]);
        }
    PHP, 'web,auth'],
    'can: middleware' => [<<<'PHP'
        public function update(Request $request, int $id)
        {
            Invoice::findOrFail($id)->update(['paid' => true]);
        }
    PHP, 'web,auth,can:update,invoice'],
    'unknown middleware' => [<<<'PHP'
        public function update(Request $request, int $id)
        {
            Invoice::destroy($id);
        }
    PHP, 'web,auth,admin'],
    'id from the authenticated user' => [<<<'PHP'
        public function update(Request $request)
        {
            Invoice::findOrFail($request->user()->id)->update(['paid' => true]);
        }
    PHP, 'web,auth'],
    'business key, not an id' => [<<<'PHP'
        public function update(Request $request, string $slug)
        {
            Invoice::findOrFail($slug)->update(['paid' => true]);
        }
    PHP, 'web,auth'],
    'bulk query-builder update' => [<<<'PHP'
        public function update(Request $request, int $id)
        {
            Invoice::where('id', $id)->update(['paid' => true]);
        }
    PHP, 'web,auth'],
]);

it('stays silent on a write to a globally scoped model', function (): void {
    $files = writeBindingFiles(<<<'PHP'
        public function update(int $id)
        {
            Invoice::findOrFail($id)->update(['paid' => true]);
        }
    PHP, model: "    protected static function booted(): void\n    {\n        static::addGlobalScope('team', fn (\$q) => \$q->where('team_id', 1));\n    }\n");

    expect(writeBindingScan($files, writeBindingRoutes('update', 'PUT invoices/{id}')))->toBe([]);
});

it('does not report a fetched, returned and updated record twice', function (): void {
    $files = writeBindingFiles(<<<'PHP'
        public function update(Request $request, int $id)
        {
            $invoice = Invoice::findOrFail($id);
            $invoice->update($request->validated());

            return response()->json($invoice);
        }
    PHP);

    expect(writeBindingScan($files, writeBindingRoutes('update', 'PUT invoices/{id}')))->toHaveCount(1);
});

// ---------------------------------------------------------------------------
// Route-model binding
// ---------------------------------------------------------------------------

it('raises an unguarded route-model-bound record returned to the client for review only', function (string $body): void {
    $files = writeBindingFiles($body);

    $findings = writeBindingScan($files, writeBindingRoutes('show', 'GET invoices/{invoice}'));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::Idor)
        ->and($findings[0]->findingClass)->toBe(FindingClass::Review)
        ->and($findings[0]->confidence)->toBe(Confidence::Possible)
        ->and($findings[0]->fix)->toBe('')
        ->and($findings[0]->line)->toBe(11)
        ->and($findings[0]->description)->toContain('route-model binding');
})->with([
    'returned directly' => [<<<'PHP'
        public function show(Invoice $invoice)
        {
            return $invoice;
        }
    PHP],
    'returned as json' => [<<<'PHP'
        public function show(Invoice $invoice)
        {
            return response()->json($invoice);
        }
    PHP],
]);

it('stays silent on a guarded or unprovable route-model binding', function (string $body, string $route, string $middleware, string $model = '', string $request = ''): void {
    $files = writeBindingFiles($body, model: $model, imports: $request === '' ? '' : "use App\\Http\\Requests\\ShowInvoiceRequest;\n", extraFile: $request);

    expect(writeBindingDescribe(writeBindingScan($files, writeBindingRoutes('show', $route, explode(',', $middleware)))))->toBe([]);
})->with([
    'authorize()' => [<<<'PHP'
        public function show(Invoice $invoice)
        {
            $this->authorize('view', $invoice);

            return $invoice;
        }
    PHP, 'GET invoices/{invoice}', 'web,auth'],
    'Gate::authorize' => [<<<'PHP'
        public function show(Invoice $invoice)
        {
            Gate::authorize('view', $invoice);

            return $invoice;
        }
    PHP, 'GET invoices/{invoice}', 'web,auth'],
    'can: middleware' => [<<<'PHP'
        public function show(Invoice $invoice)
        {
            return $invoice;
        }
    PHP, 'GET invoices/{invoice}', 'web,auth,can:view,invoice'],
    'authorizeResource in constructor' => [<<<'PHP'
        public function __construct()
        {
            $this->authorizeResource(Invoice::class, 'invoice');
        }

        public function show(Invoice $invoice)
        {
            return $invoice;
        }
    PHP, 'GET invoices/{invoice}', 'web,auth'],
    'HasMiddleware static middleware()' => [<<<'PHP'
        public static function middleware(): array
        {
            return ['can:view,invoice'];
        }

        public function show(Invoice $invoice)
        {
            return $invoice;
        }
    PHP, 'GET invoices/{invoice}', 'web,auth'],
    'ownership comparison' => [<<<'PHP'
        public function show(Request $request, Invoice $invoice)
        {
            abort_unless($invoice->user_id === $request->user()->id, 403);

            return $invoice;
        }
    PHP, 'GET invoices/{invoice}', 'web,auth'],
    'authorising form request' => [<<<'PHP'
        public function show(ShowInvoiceRequest $request, Invoice $invoice)
        {
            return $invoice;
        }
    PHP, 'GET invoices/{invoice}', 'web,auth', '', "<?php\nnamespace App\\Http\\Requests;\nuse Illuminate\\Foundation\\Http\\FormRequest;\nclass ShowInvoiceRequest extends FormRequest\n{\n    public function authorize(): bool\n    {\n        return \$this->user()->can('view', \$this->route('invoice'));\n    }\n}\n"],
    'segment name does not match' => [<<<'PHP'
        public function show(Invoice $invoice)
        {
            return $invoice;
        }
    PHP, 'GET invoices/{id}', 'web,auth'],
    'nested (possibly scoped) binding' => [<<<'PHP'
        public function show(Invoice $invoice)
        {
            return $invoice;
        }
    PHP, 'GET teams/{team}/invoices/{invoice}', 'web,auth'],
    'custom resolveRouteBinding' => [<<<'PHP'
        public function show(Invoice $invoice)
        {
            return $invoice;
        }
    PHP, 'GET invoices/{invoice}', 'web,auth', "    public function resolveRouteBinding(\$value, \$field = null)\n    {\n        return \$this->where('user_id', auth()->id())->findOrFail(\$value);\n    }\n"],
    'record not returned' => [<<<'PHP'
        public function show(Invoice $invoice)
        {
            return response()->json(['ok' => true]);
        }
    PHP, 'GET invoices/{invoice}', 'web,auth'],
    'record re-resolved through the user' => [<<<'PHP'
        public function show(Request $request, Invoice $invoice)
        {
            $invoice = $request->user()->invoices()->findOrFail($invoice->id);

            return $invoice;
        }
    PHP, 'GET invoices/{invoice}', 'web,auth'],
    'unrouted action' => [<<<'PHP'
        public function show(Invoice $invoice)
        {
            return $invoice;
        }
    PHP, 'GET invoices/{invoice}', 'web,auth,admin'],
]);

it('stays silent on a route-model binding when no route table is known', function (): void {
    $files = writeBindingFiles(<<<'PHP'
        public function show(Invoice $invoice)
        {
            return $invoice;
        }
    PHP);

    expect(writeBindingScan($files, new AccessControlContext))->toBe([]);
});

it('suggests authorize() for a write only with the matching declared ability and a quotable variable', function (string $ability, bool $suggests): void {
    $files = writeBindingFiles(<<<'PHP'
        public function destroy(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            $invoice->delete();
        }
    PHP);

    $files[] = [
        'path' => 'app/Policies/InvoicePolicy.php',
        'type' => 'other',
        'content' => "<?php\nnamespace App\\Policies;\nuse App\\Models\\Invoice;\nuse App\\Models\\User;\nclass InvoicePolicy\n{\n    public function {$ability}(User \$user, Invoice \$invoice): bool\n    {\n        return \$invoice->user_id === \$user->id;\n    }\n}\n",
    ];

    $findings = writeBindingScan($files, writeBindingRoutes('destroy', 'DELETE invoices/{id}'));

    expect($findings)->toHaveCount(1);

    if ($suggests) {
        expect($findings[0]->fix)->toContain("authorize('delete', \$invoice)")
            ->and($findings[0]->fix)->toContain('line 11');
    } else {
        expect($findings[0]->fix)->not->toContain("authorize('");
    }
})->with([
    'policy declares delete' => ['delete', true],
    'policy declares only view' => ['view', false],
]);
