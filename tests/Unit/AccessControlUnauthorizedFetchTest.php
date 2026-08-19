<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\AccessControl\SourceFile;
use Mahdi\HackAuditor\Scanner\AccessControl\UnauthorizedModelFetchDetector;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\Confidence;
use Mahdi\HackAuditor\Support\FindingClass;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * UnauthorizedModelFetchDetector contract.
 *
 * An asserted IDOR needs a complete evidence chain, and "I cannot see any
 * authorization" is not a link in it. Over six real applications the old rule
 * produced 191 findings and 190 false positives, every one of them because the
 * guard was somewhere the detector was not looking: route middleware, a global
 * scope on the model, an application permission helper, or a base controller.
 *
 * So the detector now needs a routed entry point whose middleware it fully
 * understands, a model it can read, and an exposure path it recognises. When
 * the routing or the model cannot be resolved it asks a REVIEW question with no
 * fix instead of asserting a vulnerability.
 */

/**
 * @param  array<int, array{path: string, content: string, type: string}>  $files
 * @return array<int, Vulnerability>
 */
function runFetchDetector(array $files, ?AccessControlContext $context = null): array
{
    $detector = new UnauthorizedModelFetchDetector;
    $sources = array_map(fn (array $f): SourceFile => SourceFile::fromArray($f), $files);

    return $detector->detect($sources, $context ?? fetchRoutes());
}

/**
 * @return array<int, array{path: string, content: string, type: string}>
 */
function fetchController(string $methods): array
{
    return [
        [
            'path' => 'app/Http/Controllers/InvoiceController.php',
            'type' => 'controller',
            'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Invoice;\nclass InvoiceController\n{\n{$methods}\n}\n",
        ],
        fetchInvoiceModel(),
    ];
}

/**
 * A plain Eloquent model with an OWNER column and no global scope, so both
 * "the query is not narrowed by the model itself" and "this row belongs to
 * somebody" are facts rather than assumptions.
 *
 * @return array{path: string, content: string, type: string}
 */
function fetchInvoiceModel(): array
{
    return [
        'path' => 'app/Models/Invoice.php',
        'type' => 'model',
        'content' => "<?php\n\nnamespace App\\Models;\n\nuse Illuminate\\Database\\Eloquent\\Model;\n\nclass Invoice extends Model\n{\n    protected \$fillable = ['reference', 'user_id'];\n}\n",
    ];
}

/**
 * The route table HackScanner builds from the live Router: which actions are
 * reachable, and what runs in front of them.
 *
 * @param  array<int, string>  $methods
 * @param  array<int, string>  $middleware
 */
function fetchRoutes(array $methods = ['show', 'lookup', 'touch', 'index'], array $middleware = ['web', 'auth']): AccessControlContext
{
    $routed = [];

    foreach ($methods as $method) {
        $routed['App\Http\Controllers\InvoiceController@'.$method] = [
            'route' => 'GET /invoices/{id}',
            'middleware' => $middleware,
        ];
    }

    return new AccessControlContext(routedMethods: $routed);
}

/*
|--------------------------------------------------------------------------
| Asserted findings
|--------------------------------------------------------------------------
*/

it('flags find by request id returned without authorization', function (): void {
    $method = <<<'PHP'
        public function show(Request $request)
        {
            $invoice = Invoice::find($request->id);
            return $invoice;
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::Idor)
        ->and($findings[0]->severity)->toBe(SeverityLevel::High)
        ->and($findings[0]->findingClass)->toBe(FindingClass::Vulnerability)
        ->and($findings[0]->confidence)->toBe(Confidence::Proven)
        ->and($findings[0]->line)->toBeGreaterThan(1)
        ->and($findings[0]->description)->toContain('show');
});

it('flags findOrFail with id from request via local variable', function (): void {
    $method = <<<'PHP'
        public function show(Request $request)
        {
            $id = $request->input('id');
            $invoice = Invoice::findOrFail($id);
            return response()->json($invoice);
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::Idor);
});

it('flags findOrFail with a typed route-param id and no authorization', function (): void {
    $method = <<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            return $invoice;
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::Idor)
        ->and($findings[0]->severity)->toBe(SeverityLevel::High)
        ->and($findings[0]->description)->toContain('show');
});

it('flags an untyped route-param $id findOrFail returned without authorization', function (): void {
    $method = <<<'PHP'
        public function show($id)
        {
            $invoice = Invoice::findOrFail($id);
            return response()->json($invoice);
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::Idor);
});

it('flags where id from request first without ownership', function (): void {
    $method = <<<'PHP'
        public function show(Request $request)
        {
            $invoice = Invoice::where('id', $request->id)->first();
            return view('invoices.show', compact('invoice'));
        }
    PHP;

    expect(runFetchDetector(fetchController($method)))->toHaveCount(1);
});

it('quotes the route and its middleware in the proof', function (): void {
    $method = <<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            return response()->json($invoice);
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->proof)->toContain('GET /invoices/{id}')
        ->and($findings[0]->proof)->toContain('web, auth')
        ->and($findings[0]->proof)->toContain('Invoice and every ancestor it declares are present in this scan');
});

/*
|--------------------------------------------------------------------------
| The entry point must be proven
|--------------------------------------------------------------------------
*/

it('says NOTHING about an action the route table does not name', function (): void {
    $method = <<<'PHP'
        public function orphan(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            return response()->json($invoice);
        }
    PHP;

    expect(runFetchDetector(fetchController($method)))->toBe([]);
});

it('says NOTHING when the route carries middleware this scan cannot read', function (): void {
    $method = <<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            return response()->json($invoice);
        }
    PHP;

    foreach ([['web', 'admin'], ['api', 'permission:invoices.view'], ['can:view,invoice'], ['web', 'role:manager']] as $middleware) {
        $context = fetchRoutes(['show'], $middleware);

        expect(runFetchDetector(fetchController($method), $context))->toBe([]);
    }
});

it('says NOTHING about a scalar route parameter when no route table was supplied', function (): void {
    // "an untyped scalar parameter of a controller action is a route segment"
    // is an assumption about ROUTING. Without a route table it is unproven, and
    // an unproven source is not a source.
    $method = <<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            return response()->json($invoice);
        }
    PHP;

    expect(runFetchDetector(fetchController($method), new AccessControlContext))->toBe([]);
});

it('asks a REVIEW question for an explicit request accessor when no route table was supplied', function (): void {
    $method = <<<'PHP'
        public function show(Request $request)
        {
            $invoice = Invoice::findOrFail($request->input('invoice_id'));
            return response()->json($invoice);
        }
    PHP;

    $findings = runFetchDetector(fetchController($method), new AccessControlContext);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->findingClass)->toBe(FindingClass::Review)
        ->and($findings[0]->confidence)->toBe(Confidence::Possible)
        ->and($findings[0]->hasFix())->toBeFalse()
        ->and($findings[0]->description)->toStartWith('Is InvoiceController::show() meant to be readable by any caller?')
        ->and($findings[0]->proof)->toContain('No route table was supplied');
});

it('asks a REVIEW question when the model is not in the scan', function (): void {
    $method = <<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            return response()->json($invoice);
        }
    PHP;

    $files = [fetchController($method)[0]];

    $findings = runFetchDetector($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->findingClass)->toBe(FindingClass::Review)
        ->and($findings[0]->hasFix())->toBeFalse()
        ->and($findings[0]->proof)->toContain('whether it registers a global scope is UNKNOWN');
});

it('says NOTHING about an action declared in a TRAIT, which has no route', function (): void {
    // pixelfed keeps most of its admin actions in traits whose names end in
    // "Controller". A trait is not routed, and eight false positives came from
    // treating one as though it were.
    $files = [
        [
            'path' => 'app/Http/Controllers/Admin/AdminReportController.php',
            'type' => 'controller',
            'content' => "<?php\nnamespace App\\Http\\Controllers\\Admin;\nuse App\\Models\\Invoice;\ntrait AdminReportController\n{\n    public function show(int \$id)\n    {\n        \$invoice = Invoice::findOrFail(\$id);\n        return response()->json(\$invoice);\n    }\n}\n",
        ],
        fetchInvoiceModel(),
    ];

    $context = new AccessControlContext(routedMethods: [
        'App\Http\Controllers\Admin\AdminReportController@show' => ['route' => 'GET /admin/reports/{id}', 'middleware' => ['web']],
    ]);

    expect(runFetchDetector($files, $context))->toBe([]);
});

it('says NOTHING about an abstract base controller', function (): void {
    $files = [
        [
            'path' => 'app/Http/Controllers/BaseInvoiceController.php',
            'type' => 'controller',
            'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Invoice;\nabstract class BaseInvoiceController\n{\n    public function show(int \$id)\n    {\n        \$invoice = Invoice::findOrFail(\$id);\n        return response()->json(\$invoice);\n    }\n}\n",
        ],
        fetchInvoiceModel(),
    ];

    $context = new AccessControlContext(routedMethods: [
        'App\Http\Controllers\BaseInvoiceController@show' => ['route' => 'GET /invoices/{id}', 'middleware' => ['web']],
    ]);

    expect(runFetchDetector($files, $context))->toBe([]);
});

/*
|--------------------------------------------------------------------------
| The record must be able to belong to somebody
|--------------------------------------------------------------------------
*/

it('says NOTHING about a shared catalogue model that has no owner (snipe-it regression)', function (): void {
    // snipe-it's AssetModel lists category_id, manufacturer_id, fieldset_id and
    // model_number. Nobody owns an asset MODEL, so "any caller can read another
    // user's AssetModel" is not a true sentence and must not be asserted.
    $method = <<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            return response()->json($invoice);
        }
    PHP;

    $files = fetchController($method);
    $files[1]['content'] = "<?php\n\nnamespace App\\Models;\n\nuse Illuminate\\Database\\Eloquent\\Model;\n\nclass Invoice extends Model\n{\n    protected \$fillable = ['category_id', 'manufacturer_id', 'model_number'];\n}\n";

    expect(runFetchDetector($files))->toBe([]);
});

it('flags a model that relates to the authenticatable user even without a literal column', function (): void {
    $method = <<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            return response()->json($invoice);
        }
    PHP;

    $files = fetchController($method);
    $files[1]['content'] = <<<'PHP'
    <?php

    namespace App\Models;

    use Illuminate\Database\Eloquent\Model;
    use Illuminate\Database\Eloquent\Relations\BelongsTo;

    class Invoice extends Model
    {
        public function owner(): BelongsTo
        {
            return $this->belongsTo(User::class);
        }
    }
    PHP;
    $files[] = [
        'path' => 'app/Models/User.php',
        'type' => 'model',
        'content' => "<?php\n\nnamespace App\\Models;\n\nuse Illuminate\\Foundation\\Auth\\User as Authenticatable;\n\nclass User extends Authenticatable\n{\n}\n",
    ];

    expect(runFetchDetector($files))->toHaveCount(1);
});

/*
|--------------------------------------------------------------------------
| Global scopes
|--------------------------------------------------------------------------
*/

it('says NOTHING when the model registers a global scope in its own booted()', function (): void {
    $method = <<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            return response()->json($invoice);
        }
    PHP;

    $files = fetchController($method);
    $files[1]['content'] = <<<'PHP'
    <?php

    namespace App\Models;

    use App\Scopes\CompanyScope;
    use Illuminate\Database\Eloquent\Model;

    class Invoice extends Model
    {
        protected static function booted(): void
        {
            static::addGlobalScope(new CompanyScope);
        }
    }
    PHP;

    expect(runFetchDetector($files))->toBe([]);
});

it('says NOTHING when an application TRAIT on the model registers a global scope (akaunting regression)', function (): void {
    $method = <<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            return response()->json($invoice);
        }
    PHP;

    $files = fetchController($method);
    $files[1]['content'] = <<<'PHP'
    <?php

    namespace App\Models;

    use App\Traits\Tenants;
    use Illuminate\Database\Eloquent\Model;

    class Invoice extends Model
    {
        use Tenants;
    }
    PHP;

    $files[] = [
        'path' => 'app/Traits/Tenants.php',
        'type' => 'other',
        'content' => <<<'PHP'
        <?php

        namespace App\Traits;

        use App\Scopes\Company;

        trait Tenants
        {
            protected static function bootTenants(): void
            {
                static::addGlobalScope(new Company);
            }
        }
        PHP,
    ];

    expect(runFetchDetector($files))->toBe([]);
});

it('says NOTHING when the model carries a #[ScopedBy] attribute', function (): void {
    $method = <<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            return response()->json($invoice);
        }
    PHP;

    $files = fetchController($method);
    $files[1]['content'] = <<<'PHP'
    <?php

    namespace App\Models;

    use App\Scopes\CompanyScope;
    use Illuminate\Database\Eloquent\Attributes\ScopedBy;
    use Illuminate\Database\Eloquent\Model;

    #[ScopedBy([CompanyScope::class])]
    class Invoice extends Model
    {
    }
    PHP;

    expect(runFetchDetector($files))->toBe([]);
});

/*
|--------------------------------------------------------------------------
| Guards
|--------------------------------------------------------------------------
*/

it('does NOT flag a route-param findOrFail that is authorized', function (): void {
    $method = <<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            $this->authorize('view', $invoice);
            return $invoice;
        }
    PHP;

    expect(runFetchDetector(fetchController($method)))->toBe([]);
});

it('does NOT flag a route-param fetch scoped to the owner', function (): void {
    $method = <<<'PHP'
        public function show(int $id)
        {
            $invoice = auth()->user()->invoices()->findOrFail($id);
            return $invoice;
        }
    PHP;

    expect(runFetchDetector(fetchController($method)))->toBe([]);
});

it('does NOT flag a route-param fetch that is never exposed', function (): void {
    $method = <<<'PHP'
        public function touch(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            $invoice->touch();
        }
    PHP;

    expect(runFetchDetector(fetchController($method)))->toBe([]);
});

it('does NOT flag a non-id scalar parameter fetch', function (): void {
    $method = <<<'PHP'
        public function show(string $slug)
        {
            $invoice = Invoice::findOrFail($slug);
            return $invoice;
        }
    PHP;

    expect(runFetchDetector(fetchController($method)))->toBe([]);
});

it('does NOT flag when $this->authorize is called', function (): void {
    $method = <<<'PHP'
        public function show(Request $request)
        {
            $invoice = Invoice::findOrFail($request->id);
            $this->authorize('view', $invoice);
            return $invoice;
        }
    PHP;

    expect(runFetchDetector(fetchController($method)))->toBe([]);
});

it('does NOT flag when Gate::authorize guards the fetch', function (): void {
    $method = <<<'PHP'
        public function show(Request $request)
        {
            $invoice = Invoice::findOrFail($request->id);
            Gate::authorize('view', $invoice);
            return $invoice;
        }
    PHP;

    expect(runFetchDetector(fetchController($method)))->toBe([]);
});

it('does NOT flag when an application permission helper guards the fetch (BookStack regression)', function (): void {
    $method = <<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            $this->checkOwnablePermission('invoice-view', $invoice);
            return response()->json($invoice);
        }
    PHP;

    expect(runFetchDetector(fetchController($method)))->toBe([]);
});

it('does NOT flag when the action aborts on a failed check', function (): void {
    $method = <<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            abort_unless($invoice->isVisibleTo(auth()->user()), 403);
            return response()->json($invoice);
        }
    PHP;

    expect(runFetchDetector(fetchController($method)))->toBe([]);
});

it('does NOT flag when the query is scoped to the owner', function (): void {
    $method = <<<'PHP'
        public function show(Request $request)
        {
            $invoice = Invoice::where('id', $request->id)->where('user_id', auth()->id())->first();
            return $invoice;
        }
    PHP;

    expect(runFetchDetector(fetchController($method)))->toBe([]);
});

it('does NOT flag when fetched through the auth user relationship', function (): void {
    $method = <<<'PHP'
        public function show(Request $request)
        {
            $invoice = auth()->user()->invoices()->findOrFail($request->id);
            return $invoice;
        }
    PHP;

    expect(runFetchDetector(fetchController($method)))->toBe([]);
});

it('does NOT flag when a base controller constructor registers unreadable middleware', function (): void {
    $method = <<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            return response()->json($invoice);
        }
    PHP;

    $files = [
        [
            'path' => 'app/Http/Controllers/InvoiceController.php',
            'type' => 'controller',
            'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Invoice;\nclass InvoiceController extends AdminController\n{\n{$method}\n}\n",
        ],
        [
            'path' => 'app/Http/Controllers/AdminController.php',
            'type' => 'controller',
            'content' => "<?php\nnamespace App\\Http\\Controllers;\nclass AdminController\n{\n    public function __construct()\n    {\n        \$this->middleware([Permission::SettingsManage->middleware()]);\n    }\n}\n",
        ],
        fetchInvoiceModel(),
    ];

    expect(runFetchDetector($files))->toBe([]);
});

it('does NOT flag a fetch that is not exposed', function (): void {
    $method = <<<'PHP'
        public function touch(Request $request)
        {
            $invoice = Invoice::find($request->id);
            $invoice->touch();
        }
    PHP;

    expect(runFetchDetector(fetchController($method)))->toBe([]);
});

it('does NOT flag fetches that do not use request input', function (): void {
    $method = <<<'PHP'
        public function index()
        {
            $invoice = Invoice::find(1);
            return $invoice;
        }
    PHP;

    expect(runFetchDetector(fetchController($method)))->toBe([]);
});

it('does NOT flag non-controller files', function (): void {
    $files = [[
        'path' => 'app/Models/Invoice.php',
        'type' => 'model',
        'content' => "<?php\nclass Invoice { public function show(\$r){ \$i = Invoice::find(\$r->id); return \$i; } }",
    ]];

    expect(runFetchDetector($files))->toBe([]);
});
