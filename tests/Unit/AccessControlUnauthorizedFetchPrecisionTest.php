<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\AccessControl\SourceFile;
use Mahdi\HackAuditor\Scanner\AccessControl\UnauthorizedModelFetchDetector;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\FindingClass;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * FALSE-POSITIVE REGRESSION SUITE for UnauthorizedModelFetchDetector.
 *
 * Every fixture below is scanned with a FULLY KNOWN entry point — the action is
 * in the route table and its middleware is authentication and plumbing only —
 * so nothing here passes merely because the detector went quiet about routing.
 * Each "does not flag" case therefore exercises the guard, the scope or the
 * exposure rule it is named after.
 *
 * The recurring root causes these tests pin down:
 *  - `$request->user()` is the AUTHENTICATED USER OBJECT, not attacker input.
 *  - a verb such as find()/get() means nothing without knowing the receiver.
 *  - a record handed to an arbitrary helper is not proven to reach the client.
 *  - a "fix" may only name identifiers proven to exist in the analysed code,
 *    and a policy class must be QUOTED, never synthesised as "{Model}Policy".
 *  - a line comes from the AST node, never from a byte offset into raw text.
 */

/**
 * Run the detector over an explicit file set.
 *
 * @param  array<int, array{path: string, content: string, type: string}>  $files
 * @return array<int, Vulnerability>
 */
function idorPrecisionScan(array $files, ?AccessControlContext $context = null): array
{
    $sources = array_map(
        static fn (array $file): SourceFile => SourceFile::fromArray($file),
        $files,
    );

    return (new UnauthorizedModelFetchDetector)->detect($sources, $context ?? idorPrecisionRoutes());
}

/**
 * A route table naming every action these fixtures declare, behind middleware
 * that performs authentication and nothing else.
 *
 * @param  array<int, string>  $methods
 * @param  array<int, string>  $middleware
 */
function idorPrecisionRoutes(array $methods = ['show', 'index', 'store', 'update'], array $middleware = ['web', 'auth']): AccessControlContext
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

/**
 * The two models these fixtures fetch, both free of global scopes so "nothing
 * narrows this query" is a resolved fact, and both owned so "another user's
 * record" is a meaningful claim.
 *
 * @return array<int, array{path: string, content: string, type: string}>
 */
function idorPrecisionModels(): array
{
    return [
        [
            'path' => 'app/Models/Invoice.php',
            'type' => 'model',
            'content' => "<?php\n\nnamespace App\\Models;\n\nuse Illuminate\\Database\\Eloquent\\Model;\n\nclass Invoice extends Model\n{\n    protected \$fillable = ['reference', 'user_id'];\n}\n",
        ],
        [
            'path' => 'app/Models/User.php',
            'type' => 'model',
            'content' => "<?php\n\nnamespace App\\Models;\n\nuse Illuminate\\Foundation\\Auth\\User as Authenticatable;\n\nclass User extends Authenticatable\n{\n}\n",
        ],
    ];
}

/**
 * The base controller these fixtures extend, spelled out rather than left to
 * the imagination.
 *
 * A scan that cannot read the base cannot know whether `$this->authorize()`
 * resolves on the child, and D-3 forbids writing a call whose receiver is
 * unproven. Making the base explicit — and giving it AuthorizesRequests, the
 * pre-Laravel-11 default that most deployed applications still carry — keeps
 * the tests below aimed at what they are about (which ability, which variable)
 * instead of accidentally exercising the receiver rule.
 *
 * @return array{path: string, content: string, type: string}
 */
function idorPrecisionBaseController(string $body = "    use AuthorizesRequests;\n", string $imports = "use Illuminate\\Foundation\\Auth\\Access\\AuthorizesRequests;\n"): array
{
    return [
        'path' => 'app/Http/Controllers/Controller.php',
        'type' => 'controller',
        'content' => "<?php\n\ndeclare(strict_types=1);\n\nnamespace App\\Http\\Controllers;\n\n{$imports}\nabstract class Controller\n{\n{$body}}\n",
    ];
}

/**
 * Wrap controller members in a realistic file with real imports, alongside the
 * models it fetches.
 *
 * @return array<int, array{path: string, content: string, type: string}>
 */
function idorPrecisionController(string $members, string $imports = ''): array
{
    $content = <<<PHP
    <?php

    declare(strict_types=1);

    namespace App\Http\Controllers;

    use App\Models\Invoice;
    use App\Models\User;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Auth;
    use Illuminate\Support\Facades\Gate;
    {$imports}

    class InvoiceController extends Controller
    {
    {$members}
    }

    PHP;

    return [
        [
            'path' => 'app/Http/Controllers/InvoiceController.php',
            'type' => 'controller',
            'content' => $content,
        ],
        idorPrecisionBaseController(),
        ...idorPrecisionModels(),
    ];
}

/**
 * Render findings so a failure names the file, line and claim.
 *
 * @param  array<int, Vulnerability>  $findings
 * @return array<int, string>
 */
function idorPrecisionDescribe(array $findings): array
{
    return array_map(
        static fn (Vulnerability $v): string => sprintf('%s:%d [%s] %s', $v->location, $v->line, $v->type->value, $v->description),
        $findings,
    );
}

/**
 * 1-based line of the first source line containing the needle.
 */
function idorPrecisionLineOf(string $content, string $needle): int
{
    foreach (explode("\n", $content) as $index => $line) {
        if (str_contains($line, $needle)) {
            return $index + 1;
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// The authenticated user is not attacker-controlled input.
// ---------------------------------------------------------------------------

it('does not flag a lookup keyed on $request->user()->id', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show(Request $request)
        {
            $user = User::findOrFail($request->user()->id);

            return response()->json($user);
        }
    PHP);

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

it('does not flag a lookup keyed on auth()->id()', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show()
        {
            $user = User::findOrFail(auth()->id());

            return response()->json($user);
        }
    PHP);

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

it('does not flag a lookup keyed on Auth::id()', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show()
        {
            $user = User::findOrFail(Auth::id());

            return response()->json($user);
        }
    PHP);

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

it('does not flag a lookup keyed on server-side configuration', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show()
        {
            $user = User::findOrFail(config('billing.house_account_id'));

            return response()->json($user);
        }
    PHP);

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

// ---------------------------------------------------------------------------
// Queries already scoped to the authenticated user.
// ---------------------------------------------------------------------------

it('does not flag a fetch resolved from a relation on $request->user()', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show(Request $request, int $id)
        {
            $invoice = $request->user()->invoices()->findOrFail($id);

            return response()->json($invoice);
        }
    PHP);

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

it('does not flag a fetch scoped with whereBelongsTo($request->user())', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show(Request $request, int $id)
        {
            $invoice = Invoice::whereBelongsTo($request->user())->findOrFail($id);

            return response()->json($invoice);
        }
    PHP);

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

it('does not flag a fetch scoped with where(user_id, auth()->id())', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::where('id', $id)->where('user_id', auth()->id())->firstOrFail();

            return response()->json($invoice);
        }
    PHP);

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

it('does not flag a fetch followed by an ownership comparison against auth()->id()', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);

            abort_if($invoice->user_id !== auth()->id(), 403);

            return response()->json($invoice);
        }
    PHP);

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

it('does not flag a fetch guarded by an ownership comparison against $request->user()->id', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show(Request $request, int $id)
        {
            $invoice = Invoice::findOrFail($id);

            if ($invoice->user_id !== $request->user()->id) {
                abort(403);
            }

            return response()->json($invoice);
        }
    PHP);

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

// ---------------------------------------------------------------------------
// Authorization that lives somewhere other than the method body.
// ---------------------------------------------------------------------------

it('does not flag an action authorized by authorizeResource() in the constructor', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function __construct()
        {
            $this->authorizeResource(Invoice::class, 'invoice');
        }

        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);

            return response()->json($invoice);
        }
    PHP);

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

it('does not flag an action authorized by can: middleware registered in the constructor', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function __construct()
        {
            $this->middleware('can:view,invoice');
        }

        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);

            return response()->json($invoice);
        }
    PHP);

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

it('does not flag an action whose route carries can: middleware', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);

            return response()->json($invoice);
        }
    PHP);

    $context = new AccessControlContext(
        routedMethods: [
            'App\Http\Controllers\InvoiceController@show' => [
                'route' => 'GET /invoices/{invoice}',
                'middleware' => ['api', 'auth:sanctum', 'can:view,invoice'],
            ],
        ],
        modelsWithPolicy: ['Invoice'],
    );

    expect(idorPrecisionDescribe(idorPrecisionScan($files, $context)))->toBe([]);
});

it('does not flag an action whose FormRequest authorize() asks the authorization layer', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show(ShowInvoiceRequest $request, int $id)
        {
            $invoice = Invoice::findOrFail($id);

            return response()->json($invoice);
        }
    PHP, "use App\Http\Requests\ShowInvoiceRequest;");

    $files[] = [
        'path' => 'app/Http/Requests/ShowInvoiceRequest.php',
        'type' => 'other',
        'content' => <<<'PHP'
        <?php

        declare(strict_types=1);

        namespace App\Http\Requests;

        use Illuminate\Foundation\Http\FormRequest;

        class ShowInvoiceRequest extends FormRequest
        {
            public function authorize(): bool
            {
                return $this->user()->can('view', $this->route('invoice'));
            }
        }

        PHP,
    ];

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

it('does not flag when Gate::allows guards the fetch', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);

            if (! Gate::allows('view', $invoice)) {
                abort(403);
            }

            return response()->json($invoice);
        }
    PHP);

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

// ---------------------------------------------------------------------------
// Receiver awareness: a verb is not a lookup.
// ---------------------------------------------------------------------------

it('does not treat find() on a non-Eloquent local class as a model lookup', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show(int $id)
        {
            $entry = Registry::find($id);

            return response()->json($entry);
        }
    PHP, "use App\Support\Registry;");

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

it('does not descend into a closure, whose variables are a different scope', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function index(Request $request)
        {
            return collect($request->input('ids'))->map(function ($id) {
                return Invoice::findOrFail($id);
            });
        }
    PHP);

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

// ---------------------------------------------------------------------------
// Exposure: the record must PROVABLY reach the caller.
// ---------------------------------------------------------------------------

it('does not treat redirect()->route(..., $model) as exposing the record', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function update(Request $request, int $id)
        {
            $invoice = Invoice::findOrFail($id);

            $invoice->touch();

            return redirect()->route('invoices.show', $invoice);
        }
    PHP);

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

it('does not treat a field read off the record as whole-record exposure', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);

            return response()->json($invoice->only(['id', 'total']));
        }
    PHP);

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

it('does not treat a record handed to an application view helper as published (monica regression)', function (): void {
    // `Inertia::render('…', ['data' => ShowViewHelper::data($invoice, …)])`
    // proves the record was handed to a helper. What that helper emits is not
    // visible here, so it is not proof that the record reaches the client —
    // and assuming it did produced dozens of false positives on monica.
    $files = idorPrecisionController(<<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);

            return Inertia::render('Invoices/Show', [
                'data' => InvoiceShowViewHelper::data($invoice, Auth::user()),
            ]);
        }
    PHP, "use App\Http\ViewHelpers\InvoiceShowViewHelper;\nuse Inertia\Inertia;");

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

it('does not flag a fetch whose record is only written to, never returned', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function store(Request $request)
        {
            $invoice = Invoice::findOrFail($request->validated('invoice_id'));

            $invoice->reports()->create([
                'reason' => $request->validated('reason'),
                'reported_by' => $request->user()->id,
            ]);

            return response()->json(['reported' => true], 202);
        }
    PHP);

    expect(idorPrecisionDescribe(idorPrecisionScan($files)))->toBe([]);
});

it('still treats an API Resource wrapping the record as exposure', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);

            return new InvoiceResource($invoice);
        }
    PHP, "use App\Http\Resources\InvoiceResource;");

    expect(idorPrecisionScan($files))->toHaveCount(1);
});

// ---------------------------------------------------------------------------
// Advice must never break the app.
// ---------------------------------------------------------------------------

it('never suggests an ability the Policy does not declare', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);

            return response()->json($invoice);
        }
    PHP);

    $files[] = [
        'path' => 'app/Policies/InvoicePolicy.php',
        'type' => 'other',
        'content' => <<<'PHP'
        <?php

        declare(strict_types=1);

        namespace App\Policies;

        use App\Models\Invoice;
        use App\Models\User;

        class InvoicePolicy
        {
            public function update(User $user, Invoice $invoice): bool
            {
                return $invoice->user_id === $user->id;
            }
        }

        PHP,
    ];

    $findings = idorPrecisionScan($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->not->toContain("authorize('")
        ->and($findings[0]->fix)->not->toContain('authorize("');
});

it('suggests authorize() only with an ability the Policy declares and a variable that exists', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);

            return response()->json($invoice);
        }
    PHP);

    $files[] = [
        'path' => 'app/Policies/InvoicePolicy.php',
        'type' => 'other',
        'content' => <<<'PHP'
        <?php

        declare(strict_types=1);

        namespace App\Policies;

        use App\Models\Invoice;
        use App\Models\User;

        class InvoicePolicy
        {
            public function view(User $user, Invoice $invoice): bool
            {
                return $invoice->user_id === $user->id;
            }
        }

        PHP,
    ];

    $findings = idorPrecisionScan($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain("\$this->authorize('view', \$invoice)");
});

it('QUOTES the policy class it resolved instead of synthesising {Model}Policy', function (): void {
    // A Gate::policy() registration can bind any class name. Advising
    // "ContractPolicy declares …" when the registered class is
    // ContractAccessPolicy names a class that does not exist.
    $files = idorPrecisionController(<<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);

            return response()->json($invoice);
        }
    PHP);

    $files[] = [
        'path' => 'app/Policies/InvoiceAccessPolicy.php',
        'type' => 'other',
        'content' => <<<'PHP'
        <?php

        declare(strict_types=1);

        namespace App\Policies;

        use App\Models\Invoice;
        use App\Models\User;

        class InvoiceAccessPolicy
        {
            public function view(User $user, Invoice $invoice): bool
            {
                return $invoice->user_id === $user->id;
            }
        }

        PHP,
    ];

    $findings = idorPrecisionScan($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain('InvoiceAccessPolicy')
        ->and($findings[0]->fix)->not->toContain('InvoicePolicy');
});

it('never names a variable the analysed code does not define', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show(int $id)
        {
            return response()->json(Invoice::findOrFail($id));
        }
    PHP);

    $findings = idorPrecisionScan($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->not->toContain('$model')
        ->and($findings[0]->description)->not->toContain('$model')
        ->and($findings[0]->fix)->not->toContain("authorize('");
});

/**
 * A policy declaring the read ability, so the remedy reaches the branch that
 * writes an authorize() call rather than the generic ownership advice.
 *
 * @return array{path: string, content: string, type: string}
 */
function idorPrecisionViewPolicy(): array
{
    return [
        'path' => 'app/Policies/InvoicePolicy.php',
        'type' => 'other',
        'content' => <<<'PHP'
        <?php

        declare(strict_types=1);

        namespace App\Policies;

        use App\Models\Invoice;
        use App\Models\User;

        class InvoicePolicy
        {
            public function view(User $user, Invoice $invoice): bool
            {
                return $invoice->user_id === $user->id;
            }
        }

        PHP,
    ];
}

it('names a conditionally bound record, because the advice is anchored to the lookup (D-3)', function (): void {
    // The suggested line goes "immediately after the lookup", i.e. INSIDE the
    // try block, so the only path that reaches it is the path that made the
    // binding. Refusing here would cost a true positive and buy no safety.
    $files = idorPrecisionController(<<<'PHP'
        public function show(int $id)
        {
            try {
                $invoice = Invoice::findOrFail($id);
            } catch (\Throwable $e) {
                report($e);
            }

            return response()->json($invoice);
        }
    PHP);

    $files[] = idorPrecisionViewPolicy();

    $findings = idorPrecisionScan($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain("\$this->authorize('view', \$invoice)");
});

it('never names a record bound in a match arm, where no line can follow the lookup (D-3)', function (): void {
    // "Add the call immediately after the lookup" cannot be obeyed inside a
    // match arm. The reader would place it after the whole match statement —
    // exactly where $invoice is undefined for every other mode.
    $files = idorPrecisionController(<<<'PHP'
        public function show(Request $request, int $id)
        {
            match ($request->input('mode')) {
                'full' => $invoice = Invoice::findOrFail($id),
                default => null,
            };

            return response()->json($invoice);
        }
    PHP);

    $files[] = idorPrecisionViewPolicy();

    $findings = idorPrecisionScan($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->not->toContain('$invoice')
        ->and($findings[0]->fix)->not->toContain("authorize('");
});

it('never attaches a fix to a review finding', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show(Request $request)
        {
            $invoice = Invoice::findOrFail($request->input('invoice_id'));

            return response()->json($invoice);
        }
    PHP);

    $findings = idorPrecisionScan($files, new AccessControlContext);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->findingClass)->toBe(FindingClass::Review)
        ->and($findings[0]->hasFix())->toBeFalse();
});

// ---------------------------------------------------------------------------
// Recall: the genuine IDOR still fires, at the exact line.
// ---------------------------------------------------------------------------

it('still flags the benchmark IdorController at the exact line of the lookup', function (): void {
    $path = dirname(__DIR__).'/Fixtures/benchmark/samples/IdorController.php';

    $context = new AccessControlContext(routedMethods: [
        'App\Http\Controllers\IdorController@show' => ['route' => 'GET /invoices/{id}', 'middleware' => ['web', 'auth']],
    ]);

    $findings = idorPrecisionScan([[
        'path' => 'IdorController.php',
        'type' => 'controller',
        'content' => (string) file_get_contents($path),
    ]], $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::Idor)
        ->and($findings[0]->line)->toBe(14);
});

it('reports the line of the lookup, not the docblock or the signature above it', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        /**
         * Show one invoice.
         *
         * @param  int  $id  Invoice identifier (see docs)
         */
        public function show(
            Request $request,
            int $id = 0,
        ): mixed {
            $invoice = Invoice::findOrFail($id);

            return response()->json($invoice);
        }
    PHP);

    $findings = idorPrecisionScan($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->line)->toBe(idorPrecisionLineOf($files[0]['content'], 'Invoice::findOrFail($id)'));
});

it('still flags a lookup keyed on $request->route(\'id\')', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show(Request $request)
        {
            $invoice = Invoice::findOrFail($request->route('id'));

            return response()->json($invoice);
        }
    PHP);

    expect(idorPrecisionScan($files))->toHaveCount(1);
});

it('still flags a lookup keyed on a superglobal', function (): void {
    $files = idorPrecisionController(<<<'PHP'
        public function show()
        {
            $invoice = Invoice::findOrFail($_GET['invoice_id']);

            return response()->json($invoice);
        }
    PHP);

    expect(idorPrecisionScan($files))->toHaveCount(1);
});

it('reports nothing for the whole clean precision corpus', function (): void {
    $root = dirname(__DIR__).'/Fixtures/precision';

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
    );

    $files = [];

    foreach ($iterator as $file) {
        if (! $file instanceof SplFileInfo || $file->getExtension() !== 'php') {
            continue;
        }

        $relative = str_replace(DIRECTORY_SEPARATOR, '/', str_replace($root.DIRECTORY_SEPARATOR, '', $file->getPathname()));

        $files[] = [
            'path' => $relative,
            'content' => (string) file_get_contents($file->getPathname()),
            'type' => match (true) {
                str_contains($relative, 'Http/Controllers/') => 'controller',
                str_contains($relative, 'Models/') => 'model',
                str_starts_with($relative, 'routes/') => 'route',
                default => 'other',
            },
        ];
    }

    expect($files)->not->toBeEmpty()
        ->and(idorPrecisionDescribe(idorPrecisionScan($files, new AccessControlContext)))->toBe([]);
});

// ---------------------------------------------------------------------------
// D-3 — THE RECEIVER OF THE ANCHORED REMEDY.
//
// The remedy proves the policy class, the ability and an anchorable variable.
// It used to assume the fourth identifier: that `$this->authorize()` exists at
// all. On the base controller Laravel 11+ generates it does not, and the
// advised line 500s every request instead of authorising it.
// ---------------------------------------------------------------------------

/**
 * The show() body every receiver test shares: one unconditional lookup, so the
 * only thing that can vary the remedy is the receiver.
 *
 * @return array<int, array{path: string, content: string, type: string}>
 */
function idorReceiverFixture(array $baseController): array
{
    $files = idorPrecisionController(<<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);

            return response()->json($invoice);
        }
    PHP);

    // Replace the fixture's default base with the one under test.
    foreach ($files as $index => $file) {
        if ($file['path'] === 'app/Http/Controllers/Controller.php') {
            $files[$index] = $baseController;
        }
    }

    $files[] = idorPrecisionViewPolicy();

    return $files;
}

it('does NOT advise $this->authorize() on the trait-less base Laravel 11+ generates (D-3)', function (): void {
    $files = idorReceiverFixture([
        'path' => 'app/Http/Controllers/Controller.php',
        'type' => 'controller',
        'content' => "<?php\n\nnamespace App\\Http\\Controllers;\n\nabstract class Controller\n{\n}\n",
    ]);

    $findings = idorPrecisionScan($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->not->toContain('add $this->authorize(')
        ->and($findings[0]->fix)->toContain("add Gate::authorize('view', \$invoice)")
        ->and($findings[0]->fix)->toContain('Illuminate\Support\Facades\Gate')
        ->and($findings[0]->fix)->toContain('does not have that method');
});

it('does NOT advise $this->authorize() on a base extending Illuminate\Routing\Controller with no trait (D-3)', function (): void {
    $files = idorReceiverFixture([
        'path' => 'app/Http/Controllers/Controller.php',
        'type' => 'controller',
        'content' => "<?php\n\nnamespace App\\Http\\Controllers;\n\nuse Illuminate\\Routing\\Controller as BaseController;\n\nabstract class Controller extends BaseController\n{\n}\n",
    ]);

    $findings = idorPrecisionScan($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->not->toContain('add $this->authorize(')
        ->and($findings[0]->fix)->toContain("add Gate::authorize('view', \$invoice)");
});

it('KEEPS $this->authorize() when the base controller uses AuthorizesRequests (D-3)', function (): void {
    $files = idorReceiverFixture(idorPrecisionBaseController());

    $findings = idorPrecisionScan($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain("add \$this->authorize('view', \$invoice)")
        ->and($findings[0]->fix)->not->toContain('Gate::authorize');
});

it('KEEPS $this->authorize() when a parent declares an authorize() of its own (D-3)', function (): void {
    $files = idorReceiverFixture([
        'path' => 'app/Http/Controllers/Controller.php',
        'type' => 'controller',
        'content' => "<?php\n\nnamespace App\\Http\\Controllers;\n\nabstract class Controller\n{\n    public function authorize(\$ability, \$arguments = []) { return true; }\n}\n",
    ]);

    $findings = idorPrecisionScan($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain("add \$this->authorize('view', \$invoice)");
});

it('does NOT advise $this->authorize() when the base controller cannot be read (D-3)', function (): void {
    $files = idorReceiverFixture([
        'path' => 'app/Support/Placeholder.php',
        'type' => 'other',
        'content' => "<?php\n\nnamespace App\\Support;\n\nclass Placeholder\n{\n}\n",
    ]);

    $findings = idorPrecisionScan($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->not->toContain('add $this->authorize(')
        ->and($findings[0]->fix)->toContain("add Gate::authorize('view', \$invoice)")
        ->and($findings[0]->fix)->toContain('which this scan could not read');
});

it('accepts `use AuthorizesRequests;` written without an import statement (D-3)', function (): void {
    // Unimported, the trait resolves to App\Http\Controllers\AuthorizesRequests,
    // a name nothing in the scan occupies. In a Laravel controller that spelling
    // means the framework trait, so the method really is callable and the
    // $this-> form stands.
    $files = idorReceiverFixture(idorPrecisionBaseController("    use AuthorizesRequests;\n", ''));

    $findings = idorPrecisionScan($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain("add \$this->authorize('view', \$invoice)");
});

it('refuses an application trait that merely shares the AuthorizesRequests name (D-3)', function (): void {
    // A READABLE trait of that name proves nothing: it declares no authorize(),
    // so the method is still missing and the advice must not write it.
    $files = idorReceiverFixture(idorPrecisionBaseController("    use AuthorizesRequests;\n", ''));

    $files[] = [
        'path' => 'app/Http/Controllers/AuthorizesRequests.php',
        'type' => 'other',
        'content' => "<?php\n\nnamespace App\\Http\\Controllers;\n\ntrait AuthorizesRequests\n{\n    public function tagRequest(): void {}\n}\n",
    ];

    $findings = idorPrecisionScan($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->not->toContain('add $this->authorize(')
        ->and($findings[0]->fix)->toContain("add Gate::authorize('view', \$invoice)");
});
