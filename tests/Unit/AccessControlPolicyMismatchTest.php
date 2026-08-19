<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\AccessControl\PolicyRouteMismatchDetector;
use Mahdi\HackAuditor\Scanner\AccessControl\SourceFile;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\Confidence;
use Mahdi\HackAuditor\Support\FindingClass;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * PolicyRouteMismatchDetector.
 *
 * The detector answers one question in one of THREE ways: silence, a review
 * question, or a proven vulnerability.
 *
 *  - silence            — authorization is visible somewhere it can read, the
 *                         policy declares no such ability, or the action is not
 *                         routed at all.
 *  - class: review      — the ability is declared and no check is visible, but
 *                         the negative is NOT proven (the route table, a parent
 *                         controller, a trait or an injected class could not be
 *                         read). Phrased as a question, carries NO fix.
 *  - class: vulnerability — every link is resolved: the route is known and its
 *                         middleware authorises nothing, the ancestry and
 *                         traits are readable and apply nothing, the method and
 *                         its same-class helpers call nothing, no form request
 *                         authorises. Only here may a fix be written.
 *
 * The "(FP-n)" tests encode false positives a real application received. The
 * "(D-1)" tests encode the destructive advice that would 403 every DELETE.
 */

/**
 * @param  array<int, array{path: string, content: string, type: string}>  $files
 * @return array<int, Vulnerability>
 */
function runPolicyDetector(array $files, AccessControlContext $context): array
{
    $detector = new PolicyRouteMismatchDetector;
    $sources = array_map(fn (array $f): SourceFile => SourceFile::fromArray($f), $files);

    return $detector->detect($sources, $context);
}

/**
 * A PostController wrapping the given method bodies.
 *
 * @return array<int, array{path: string, content: string, type: string}>
 */
function policyController(string $methods): array
{
    return [[
        'path' => 'app/Http/Controllers/PostController.php',
        'type' => 'controller',
        'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Post;\nuse Illuminate\\Http\\Request;\nclass PostController\n{\n{$methods}\n}\n",
    ]];
}

/**
 * A policy source file, so the detector can read the abilities itself rather
 * than being told what they are.
 *
 * @param  array<int, string>  $abilities
 * @return array{path: string, content: string, type: string}
 */
function policySource(string $model, array $abilities): array
{
    $methods = '';

    foreach ($abilities as $ability) {
        $methods .= "    public function {$ability}(\$user, \$subject): bool { return true; }\n";
    }

    return [
        'path' => "app/Policies/{$model}Policy.php",
        'type' => 'other',
        'content' => "<?php\nnamespace App\\Policies;\nuse App\\Models\\{$model};\nclass {$model}Policy\n{\n{$methods}}\n",
    ];
}

/**
 * A resolved route table: "Controller@method" => the middleware the router
 * actually reports for it.
 *
 * A KNOWN middleware stack is what turns "no authorization is visible" into
 * "no authorization runs". Without it the detector may only ask a question.
 *
 * @param  array<string, array<int, string>>  $map
 * @return array<string, array{route: string, middleware: array<int, string>}>
 */
function policyRoutes(array $map): array
{
    $routes = [];

    foreach ($map as $key => $middleware) {
        [$class, $method] = explode('@', $key);

        $routes["App\\Http\\Controllers\\{$class}@{$method}"] = [
            'route' => 'POST /'.strtolower($class).'/{id}',
            'middleware' => $middleware,
        ];
    }

    return $routes;
}

/**
 * The context a scanner builds once it has read app/Policies.
 *
 * @param  array<string, array<int, string>>  $abilities
 * @param  array<string, array{route: string, middleware: array<int, string>}>  $routedMethods
 */
function policyContext(array $abilities, array $routedMethods = []): AccessControlContext
{
    return new AccessControlContext(
        routedMethods: $routedMethods,
        modelsWithPolicy: array_keys($abilities),
        policyAbilities: $abilities,
    );
}

// ---------------------------------------------------------------------------
// D-1 — THE CLOSURE-SCOPE BUG THAT 403'd EVERY DELETE.
// ---------------------------------------------------------------------------

/**
 * The exact shape that produced the destructive advice: $contract exists only
 * inside the transaction closure, and the authorization runs in there too,
 * through a private guard helper.
 *
 * @return array<int, array{path: string, content: string, type: string}>
 */
function contractControllerGuardedInsideTransaction(): array
{
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\Contract;
    use Illuminate\Support\Facades\DB;
    use Illuminate\Support\Facades\Gate;

    class ContractController
    {
        public function destroy(int $id)
        {
            return DB::transaction(function () use ($id) {
                $contract = Contract::findOrFail($id);

                $this->guardContract($contract);

                $contract->delete();

                return response()->noContent();
            });
        }

        private function guardContract(Contract $contract): void
        {
            Gate::authorize('delete', $contract);
        }
    }
    PHP;

    return [[
        'path' => 'app/Http/Controllers/ContractController.php',
        'type' => 'controller',
        'content' => $content,
    ]];
}

/**
 * The same shape with the guard removed, so a finding IS legitimate — and the
 * advice that ships with it must still never name $contract.
 *
 * @return array<int, array{path: string, content: string, type: string}>
 */
function contractControllerUnguarded(): array
{
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\Contract;
    use Illuminate\Support\Facades\DB;

    class ContractController
    {
        public function destroy(int $id)
        {
            return DB::transaction(function () use ($id) {
                $contract = Contract::findOrFail($id);

                $contract->delete();

                return response()->noContent();
            });
        }
    }
    PHP;

    return [[
        'path' => 'app/Http/Controllers/ContractController.php',
        'type' => 'controller',
        'content' => $content,
    ]];
}

it('does NOT flag a controller that authorises inside its transaction closure (D-1)', function (): void {
    $context = policyContext(
        ['Contract' => ['view', 'create', 'update', 'delete']],
        policyRoutes(['ContractController@destroy' => ['web', 'auth']]),
    );

    expect(runPolicyDetector(contractControllerGuardedInsideTransaction(), $context))->toBeEmpty();
});

it('never names a variable that exists only inside a closure (D-1)', function (): void {
    $context = policyContext(
        ['Contract' => ['view', 'create', 'update', 'delete']],
        policyRoutes(['ContractController@destroy' => ['web', 'auth']]),
    );

    $findings = runPolicyDetector(contractControllerUnguarded(), $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->findingClass)->toBe(FindingClass::Vulnerability)
        ->and($findings[0]->confidence)->toBe(Confidence::Proven)
        // The killer assertion: $contract is assigned inside the transaction
        // closure, so it is NOT in scope at the top of destroy(). Advising
        // $this->authorize('delete', $contract) there yields
        // Gate::authorize('delete', null) and a 403 on every delete.
        ->and($findings[0]->fix)->not->toContain('$contract')
        ->and($findings[0]->fix)->not->toContain('authorize(')
        ->and($findings[0]->proof)->not->toContain('$contract')
        ->and($findings[0]->description)->not->toContain('$contract')
        ->and($findings[0]->fix)->toContain('delete');
});

it('does NOT treat a closure-scoped assignment as a method-scope binding', function (): void {
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\Post;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\DB;

    class PostController
    {
        public function update(Request $request, int $id)
        {
            DB::transaction(function () use ($request, $id) {
                $post = Post::findOrFail($id);
                $post->update($request->all());
            });
        }
    }
    PHP;

    $files = [['path' => 'app/Http/Controllers/PostController.php', 'type' => 'controller', 'content' => $content]];

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => ['web']]),
    );

    $findings = runPolicyDetector($files, $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->not->toContain('$post');
});

// ---------------------------------------------------------------------------
// D-3 — CONDITIONAL BINDINGS: D-1'S 403, REACHED THROUGH A DIFFERENT CONSTRUCT.
// ---------------------------------------------------------------------------

/**
 * Scope-awareness stopped the closure case and nothing else. try/catch, match
 * arms, switch cases, loop bodies and if branches open NO scope in PHP, so a
 * variable bound inside one of them is in the method's own scope and still
 * undefined on the paths that skip the binding. Advice naming it inserts
 * `$this->authorize('delete', null)`, which throws AuthorizationException — a
 * 403 on exactly the requests that were supposed to succeed.
 *
 * Every fixture below is a proven vulnerability, so a fix IS emitted; the
 * assertion is on what that fix may say.
 *
 * @param  array<int, Vulnerability>  $findings
 */
function expectNoVariableAdvice(array $findings, string $variable): void
{
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->findingClass)->toBe(FindingClass::Vulnerability)
        ->and($findings[0]->confidence)->toBe(Confidence::Proven)
        ->and($findings[0]->fix)->not->toContain($variable)
        ->and($findings[0]->fix)->not->toContain('authorize(')
        ->and($findings[0]->fix)->toContain('delete');
}

/**
 * The context these fixtures share: Post has a policy declaring `delete`, and
 * PostController@destroy is routed behind authentication only.
 */
function conditionalBindingContext(): AccessControlContext
{
    return policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@destroy' => ['web', 'auth']]),
    );
}

it('never names a variable bound only inside a catch block (D-3)', function (): void {
    // The original incident, reproduced without a closure: on the happy path
    // the catch never runs and $post was never assigned.
    $method = <<<'PHP'
        public function destroy($id)
        {
            try {
                Post::where('id', $id)->delete();
            } catch (\Throwable $e) {
                $post = Post::withTrashed()->findOrFail($id);
                $post->forceDelete();
            }

            return response()->noContent();
        }
    PHP;

    $findings = runPolicyDetector(policyController($method), conditionalBindingContext());

    expectNoVariableAdvice($findings, '$post');
    expect($findings[0]->fix)->toContain('only some of its paths');
});

it('never names a variable bound only in some match arms (D-3)', function (): void {
    // `default => null` binds nothing, so any other mode reaches the end of the
    // method with $post undefined.
    $method = <<<'PHP'
        public function destroy(Request $request, $id)
        {
            match ($request->input('mode')) {
                'soft' => $post = Post::findOrFail($id),
                'hard' => $post = Post::withTrashed()->findOrFail($id),
                default => null,
            };

            return response()->noContent();
        }
    PHP;

    expectNoVariableAdvice(
        runPolicyDetector(policyController($method), conditionalBindingContext()),
        '$post',
    );
});

it('never names a variable bound only inside a foreach body (D-3)', function (): void {
    // An empty ids array leaves the loop body unexecuted and $post undefined.
    $method = <<<'PHP'
        public function destroy(Request $request)
        {
            foreach ($request->input('ids', []) as $id) {
                $post = Post::findOrFail($id);
                $post->delete();
            }

            return response()->noContent();
        }
    PHP;

    expectNoVariableAdvice(
        runPolicyDetector(policyController($method), conditionalBindingContext()),
        '$post',
    );
});

it('never names a variable bound in an if with no else (D-3)', function (): void {
    $method = <<<'PHP'
        public function destroy(Request $request, $id)
        {
            if ($request->boolean('confirm')) {
                $post = Post::findOrFail($id);
                $post->delete();
            }

            return response()->noContent();
        }
    PHP;

    expectNoVariableAdvice(
        runPolicyDetector(policyController($method), conditionalBindingContext()),
        '$post',
    );
});

it('never names a variable bound in an if/else where only one branch binds it (D-3)', function (): void {
    $method = <<<'PHP'
        public function destroy(Request $request, $id)
        {
            if ($request->boolean('confirm')) {
                $post = Post::findOrFail($id);
                $post->delete();
            } else {
                Post::where('id', $id)->update(['flagged' => true]);
            }

            return response()->noContent();
        }
    PHP;

    expectNoVariableAdvice(
        runPolicyDetector(policyController($method), conditionalBindingContext()),
        '$post',
    );
});

it('never names a variable bound in a ternary limb (D-3)', function (): void {
    $method = <<<'PHP'
        public function destroy(Request $request, $id)
        {
            $result = $request->boolean('confirm') ? $post = Post::findOrFail($id) : null;

            return response()->json($result);
        }
    PHP;

    expectNoVariableAdvice(
        runPolicyDetector(policyController($method), conditionalBindingContext()),
        '$post',
    );
});

it('never names a variable bound on the right of a null coalesce (D-3)', function (): void {
    $method = <<<'PHP'
        public function destroy(Request $request, $id)
        {
            $result = $request->input('cached') ?? $post = Post::findOrFail($id);

            return response()->json($result);
        }
    PHP;

    expectNoVariableAdvice(
        runPolicyDetector(policyController($method), conditionalBindingContext()),
        '$post',
    );
});

it('says the method binds the record conditionally, not that it never binds it (D-3)', function (): void {
    // The refusal has to be TRUE. "never binds the Post instance" is false of a
    // method whose catch block binds it; the reason no call can be written is
    // that the binding does not hold on every path.
    $method = <<<'PHP'
        public function destroy($id)
        {
            try {
                Post::where('id', $id)->delete();
            } catch (\Throwable $e) {
                $post = Post::withTrashed()->findOrFail($id);
            }

            return response()->noContent();
        }
    PHP;

    $findings = runPolicyDetector(policyController($method), conditionalBindingContext());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain('only some of its paths')
        ->and($findings[0]->fix)->not->toContain('never binds');
});

it('STILL names a variable assigned unconditionally at the top of the method (D-3)', function (): void {
    // The guard must refuse conditional bindings, not all bindings. Without
    // this the detector would have "fixed" the destructive advice by never
    // giving any advice at all.
    $method = <<<'PHP'
        public function destroy($id)
        {
            $post = Post::findOrFail($id);

            $post->delete();

            return response()->noContent();
        }
    PHP;

    $findings = runPolicyDetector(policyController($method), conditionalBindingContext());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain("authorize('delete', \$post)");
});

it('names a variable every branch of an if/else binds (D-3)', function (): void {
    $method = <<<'PHP'
        public function destroy(Request $request, $id)
        {
            if ($request->boolean('trashed')) {
                $post = Post::withTrashed()->findOrFail($id);
            } else {
                $post = Post::findOrFail($id);
            }

            $post->delete();

            return response()->noContent();
        }
    PHP;

    $findings = runPolicyDetector(policyController($method), conditionalBindingContext());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain("authorize('delete', \$post)");
});

// ---------------------------------------------------------------------------
// AUTHORIZATION THE OLD IMPLEMENTATION COULD NOT SEE.
// ---------------------------------------------------------------------------

it('does NOT flag when a private guard helper of the same class authorises', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            $this->assertOwns($post);
            $post->update($request->all());
            return $post;
        }

        private function assertOwns(Post $post): void
        {
            abort_unless($post->user_id === auth()->id(), 403);
        }
    PHP;

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => ['web']]),
    );

    expect(runPolicyDetector(policyController($method), $context))->toBeEmpty();
});

it('does NOT flag when a guard helper is reached through self::', function (): void {
    $method = <<<'PHP'
        public function destroy($id)
        {
            $post = Post::findOrFail($id);
            self::guard($post);
            $post->delete();
        }

        protected static function guard(Post $post): void
        {
            \Illuminate\Support\Facades\Gate::authorize('delete', $post);
        }
    PHP;

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@destroy' => ['web']]),
    );

    expect(runPolicyDetector(policyController($method), $context))->toBeEmpty();
});

it('does NOT flag when a parent controller in the scan calls authorizeResource', function (): void {
    $files = [
        [
            'path' => 'app/Http/Controllers/BaseController.php',
            'type' => 'controller',
            'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Post;\nuse Illuminate\\Http\\Request;\n".
                "class BaseController\n{\n    public function __construct() { \$this->authorizeResource(Post::class, 'post'); }\n}\n",
        ],
        [
            'path' => 'app/Http/Controllers/PostController.php',
            'type' => 'controller',
            'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Post;\nuse Illuminate\\Http\\Request;\n".
                "class PostController extends BaseController\n{\n".
                "    public function update(Request \$request, \$id)\n    {\n        \$post = Post::findOrFail(\$id);\n        \$post->update(\$request->all());\n        return \$post;\n    }\n}\n",
        ],
    ];

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => ['web']]),
    );

    expect(runPolicyDetector($files, $context))->toBeEmpty();
});

it('does NOT flag when a trait the controller uses registers authorization middleware', function (): void {
    $files = [
        [
            'path' => 'app/Http/Controllers/Concerns/GuardsPosts.php',
            'type' => 'other',
            'content' => "<?php\nnamespace App\\Http\\Controllers\\Concerns;\n".
                "trait GuardsPosts\n{\n    public function __construct() { \$this->middleware('can:update,post'); }\n}\n",
        ],
        [
            'path' => 'app/Http/Controllers/PostController.php',
            'type' => 'controller',
            'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Http\\Controllers\\Concerns\\GuardsPosts;\nuse App\\Models\\Post;\nuse Illuminate\\Http\\Request;\n".
                "class PostController\n{\n    use GuardsPosts;\n".
                "    public function update(Request \$request, \$id)\n    {\n        \$post = Post::findOrFail(\$id);\n        \$post->update(\$request->all());\n        return \$post;\n    }\n}\n",
        ],
    ];

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => ['web']]),
    );

    expect(runPolicyDetector($files, $context))->toBeEmpty();
});

it('does NOT flag an action the resolved route table never reaches', function (): void {
    $method = <<<'PHP'
        public function index()
        {
            return Post::all();
        }

        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            $post->update($request->all());
            return $post;
        }
    PHP;

    // The router knows PostController — but only its index route. update() is
    // not bound to any route, so it is not an access-control gap.
    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@index' => ['web']]),
    );

    expect(runPolicyDetector(policyController($method), $context))->toBeEmpty();
});

// ---------------------------------------------------------------------------
// CLASSIFICATION — review is the default, vulnerability must be earned.
// ---------------------------------------------------------------------------

it('emits a review question, not an assertion, when the route table is unknown', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            $post->update($request->all());
            return $post;
        }
    PHP;

    // No routedMethods at all: the middleware stack for this action was never
    // read, so "no authorization runs" cannot be proven.
    $findings = runPolicyDetector(policyController($method), policyContext(['Post' => ['view', 'update', 'delete']]));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->findingClass)->toBe(FindingClass::Review)
        ->and($findings[0]->confidence)->toBe(Confidence::Possible)
        ->and($findings[0]->mayCarryFix())->toBeFalse()
        ->and($findings[0]->description)->toStartWith('Review: ')
        ->and($findings[0]->description)->toEndWith('?')
        ->and($findings[0]->fix)->toBe('')
        ->and($findings[0]->proof)->toContain('not evidence');
});

it('emits a proven vulnerability once the route and its middleware are resolved', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            $post->update($request->all());
            return $post;
        }
    PHP;

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => ['web', 'auth']]),
    );

    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->findingClass)->toBe(FindingClass::Vulnerability)
        ->and($findings[0]->confidence)->toBe(Confidence::Proven)
        ->and($findings[0]->mayCarryFix())->toBeTrue()
        ->and($findings[0]->description)->not->toStartWith('Review: ')
        ->and($findings[0]->fix)->toContain("authorize('update', \$post)")
        ->and($findings[0]->proof)->toContain('web, auth');
});

it('stays a review when the route is resolved but its middleware stack is not', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            $post->update($request->all());
            return $post;
        }
    PHP;

    // An empty middleware list is what a FAILED lookup also looks like, so it
    // is unknown, not empty.
    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => []]),
    );

    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->findingClass)->toBe(FindingClass::Review)
        ->and($findings[0]->fix)->toBe('');
});

it('stays a review when the controller extends a base class outside the scan', function (): void {
    $content = "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Post;\nuse Vendor\\Package\\ResourceController;\n".
        "class PostController extends ResourceController\n{\n".
        "    public function update(Request \$request, \$id)\n    {\n        \$post = Post::findOrFail(\$id);\n        \$post->update(\$request->all());\n        return \$post;\n    }\n}\n";

    $files = [['path' => 'app/Http/Controllers/PostController.php', 'type' => 'controller', 'content' => $content]];

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => ['web']]),
    );

    $findings = runPolicyDetector($files, $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->findingClass)->toBe(FindingClass::Review)
        ->and($findings[0]->fix)->toBe('')
        ->and($findings[0]->description)->toContain('outside this scan');
});

it('names the injected request class in the review question only when it resolved it', function (): void {
    $files = [
        [
            'path' => 'app/Http/Controllers/PostController.php',
            'type' => 'controller',
            'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Http\\Requests\\UpdatePostRequest;\nuse App\\Models\\Post;\nuse Illuminate\\Http\\Request;\n".
                "class PostController\n{\n".
                "    public function update(UpdatePostRequest \$request, \$id)\n    {\n        \$post = Post::findOrFail(\$id);\n        \$post->update(\$request->validated());\n        return \$post;\n    }\n}\n",
        ],
        [
            'path' => 'app/Http/Requests/UpdatePostRequest.php',
            'type' => 'other',
            'content' => "<?php\nnamespace App\\Http\\Requests;\nuse Illuminate\\Foundation\\Http\\FormRequest;\n".
                "class UpdatePostRequest extends FormRequest\n{\n    public function authorize(): bool { return true; }\n}\n",
        ],
    ];

    $findings = runPolicyDetector($files, policyContext(['Post' => ['view', 'update', 'delete']]));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->findingClass)->toBe(FindingClass::Review)
        ->and($findings[0]->description)->toContain('UpdatePostRequest::authorize()');
});

it('never invents a policy class name it did not resolve (D-2)', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            $post->update($request->all());
            return $post;
        }
    PHP;

    // The ability list was introspected off disk; the class that declared it
    // may be ContractAccessPolicy registered through Gate::policy(). Naming
    // "PostPolicy" would name a class that need not exist.
    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => ['web']]),
    );

    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->description)->not->toContain('PostPolicy')
        ->and($findings[0]->proof)->not->toContain('PostPolicy')
        ->and($findings[0]->fix)->not->toContain('PostPolicy')
        ->and($findings[0]->proof)->toContain('the policy registered for Post');
});

// ---------------------------------------------------------------------------
// TRUE POSITIVES — the ability is declared and provably never applied.
// ---------------------------------------------------------------------------

it('flags an update action when the Post policy declares update but never applies it', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            $post->update($request->all());
            return $post;
        }
    PHP;

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => ['web']]),
    );

    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::AuthBypass)
        ->and($findings[0]->severity)->toBe(SeverityLevel::High)
        ->and($findings[0]->description)->toContain('Post')
        ->and($findings[0]->description)->toContain('update');
});

it('reads the declared abilities from the Policy source when it is part of the scan', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            $post->update($request->all());
            return $post;
        }
    PHP;

    $files = [...policyController($method), policySource('Post', ['view', 'update', 'delete'])];

    // No ability data in the context at all: the Policy is read from its own AST.
    $context = new AccessControlContext(routedMethods: policyRoutes(['PostController@update' => ['web']]));
    $findings = runPolicyDetector($files, $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->proof)->toContain('PostPolicy::update()')
        ->and($findings[0]->proof)->toContain('app/Policies/PostPolicy.php');
});

it('flags a destroy action when the policy declares delete and no guard runs', function (): void {
    $method = <<<'PHP'
        public function destroy($id)
        {
            Post::destroy($id);
            return response()->noContent();
        }
    PHP;

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@destroy' => ['web']]),
    );

    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->description)->toContain('delete');
});

it('attributes to the controller-resource model when several models are touched (M4)', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $author = Author::find($request->author_id);
            $post = Post::findOrFail($id);
            $post->update($request->all());
            return $post;
        }
    PHP;

    $context = policyContext(
        [
            'Post' => ['view', 'update', 'delete'],
            'Author' => ['view', 'update'],
        ],
        policyRoutes(['PostController@update' => ['web']]),
    );

    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->description)->toContain('Post')
        ->and($findings[0]->proof)->toContain('Post');
});

it('does NOT flag when attribution is ambiguous across two policied non-resource models (M4)', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $tag = Tag::find($request->tag_id);
            $category = Category::findOrFail($id);
            $tag->update($request->all());
            return $category;
        }
    PHP;

    $context = policyContext(
        [
            'Tag' => ['view', 'update'],
            'Category' => ['view', 'update'],
        ],
        policyRoutes(['PostController@update' => ['web']]),
    );

    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toBeEmpty();
});

it('attributes to the single ability-declaring model when only one of several has the ability (M4)', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $tag = Tag::find($request->tag_id);
            $category = Category::findOrFail($id);
            $category->update($request->all());
            return $category;
        }
    PHP;

    $context = policyContext(
        ['Category' => ['view', 'update']],
        policyRoutes(['PostController@update' => ['web']]),
    );

    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->description)->toContain('Category');
});

// ---------------------------------------------------------------------------
// FP-1 / FP-2 / FP-3 — a Policy exists, but NOT the ability the action needs.
// ---------------------------------------------------------------------------

/**
 * The verbatim ability list of the RoomPolicy that produced three false
 * "Authentication Bypass" findings. There is no store and no create.
 *
 * @return array<int, string>
 */
function roomPolicyAbilities(): array
{
    return [
        'view', 'update', 'delete', 'manageImage', 'managePassword',
        'manageTriggers', 'manageWebhooks', 'manageMembers', 'viewPrivateLocation',
    ];
}

it('does NOT flag store() when the policy declares no create ability (FP-1)', function (): void {
    $controller = [[
        'path' => 'app/Http/Controllers/RoomController.php',
        'type' => 'controller',
        'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Room;\nuse Illuminate\\Http\\Request;\n".
            "class RoomController\n{\n".
            "    public function store(Request \$request)\n    {\n".
            "        \$room = Room::create(\$request->all());\n".
            "        return \$room;\n    }\n}\n",
    ]];

    $context = policyContext(
        ['Room' => roomPolicyAbilities()],
        policyRoutes(['RoomController@store' => ['web']]),
    );

    expect(runPolicyDetector($controller, $context))->toBeEmpty();
});

it('does NOT flag joining a room by invite code (FP-2)', function (): void {
    $controller = [[
        'path' => 'app/Http/Controllers/RoomMemberController.php',
        'type' => 'controller',
        'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Room;\nuse Illuminate\\Http\\Request;\n".
            "class RoomMemberController\n{\n".
            "    public function store(Request \$request)\n    {\n".
            "        \$room = Room::where('invite_code', \$request->input('code'))->firstOrFail();\n".
            "        \$room->members()->syncWithoutDetaching([\$request->user()->id]);\n    }\n}\n",
    ]];

    $context = policyContext(
        ['Room' => roomPolicyAbilities()],
        policyRoutes(['RoomMemberController@store' => ['web']]),
    );

    expect(runPolicyDetector($controller, $context))->toBeEmpty();
});

it('does NOT flag reporting a room for abuse (FP-3)', function (): void {
    $controller = [[
        'path' => 'app/Http/Controllers/RoomReportController.php',
        'type' => 'controller',
        'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Room;\nuse Illuminate\\Http\\Request;\n".
            "class RoomReportController\n{\n".
            "    public function store(Request \$request)\n    {\n".
            "        \$room = Room::findOrFail(\$request->input('room_id'));\n".
            "        \$room->reports()->create(['reason' => \$request->input('reason')]);\n    }\n}\n",
    ]];

    $context = policyContext(
        ['Room' => roomPolicyAbilities()],
        policyRoutes(['RoomReportController@store' => ['web']]),
    );

    expect(runPolicyDetector($controller, $context))->toBeEmpty();
});

it('does NOT flag when a Policy class exists but its abilities were never read', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            $post->update($request->all());
            return $post;
        }
    PHP;

    // The old context shape: "a Policy exists" and nothing more. Not evidence.
    $context = new AccessControlContext(
        routedMethods: policyRoutes(['PostController@update' => ['web']]),
        modelsWithPolicy: ['Post'],
    );

    expect(runPolicyDetector(policyController($method), $context))->toBeEmpty();
});

it('does NOT flag when the policy declares update but the action is a store', function (): void {
    $controller = [[
        'path' => 'app/Http/Controllers/RoomController.php',
        'type' => 'controller',
        'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Room;\nuse Illuminate\\Http\\Request;\n".
            "class RoomController\n{\n".
            "    public function store(Request \$request)\n    {\n".
            "        return Room::create(\$request->all());\n    }\n}\n",
    ]];

    // update/delete exist; create does not. store() maps to create, not store.
    $context = policyContext(
        ['Room' => ['view', 'update', 'delete']],
        policyRoutes(['RoomController@store' => ['web']]),
    );

    expect(runPolicyDetector($controller, $context))->toBeEmpty();
});

// ---------------------------------------------------------------------------
// THE ADVICE MUST NEVER BREAK THE APPLICATION.
// ---------------------------------------------------------------------------

it('never advises an ability the policy does not declare', function (): void {
    $files = [
        [
            'path' => 'app/Http/Controllers/RoomController.php',
            'type' => 'controller',
            'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Room;\nuse Illuminate\\Http\\Request;\n".
                "class RoomController\n{\n".
                "    public function store(Request \$request)\n    {\n        return Room::create(\$request->all());\n    }\n".
                "    public function update(Request \$request, \$id)\n    {\n        \$room = Room::findOrFail(\$id);\n        \$room->update(\$request->all());\n        return \$room;\n    }\n}\n",
        ],
        policySource('Room', roomPolicyAbilities()),
    ];

    $declared = roomPolicyAbilities();
    $context = new AccessControlContext(routedMethods: policyRoutes([
        'RoomController@store' => ['web'],
        'RoomController@update' => ['web'],
    ]));

    foreach (runPolicyDetector($files, $context) as $finding) {
        preg_match_all("/authorize\(\s*'(\w+)'/", $finding->fix, $matches);

        foreach ($matches[1] as $ability) {
            expect($declared)->toContain($ability);
        }
    }
});

it('never synthesises an authorize() call for a create action, where no instance exists', function (): void {
    $controller = [[
        'path' => 'app/Http/Controllers/RoomController.php',
        'type' => 'controller',
        'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Room;\nuse Illuminate\\Http\\Request;\n".
            "class RoomController\n{\n".
            "    public function store(Request \$request)\n    {\n        return Room::create(\$request->all());\n    }\n}\n",
    ]];

    // This time the policy DOES declare create, so a finding is legitimate —
    // but the advice must not reference a $room that does not exist yet.
    $context = policyContext(
        ['Room' => ['view', 'create', 'update', 'delete']],
        policyRoutes(['RoomController@store' => ['web']]),
    );

    $findings = runPolicyDetector($controller, $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain("authorize('create', Room::class)")
        ->and($findings[0]->fix)->not->toContain('$room');
});

it('describes the gap instead of naming a variable that is not in scope', function (): void {
    $method = <<<'PHP'
        public function destroy($id)
        {
            Post::destroy($id);
            return response()->noContent();
        }
    PHP;

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@destroy' => ['web']]),
    );

    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->not->toContain('authorize(')
        ->and($findings[0]->fix)->toContain('delete');
});

it('names only a variable the method really binds', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $existing = Post::findOrFail($id);
            $existing->update($request->all());
            return $existing;
        }
    PHP;

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => ['web']]),
    );

    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain("authorize('update', \$existing)")
        ->and($findings[0]->fix)->not->toContain('$post');
});

it('does not mistake a collection query for a single model instance', function (): void {
    $method = <<<'PHP'
        public function destroy(Request $request)
        {
            $posts = Post::where('author_id', $request->input('author'))->get();
            foreach ($posts as $post) {
                $post->delete();
            }
        }
    PHP;

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@destroy' => ['web']]),
    );

    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->not->toContain('$posts');
});

// ---------------------------------------------------------------------------
// LINE PRECISION — from the AST, never from a byte offset.
// ---------------------------------------------------------------------------

it('reports the line of the function keyword, not the docblock above it', function (): void {
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\Post;
    use Illuminate\Http\Request;

    class PostController
    {
        /**
         * Update a post.
         *
         * @param  string  $label  Display label, e.g. "draft (pending)"
         */
        public function update(
            Request $request,
            string $label = 'draft (pending)',
        ) {
            $post = Post::findOrFail($request->input('id'));
            $post->update($request->all());

            return $post;
        }
    }
    PHP;

    $files = [['path' => 'app/Http/Controllers/PostController.php', 'type' => 'controller', 'content' => $content]];

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => ['web']]),
    );

    $findings = runPolicyDetector($files, $context);

    $lines = explode("\n", $content);

    expect($findings)->toHaveCount(1)
        ->and($lines[$findings[0]->line - 1])->toContain('public function update(');
});

// ---------------------------------------------------------------------------
// EVERY AUTHORIZATION PATH MUST SUPPRESS THE FINDING.
// ---------------------------------------------------------------------------

it('does NOT flag when the method calls $this->authorize', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            $this->authorize('update', $post);
            $post->update($request->all());
            return $post;
        }
    PHP;

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => ['web']]),
    );

    expect(runPolicyDetector(policyController($method), $context))->toBeEmpty();
});

it('does NOT flag when the method calls Gate::authorize', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            \Illuminate\Support\Facades\Gate::authorize('update', $post);
            $post->update($request->all());
            return $post;
        }
    PHP;

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => ['web']]),
    );

    expect(runPolicyDetector(policyController($method), $context))->toBeEmpty();
});

it('does NOT flag when the method calls $user->cannot()', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            if ($request->user()->cannot('update', $post)) {
                abort(403);
            }
            $post->update($request->all());
            return $post;
        }
    PHP;

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => ['web']]),
    );

    expect(runPolicyDetector(policyController($method), $context))->toBeEmpty();
});

it('does NOT flag when the authorization call is inside a closure', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            DB::transaction(function () use ($post, $request) {
                $this->authorize('update', $post);
                $post->update($request->all());
            });
            return $post;
        }
    PHP;

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => ['web']]),
    );

    expect(runPolicyDetector(policyController($method), $context))->toBeEmpty();
});

it('does NOT flag when the controller uses authorizeResource', function (): void {
    $controller = [[
        'path' => 'app/Http/Controllers/PostController.php',
        'type' => 'controller',
        'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Post;\nuse Illuminate\\Http\\Request;\n".
            "class PostController\n{\n".
            "    public function __construct() { \$this->authorizeResource(Post::class, 'post'); }\n".
            "    public function update(Request \$request, \$id)\n    {\n        \$post = Post::findOrFail(\$id);\n        \$post->update(\$request->all());\n        return \$post;\n    }\n}\n",
    ]];

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => ['web']]),
    );

    expect(runPolicyDetector($controller, $context))->toBeEmpty();
});

it('does NOT flag when the constructor registers can: middleware', function (): void {
    $controller = [[
        'path' => 'app/Http/Controllers/PostController.php',
        'type' => 'controller',
        'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Post;\nuse Illuminate\\Http\\Request;\n".
            "class PostController\n{\n".
            "    public function __construct() { \$this->middleware('can:update,post')->only('update'); }\n".
            "    public function update(Request \$request, \$id)\n    {\n        \$post = Post::findOrFail(\$id);\n        \$post->update(\$request->all());\n        return \$post;\n    }\n}\n",
    ]];

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => ['web']]),
    );

    expect(runPolicyDetector($controller, $context))->toBeEmpty();
});

it('does NOT flag when an injected form request implements authorize()', function (): void {
    $files = [
        [
            'path' => 'app/Http/Controllers/PostController.php',
            'type' => 'controller',
            'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Http\\Requests\\UpdatePostRequest;\nuse App\\Models\\Post;\nuse Illuminate\\Http\\Request;\n".
                "class PostController\n{\n".
                "    public function update(UpdatePostRequest \$request, \$id)\n    {\n        \$post = Post::findOrFail(\$id);\n        \$post->update(\$request->validated());\n        return \$post;\n    }\n}\n",
        ],
        [
            'path' => 'app/Http/Requests/UpdatePostRequest.php',
            'type' => 'other',
            'content' => "<?php\nnamespace App\\Http\\Requests;\nuse Illuminate\\Foundation\\Http\\FormRequest;\n".
                "class UpdatePostRequest extends FormRequest\n{\n".
                "    public function authorize(): bool { return \$this->user()?->owns(\$this->route('post')) === true; }\n}\n",
        ],
    ];

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => ['web']]),
    );

    expect(runPolicyDetector($files, $context))->toBeEmpty();
});

it('still flags when the injected form request authorize() is the scaffold `return true`', function (): void {
    $files = [
        [
            'path' => 'app/Http/Controllers/PostController.php',
            'type' => 'controller',
            'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Http\\Requests\\UpdatePostRequest;\nuse App\\Models\\Post;\nuse Illuminate\\Http\\Request;\n".
                "class PostController\n{\n".
                "    public function update(UpdatePostRequest \$request, \$id)\n    {\n        \$post = Post::findOrFail(\$id);\n        \$post->update(\$request->validated());\n        return \$post;\n    }\n}\n",
        ],
        [
            'path' => 'app/Http/Requests/UpdatePostRequest.php',
            'type' => 'other',
            'content' => "<?php\nnamespace App\\Http\\Requests;\nuse Illuminate\\Foundation\\Http\\FormRequest;\n".
                "class UpdatePostRequest extends FormRequest\n{\n".
                "    public function authorize(): bool { return true; }\n}\n",
        ],
    ];

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        policyRoutes(['PostController@update' => ['web']]),
    );

    $findings = runPolicyDetector($files, $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->findingClass)->toBe(FindingClass::Vulnerability);
});

it('does NOT flag when the route carries can: middleware', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            $post->update($request->all());
            return $post;
        }
    PHP;

    $context = policyContext(
        ['Post' => ['view', 'update', 'delete']],
        ['PostController@update' => ['route' => 'PUT /posts/{post}', 'middleware' => ['web', 'auth', 'can:update,post']]],
    );

    expect(runPolicyDetector(policyController($method), $context))->toBeEmpty();
});

// ---------------------------------------------------------------------------
// SCOPE.
// ---------------------------------------------------------------------------

it('does NOT flag non-sensitive read actions', function (): void {
    $method = <<<'PHP'
        public function index()
        {
            return Post::all();
        }
    PHP;

    $context = policyContext(
        ['Post' => ['viewAny', 'view', 'update']],
        policyRoutes(['PostController@index' => ['web']]),
    );

    expect(runPolicyDetector(policyController($method), $context))->toBeEmpty();
});

it('does NOT flag when no policy exists for the model', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            $post->update($request->all());
            return $post;
        }
    PHP;

    $context = new AccessControlContext(
        routedMethods: policyRoutes(['PostController@update' => ['web']]),
        modelsWithPolicy: [],
    );

    expect(runPolicyDetector(policyController($method), $context))->toBeEmpty();
});

it('does NOT flag a Policy class itself, whose methods are named update and delete', function (): void {
    $files = [policySource('Post', ['view', 'update', 'delete'])];

    expect(runPolicyDetector($files, policyContext(['Post' => ['view', 'update', 'delete']])))->toBeEmpty();
});

it('reports nothing for a file that cannot be parsed', function (): void {
    $files = [[
        'path' => 'app/Http/Controllers/BrokenController.php',
        'type' => 'controller',
        'content' => "<?php\nclass BrokenController {\n    public function update(  {{{ \n",
    ]];

    expect(runPolicyDetector($files, policyContext(['Broken' => ['update']])))->toBeEmpty();
});

// ---------------------------------------------------------------------------
// D-3 — THE RECEIVER. `$this->authorize()` NEEDS A CONTROLLER THAT HAS IT.
//
// Three emitters used to write `$this->authorize('ability', $var)` having
// proved the policy, the ability and the variable, and never the receiver.
// Since Laravel 11 `make:controller` emits `abstract class Controller {}` — no
// parent, no trait — so on a default modern application that advice produces
// `Error: Call to undefined method PostController::authorize()`: an HTTP 500
// on every request, worse than the missing check it was meant to repair.
// ---------------------------------------------------------------------------

/**
 * A PostController whose base class is SPELLED OUT, so the receiver of
 * `$this->authorize()` can be proved or disproved instead of assumed.
 *
 * @return array<int, array{path: string, content: string, type: string}>
 */
function policyReceiverFixture(string $methods, string $extends = 'Controller', ?string $baseSource = null, string $classBody = ''): array
{
    $files = [[
        'path' => 'app/Http/Controllers/PostController.php',
        'type' => 'controller',
        'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Post;\nuse Illuminate\\Http\\Request;\nclass PostController extends {$extends}\n{\n{$classBody}{$methods}\n}\n",
    ]];

    if ($baseSource !== null) {
        $files[] = [
            'path' => 'app/Http/Controllers/Controller.php',
            'type' => 'controller',
            'content' => $baseSource,
        ];
    }

    return $files;
}

/**
 * The destroy() body every receiver test below shares: one unconditional
 * binding, so the ONLY thing that can vary the advice is the receiver.
 */
function policyReceiverDestroy(): string
{
    return <<<'PHP'
        public function destroy($id)
        {
            $post = Post::findOrFail($id);

            $post->delete();

            return response()->noContent();
        }
    PHP;
}

function policyReceiverContext(): AccessControlContext
{
    return policyContext(
        ['Post' => ['view', 'create', 'update', 'delete']],
        policyRoutes(['PostController@destroy' => ['web'], 'PostController@store' => ['web']]),
    );
}

it('does NOT advise $this->authorize() on the trait-less base Laravel 11+ generates (D-3)', function (): void {
    // `abstract class Controller {}` — no parent, no trait. The literal output
    // of make:controller on a current Laravel application.
    $files = policyReceiverFixture(
        policyReceiverDestroy(),
        'Controller',
        "<?php\nnamespace App\\Http\\Controllers;\nabstract class Controller\n{\n}\n",
    );

    $findings = runPolicyDetector($files, policyReceiverContext());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->not->toContain('add $this->authorize(')
        ->and($findings[0]->fix)->toContain("add Gate::authorize('delete', \$post)")
        ->and($findings[0]->fix)->toContain('Illuminate\Support\Facades\Gate')
        ->and($findings[0]->fix)->toContain('does not have that method');
});

it('does NOT advise $this->authorize() on a base that extends Illuminate\Routing\Controller with no trait (D-3)', function (): void {
    // Illuminate\Routing\Controller has no authorize() either — its __call()
    // turns the call into a BadMethodCallException, which is still a 500.
    $files = policyReceiverFixture(
        policyReceiverDestroy(),
        'Controller',
        "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Routing\\Controller as BaseController;\nabstract class Controller extends BaseController\n{\n}\n",
    );

    $findings = runPolicyDetector($files, policyReceiverContext());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->not->toContain('add $this->authorize(')
        ->and($findings[0]->fix)->toContain("add Gate::authorize('delete', \$post)")
        ->and($findings[0]->fix)->toContain('does not have that method');
});

it('does NOT advise $this->authorize() on a controller extending Illuminate\Routing\Controller directly (D-3)', function (): void {
    $files = policyReceiverFixture(policyReceiverDestroy(), '\\Illuminate\\Routing\\Controller');

    $findings = runPolicyDetector($files, policyReceiverContext());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->not->toContain('add $this->authorize(')
        ->and($findings[0]->fix)->toContain("add Gate::authorize('delete', \$post)");
});

it('KEEPS $this->authorize() when the controller itself uses AuthorizesRequests (D-3)', function (): void {
    $files = policyReceiverFixture(
        policyReceiverDestroy(),
        'Controller',
        "<?php\nnamespace App\\Http\\Controllers;\nabstract class Controller\n{\n}\n",
        "    use \\Illuminate\\Foundation\\Auth\\Access\\AuthorizesRequests;\n",
    );

    $findings = runPolicyDetector($files, policyReceiverContext());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain("add \$this->authorize('delete', \$post)")
        ->and($findings[0]->fix)->not->toContain('Gate::authorize')
        ->and($findings[0]->fix)->not->toContain('does not have that method');
});

it('KEEPS $this->authorize() when a PARENT provides it through the trait (D-3)', function (): void {
    // The pre-Laravel-11 default base controller, which most deployed
    // applications still carry.
    $files = policyReceiverFixture(
        policyReceiverDestroy(),
        'Controller',
        "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Foundation\\Auth\\Access\\AuthorizesRequests;\nabstract class Controller\n{\n    use AuthorizesRequests;\n}\n",
    );

    $findings = runPolicyDetector($files, policyReceiverContext());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain("add \$this->authorize('delete', \$post)")
        ->and($findings[0]->fix)->not->toContain('Gate::authorize');
});

it('KEEPS $this->authorize() when an application trait carries the framework trait (D-3)', function (): void {
    // Transitive: PostController uses Authorizable, which uses
    // AuthorizesRequests. The method really is callable, so the advice stands.
    $files = policyReceiverFixture(
        policyReceiverDestroy(),
        'Controller',
        "<?php\nnamespace App\\Http\\Controllers;\nabstract class Controller\n{\n}\n",
        "    use \\App\\Support\\Authorizable;\n",
    );

    $files[] = [
        'path' => 'app/Support/Authorizable.php',
        'type' => 'other',
        'content' => "<?php\nnamespace App\\Support;\nuse Illuminate\\Foundation\\Auth\\Access\\AuthorizesRequests;\ntrait Authorizable\n{\n    use AuthorizesRequests;\n}\n",
    ];

    $findings = runPolicyDetector($files, policyReceiverContext());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain("add \$this->authorize('delete', \$post)");
});

it('KEEPS $this->authorize() when a parent declares an authorize() of its own (D-3)', function (): void {
    $files = policyReceiverFixture(
        policyReceiverDestroy(),
        'Controller',
        "<?php\nnamespace App\\Http\\Controllers;\nabstract class Controller\n{\n    public function authorize(\$ability, \$arguments = []) { return true; }\n}\n",
    );

    $findings = runPolicyDetector($files, policyReceiverContext());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain("add \$this->authorize('delete', \$post)");
});

it('does NOT advise $this->authorize() when part of the inheritance surface cannot be read (D-3)', function (): void {
    // The base carries a framework trait this scan cannot open. Everything the
    // finding itself needs is still proven, so a fix is written — but "we could
    // not read it" is not "it provides authorize()", and the fix says which
    // name it could not read rather than hedging.
    $files = policyReceiverFixture(
        policyReceiverDestroy(),
        'Controller',
        "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Foundation\\Validation\\ValidatesRequests;\nabstract class Controller\n{\n    use ValidatesRequests;\n}\n",
    );

    $findings = runPolicyDetector($files, policyReceiverContext());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->not->toContain('add $this->authorize(')
        ->and($findings[0]->fix)->toContain("add Gate::authorize('delete', \$post)")
        ->and($findings[0]->fix)->toContain('ValidatesRequests, which this scan could not read');
});

it('applies the receiver rule to class-level abilities too (D-3)', function (): void {
    $method = <<<'PHP'
        public function store(Request $request)
        {
            return Post::create($request->all());
        }
    PHP;

    $files = policyReceiverFixture(
        $method,
        'Controller',
        "<?php\nnamespace App\\Http\\Controllers;\nabstract class Controller\n{\n}\n",
    );

    $findings = runPolicyDetector($files, policyReceiverContext());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->not->toContain('add $this->authorize(')
        ->and($findings[0]->fix)->toContain("add Gate::authorize('create', Post::class)");
});

it('keeps $this->authorize() for a class-level ability on a controller that has the trait (D-3)', function (): void {
    $method = <<<'PHP'
        public function store(Request $request)
        {
            return Post::create($request->all());
        }
    PHP;

    $files = policyReceiverFixture(
        $method,
        'Controller',
        "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Foundation\\Auth\\Access\\AuthorizesRequests;\nabstract class Controller\n{\n    use AuthorizesRequests;\n}\n",
    );

    $findings = runPolicyDetector($files, policyReceiverContext());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain("add \$this->authorize('create', Post::class)");
});

it('refuses an application trait that merely shares the AuthorizesRequests name (D-3)', function (): void {
    // A readable app trait of that name proves nothing: it does not declare
    // authorize(), so the method is still missing and the advice must not
    // write it.
    $files = policyReceiverFixture(
        policyReceiverDestroy(),
        'Controller',
        "<?php\nnamespace App\\Http\\Controllers;\nabstract class Controller\n{\n    use AuthorizesRequests;\n}\n",
    );

    $files[] = [
        'path' => 'app/Http/Controllers/AuthorizesRequests.php',
        'type' => 'other',
        'content' => "<?php\nnamespace App\\Http\\Controllers;\ntrait AuthorizesRequests\n{\n    public function tagRequest(): void {}\n}\n",
    ];

    $findings = runPolicyDetector($files, policyReceiverContext());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->not->toContain('add $this->authorize(')
        ->and($findings[0]->fix)->toContain("add Gate::authorize('delete', \$post)");
});
