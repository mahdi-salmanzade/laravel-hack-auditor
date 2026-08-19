<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\AccessControl;

use Mahdi\HackAuditor\Scanner\Php\ClassShape;
use Mahdi\HackAuditor\Scanner\Php\DefiniteAssignment;
use Mahdi\HackAuditor\Scanner\Php\MethodShape;
use Mahdi\HackAuditor\Scanner\Php\ParsedFile;
use Mahdi\HackAuditor\Scanner\Php\SemanticContext;
use Mahdi\HackAuditor\Scanner\Php\SemanticWorkspace;
use Mahdi\HackAuditor\Scanner\Php\TaintJudgement;
use Mahdi\HackAuditor\Scanner\Php\TypeNames;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\Confidence;
use Mahdi\HackAuditor\Support\FindingClass;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;
use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * Flags a routed controller action that fetches ONE record by an
 * attacker-chosen identifier and hands that record back to the client with
 * nothing standing between the two (IDOR, CWE-639 / OWASP A01).
 *
 * WHAT CHANGED AND WHY
 * --------------------
 * Measured over six real applications (monica, akaunting, pixelfed, BookStack,
 * snipe-it, koel) the previous implementation produced 191 findings, 190 of
 * them false. Every one of those had the same defect: it proved the identifier
 * was attacker controlled and then ASSERTED the absence of authorization from
 * the fact that it could not see any. "No authorization visible in this file"
 * is not evidence of "no authorization" —
 *
 *   - monica authorises through `can:vault-viewer,vault` ROUTE MIDDLEWARE;
 *   - akaunting scopes every model with a GLOBAL SCOPE registered by
 *     `App\Traits\Tenants::bootTenants()`;
 *   - BookStack calls `$this->checkOwnablePermission(...)`, an authorization
 *     primitive this detector had never heard of;
 *   - pixelfed's admin actions live in TRAITS that are not routed at all, and
 *     the records were being "exposed" through view helpers that the detector
 *     merely assumed published them.
 *
 * THE EVIDENCE CHAIN
 * ------------------
 * A `class: vulnerability` finding is emitted only when all of these are
 * resolved from the analysed code, each printable with a file and a line:
 *
 *  1. ENTRY POINT — the enclosing declaration is a concrete, non-abstract
 *     controller CLASS (never a trait), and the route table says this action is
 *     bound to a route. A method nobody can reach is not an IDOR.
 *  2. SOURCE — the identifier is attacker controlled per LaravelSemantics: a
 *     route segment of a confirmed route, or `$request->input()/query()/route()`
 *     and friends. Explicitly NOT `$request->user()->id`, `auth()->id()`,
 *     `Auth::id()` or `config()`. `Unknown` means silence, not suspicion.
 *  3. SHAPE — the identifier is identifier shaped (`$id`, `$roomId`,
 *     `input('user_id')`). `Invoice::findOrFail($slug)` is a business-key lookup
 *     and is left to the reader.
 *  4. SINK — the record reaches the client as a WHOLE OBJECT through a path
 *     this detector recognises: returned directly, `response()->json(...)`,
 *     `view(..., compact('record'))`, an API Resource, an array literal in a
 *     rendered payload. A model handed to an arbitrary helper
 *     (`ShowViewHelper::data($contact, …)`) is NOT proven to reach anybody.
 *  5. NO GUARD — nothing in the method, its class, its ancestors, its
 *     FormRequest or its route authorises or scopes the lookup, AND the route's
 *     middleware list is fully understood. A route carrying middleware this
 *     scan cannot read (`admin`, `permission:x`, anything app-specific) may
 *     authorise, so the absence of authorization is UNPROVEN and nothing is
 *     emitted.
 *  6. NO SCOPE — the model is present in the scan and neither it, its
 *     ancestors, nor any application trait they use registers a global scope.
 *     A globally scoped model does not return other tenants' rows to begin with.
 *  7. AN OWNER EXISTS — the model can belong to somebody: it is itself a
 *     principal, or it names an ownership column, or it relates to one.
 *     snipe-it's AssetModel is a shared catalogue keyed on category_id and
 *     manufacturer_id; "another user's AssetModel" is not a thing, so the
 *     sentence this detector would print is not true of it.
 *
 * When the entry point or the model cannot be resolved, but everything else
 * holds, the finding is downgraded to `class: review`: a question for a human,
 * carrying no fix, excluded from the vulnerability count and the exit code.
 * Anything weaker than that is not emitted at all.
 *
 * FIX SAFETY
 * ----------
 * The remedy names only identifiers proven to exist AND to be in scope at the
 * insertion point. The policy class is QUOTED FROM THE CLASS ACTUALLY RESOLVED
 * — never synthesised as "{Model}Policy", which once told a codebase to call
 * `ContractPolicy` when the registered class was `ContractAccessPolicy`. The
 * ability is read from that policy's own declared methods. The record variable
 * is resolved from the enclosing scope EXCLUDING nested closures. If any of
 * those cannot be resolved, no call is suggested at all: a missing fix is fine,
 * a wrong fix is a catastrophe.
 *
 * This remedy is ANCHORED — "immediately after the lookup on line N" — which is
 * what makes a conditionally bound record safe to name here: the suggested line
 * lands inside the same try block, branch or loop body as the assignment, so
 * the only path that reaches it is the path that made the binding. What it
 * still refuses is an assignment with no statement boundary after it — a match
 * arm, a ternary limb, a `??` right-hand side — because there the advice can
 * only be applied after the whole enclosing statement, which is exactly where
 * the variable may be undefined. DefiniteAssignment::holdsImmediatelyAfter()
 * draws that line. Advice that is NOT anchored to the lookup, as in
 * PolicyRouteMismatchDetector, needs the stricter holdsThroughout().
 */
final class UnauthorizedModelFetchDetector implements AccessControlDetector
{
    /**
     * Terminal calls that resolve exactly one record by primary key.
     *
     * @var array<int, string>
     */
    private const FIND_METHODS = ['find', 'findorfail', 'findor', 'findornew'];

    /**
     * Terminal calls that materialise a `where(...)`-built query.
     *
     * @var array<int, string>
     */
    private const TERMINAL_METHODS = ['first', 'firstorfail', 'sole', 'get'];

    /**
     * Chain links that key a query on the primary key.
     *
     * @var array<int, string>
     */
    private const KEY_CONSTRAINTS = ['where', 'orwhere', 'wherekey'];

    /**
     * Columns that record who owns a row. A query constrained on one of these
     * is scoped, whatever the value it is compared against.
     *
     * @var array<int, string>
     */
    private const OWNERSHIP_COLUMNS = [
        'user_id', 'owner_id', 'author_id', 'account_id', 'team_id',
        'tenant_id', 'customer_id', 'organization_id', 'org_id', 'company_id',
        'created_by', 'updated_by', 'member_id', 'profile_id',
    ];

    /**
     * Columns that say a ROW HAS AN OWNER. Narrower than OWNERSHIP_COLUMNS:
     * `created_by` and `updated_by` are audit columns present on nearly every
     * table and record who typed, not who owns.
     *
     * @var array<int, string>
     */
    private const OWNER_COLUMNS = [
        'user_id', 'owner_id', 'author_id', 'account_id', 'team_id',
        'tenant_id', 'customer_id', 'organization_id', 'org_id', 'company_id',
        'member_id', 'profile_id',
    ];

    /**
     * Base classes and contracts that mean "this model is a principal": the row
     * belongs to the person it represents.
     *
     * @var array<int, string>
     */
    private const AUTHENTICATABLE_CLASSES = [
        'Illuminate\Foundation\Auth\User',
        'Illuminate\Contracts\Auth\Authenticatable',
        'Illuminate\Auth\Authenticatable',
        'Illuminate\Auth\GenericUser',
    ];

    /**
     * Instance calls that ask the authorization layer a question by name.
     *
     * @var array<int, string>
     */
    private const AUTHORIZATION_METHODS = [
        'authorize', 'authorizeforuser', 'authorizeresource', 'can', 'cannot',
        'cant', 'canany', 'checkauthorization', 'allows', 'denies', 'forbids',
    ];

    /**
     * Name FRAGMENTS that mean an application-specific authorization helper.
     * BookStack's `checkOwnablePermission()` is the case that proved a fixed
     * list of framework primitives is not enough.
     *
     * @var array<int, string>
     */
    private const AUTHORIZATION_FRAGMENTS = [
        'authoriz', 'permission', 'ability', 'policy', 'ownable', 'accesscheck',
        'checkaccess', 'hasaccess', 'canaccess', 'isadmin', 'requireadmin',
    ];

    /**
     * Helper functions that stop the request when a condition fails.
     *
     * @var array<int, string>
     */
    private const ABORT_FUNCTIONS = [
        'abort', 'abort_if', 'abort_unless', 'throw_if', 'throw_unless',
        'policy', 'gate',
    ];

    /**
     * Exceptions whose presence means the method refuses unauthorised callers.
     *
     * @var array<int, string>
     */
    private const AUTHORIZATION_EXCEPTIONS = [
        'AuthorizationException', 'AccessDeniedHttpException', 'AccessDeniedException',
        'UnauthorizedException', 'UnauthorizedHttpException', 'HttpException',
        'PermissionsException', 'NotPermittedException',
    ];

    /**
     * Gate facade calls that authorise.
     *
     * @var array<int, string>
     */
    private const GATE_METHODS = ['authorize', 'allows', 'denies', 'forbids', 'any', 'none', 'check'];

    /**
     * Relation/scope calls that constrain a query to an owning record.
     *
     * @var array<int, string>
     */
    private const OWNERSHIP_CONSTRAINTS = ['wherebelongsto', 'whereownedby', 'ownedby', 'visible', 'scopevisible'];

    /**
     * Route middleware this detector UNDERSTANDS to be authentication,
     * transport or plumbing rather than per-record authorization.
     *
     * Anything outside this list — `admin`, `permission:x`, `role:x`, `can:x`,
     * any application middleware — may authorise, and its presence means the
     * absence of authorization is unproven. The list is deliberately short:
     * guessing that an unknown middleware is inert is exactly how 190 false
     * positives were produced.
     *
     * @var array<int, string>
     */
    private const INERT_MIDDLEWARE = [
        'web', 'api', 'auth', 'guest', 'throttle', 'bindings',
        'substitutebindings', 'signed', 'verified', 'precognitive',
        'cache.headers', 'encryptcookies', 'startsession', 'sharederrorsfromsession',
        'validatepostsize', 'trimstrings', 'convertemptystringstotonull',
        'handlecors', 'preventrequestsduringmaintenance', 'addqueuedcookiestoresponse',
        'verifycsrftoken', 'csrf', 'setcachheaders',
    ];

    /**
     * Helpers whose arguments become a URL, not a response body.
     *
     * @var array<int, string>
     */
    private const URL_HELPERS = [
        'redirect', 'route', 'url', 'secure_url', 'action', 'to_route', 'asset',
    ];

    /**
     * Response builders that publish whatever is handed to them.
     *
     * @var array<int, string>
     */
    private const RESPONSE_HELPERS = ['response', 'view', 'collect', 'json_encode', 'jsonresponse'];

    private readonly SemanticWorkspace $workspace;

    public function __construct(?SemanticWorkspace $workspace = null)
    {
        $this->workspace = $workspace ?? new SemanticWorkspace;
    }

    public function detect(array $files, AccessControlContext $context): array
    {
        $sources = [];

        foreach ($files as $file) {
            $sources[] = ['path' => $file->path, 'content' => $file->content, 'type' => $file->type];
        }

        $semantic = $this->workspace->contextFor($sources);
        $findings = [];

        // Decide from the class INDEX whether a file can hold a routable
        // controller, and only then open it. Most of an application declares
        // none, and parsing those to find that out is pure cost.
        foreach ($semantic->paths() as $path) {
            if (! $this->declaresRoutableController($path, $semantic)) {
                continue;
            }

            $parsed = $semantic->parsed($path);

            if ($parsed === null || ! $parsed->isAnalysable()) {
                continue;
            }

            foreach ($parsed->classes() as $class) {
                if (! $this->isRoutableController($class, $semantic)) {
                    continue;
                }

                foreach ($class->publicMethods() as $method) {
                    foreach ($this->inspect($parsed, $class, $method, $semantic, $context) as $finding) {
                        $findings[] = $finding;
                    }
                }
            }
        }

        return $findings;
    }

    /**
     * Whether the declaration can actually be bound to a route: a concrete,
     * non-abstract controller CLASS. pixelfed keeps most of its admin actions
     * in TRAITS whose names end in `Controller`; a trait has no routes, and
     * eight of its false positives came from exactly that.
     */
    private function isRoutableController(ClassShape $class, SemanticContext $semantic): bool
    {
        return $class->isClass()
            && ! $class->isAbstract()
            && $semantic->semantics()->isController($class);
    }

    /**
     * The same test as isRoutableController(), asked of the node-free summaries
     * the index holds. It must stay an exact mirror: a file this rejects is
     * never opened, so any divergence is a silently missed finding.
     */
    private function declaresRoutableController(string $path, SemanticContext $semantic): bool
    {
        foreach ($semantic->summariesIn($path) as $summary) {
            if ($summary->isClass()
                && ! $summary->isAbstract()
                && $semantic->semantics()->isController($summary)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Examine one controller action.
     *
     * @return array<int, Vulnerability>
     */
    private function inspect(
        ParsedFile $parsed,
        ClassShape $class,
        MethodShape $method,
        SemanticContext $semantic,
        AccessControlContext $context,
    ): array {
        if ($method->isConstructor()) {
            return [];
        }

        $fetches = $this->candidateFetches($method, $semantic);

        if ($fetches === []) {
            return [];
        }

        $entry = $this->entryPoint($class, $method, $context);

        if ($entry['verdict'] === 'unreachable') {
            return [];
        }

        if ($this->hasAuthorizationGuard($method, $class, $semantic)) {
            return [];
        }

        if ($this->hasOwnershipScope($method)) {
            return [];
        }

        $state = $semantic->taint()->track($method);
        $findings = [];

        foreach ($fetches as $fetch) {
            $judgement = $semantic->semantics()->judge($fetch['id'], $method, $state);

            if (! $judgement->isTainted()) {
                continue;
            }

            // Without a confirmed route, "this scalar parameter is a route
            // segment the client chose" is an assumption about routing, not a
            // fact about the code. An explicit request accessor needs no such
            // assumption, so only that survives an unknown route table.
            if ($entry['verdict'] === 'unrouted' && ! $this->isExplicitRequestSource($judgement)) {
                continue;
            }

            if (! $this->looksLikeIdentifier($this->identifierLabel($fetch['id']))) {
                continue;
            }

            $variable = $this->assignedVariable($fetch['call']);

            if (! $this->reachesClient($method, $variable, $fetch['call'], $semantic)) {
                continue;
            }

            $scoped = $this->globalScopeVerdict($fetch['model'], $semantic);

            if ($scoped === 'scoped') {
                continue;
            }

            // IDOR is the claim "you can read a record that belongs to someone
            // else". On a model this scan can read and that has no owner at
            // all, that claim is simply false.
            if ($scoped === 'unscoped' && ! $this->modelHasOwner($fetch['model'], $semantic)) {
                continue;
            }

            $proven = $entry['verdict'] === 'routed' && $scoped === 'unscoped';

            $findings[] = $this->report($parsed, $class, $method, $fetch, $variable, $judgement, $semantic, $entry, $scoped, $proven);
        }

        return $findings;
    }

    /*
    |--------------------------------------------------------------------------
    | Entry point
    |--------------------------------------------------------------------------
    */

    /**
     * Whether this action is reachable, and whether the guard surface around it
     * is fully known.
     *
     * - `routed`      the route table names this action and every middleware on
     *                 it is understood to be inert.
     * - `unrouted`    no route data was supplied at all; the guard surface is
     *                 unknown and a finding can only ever be a question.
     * - `unreachable` route data WAS supplied and either does not name this
     *                 action (nothing can call it) or puts middleware on it that
     *                 this scan cannot read (it may already authorise).
     *
     * @return array{verdict: string, route: string|null, middleware: array<int, string>}
     */
    private function entryPoint(ClassShape $class, MethodShape $method, AccessControlContext $context): array
    {
        $route = $context->routeFor($class->shortName(), $method->name());

        if ($route === null) {
            return $context->routedMethods === []
                ? ['verdict' => 'unrouted', 'route' => null, 'middleware' => []]
                : ['verdict' => 'unreachable', 'route' => null, 'middleware' => []];
        }

        foreach ($route['middleware'] as $middleware) {
            if (! $this->isInertMiddleware($middleware)) {
                return ['verdict' => 'unreachable', 'route' => $route['route'], 'middleware' => $route['middleware']];
            }
        }

        return ['verdict' => 'routed', 'route' => $route['route'], 'middleware' => $route['middleware']];
    }

    /**
     * Whether a middleware string is one this detector understands to perform
     * no per-record authorization.
     */
    private function isInertMiddleware(string $middleware): bool
    {
        $name = strtolower(trim($middleware));
        $name = str_contains($name, ':') ? substr($name, 0, (int) strpos($name, ':')) : $name;
        $name = TypeNames::shortName($name);

        return in_array($name, self::INERT_MIDDLEWARE, true);
    }

    /**
     * Whether the identifier came from an EXPLICIT request accessor rather than
     * from the "an untyped scalar parameter of a controller action is a route
     * segment" inference.
     */
    private function isExplicitRequestSource(TaintJudgement $judgement): bool
    {
        $source = $judgement->source;

        if ($source === null) {
            return false;
        }

        return str_starts_with($source, '$request->')
            || str_starts_with($source, '$_')
            || str_starts_with($source, 'request(')
            || str_starts_with($source, 'old(');
    }

    /*
    |--------------------------------------------------------------------------
    | Candidate fetches
    |--------------------------------------------------------------------------
    */

    /**
     * Every single-record lookup in the method that is rooted at an Eloquent
     * model class and keyed on an explicit identifier expression.
     *
     * @return array<int, array{call: Node\Expr\MethodCall|Node\Expr\StaticCall, root: Node\Expr\StaticCall, model: string, id: Node\Expr, verb: string, chain: array<int, Node\Expr\MethodCall|Node\Expr\StaticCall>}>
     */
    private function candidateFetches(MethodShape $method, SemanticContext $semantic): array
    {
        $statements = $method->statements();

        if ($statements === []) {
            return [];
        }

        $calls = (new NodeFinder)->find(
            $statements,
            static fn (Node $node): bool => $node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall,
        );

        $fetches = [];

        foreach ($calls as $call) {
            if (! $call instanceof Node\Expr\MethodCall && ! $call instanceof Node\Expr\StaticCall) {
                continue;
            }

            if (! $this->isTerminalCall($call) || $this->isInsideNestedScope($call)) {
                continue;
            }

            $chain = $this->chainCalls($call);
            $root = $chain[0] ?? null;

            if (! $root instanceof Node\Expr\StaticCall || ! $root->class instanceof Node\Name) {
                continue;
            }

            $model = $method->file()->resolveName($root->class);

            if (! $semantic->semantics()->isEloquentClass($model)) {
                continue;
            }

            $verb = $call->name instanceof Node\Identifier ? strtolower($call->name->toString()) : '';
            $id = $this->identifierArgument($call, $verb, $chain);

            if ($id === null) {
                continue;
            }

            $fetches[] = [
                'call' => $call,
                'root' => $root,
                'model' => $model,
                'id' => $id,
                'verb' => $call->name instanceof Node\Identifier ? $call->name->toString() : $verb,
                'chain' => $chain,
            ];
        }

        return $fetches;
    }

    /**
     * The expression that supplies the primary key for this lookup, or null
     * when the call is not a keyed single-record fetch.
     *
     * @param  array<int, Node\Expr\MethodCall|Node\Expr\StaticCall>  $chain
     */
    private function identifierArgument(Node\Expr\MethodCall|Node\Expr\StaticCall $call, string $verb, array $chain): ?Node\Expr
    {
        if (in_array($verb, self::FIND_METHODS, true)) {
            return $this->argument($call, 0);
        }

        if (! in_array($verb, self::TERMINAL_METHODS, true)) {
            return null;
        }

        foreach ($chain as $link) {
            $name = $link->name instanceof Node\Identifier ? strtolower($link->name->toString()) : '';

            if (! in_array($name, self::KEY_CONSTRAINTS, true)) {
                continue;
            }

            if ($name === 'wherekey') {
                return $this->argument($link, 0);
            }

            $column = $this->stringArgument($link, 0);

            if ($column === null || strtolower($column) !== 'id') {
                continue;
            }

            // where('id', $x) and where('id', '=', $x) both key on the third
            // positional slot when an operator is present.
            return count($link->args) >= 3
                ? $this->argument($link, 2)
                : $this->argument($link, 1);
        }

        return null;
    }

    /**
     * Whether the call ends its own chain, i.e. nothing is invoked on its
     * result. Only the terminal call of a chain is a candidate fetch.
     */
    private function isTerminalCall(Node\Expr\MethodCall|Node\Expr\StaticCall $call): bool
    {
        $parent = $call->getAttribute('parent');

        return ! ($parent instanceof Node\Expr\MethodCall && $parent->var === $call);
    }

    /**
     * Whether the node sits inside a closure, arrow function or anonymous
     * class. Those are a different variable scope, which neither the taint
     * tracker nor the assignment collector models, so they are left alone.
     *
     * The walk itself lives in DefiniteAssignment, which both this detector and
     * PolicyRouteMismatchDetector answer scope questions with.
     */
    private function isInsideNestedScope(Node $node): bool
    {
        return DefiniteAssignment::isInsideNestedScope($node);
    }

    /**
     * The calls making up a fluent chain, root first.
     *
     * @return array<int, Node\Expr\MethodCall|Node\Expr\StaticCall>
     */
    private function chainCalls(Node\Expr $call): array
    {
        $calls = [];
        $current = $call;
        $depth = 0;

        while ($depth++ < 32) {
            if ($current instanceof Node\Expr\MethodCall) {
                $calls[] = $current;
                $current = $current->var;

                continue;
            }

            if ($current instanceof Node\Expr\StaticCall) {
                $calls[] = $current;
            }

            break;
        }

        return array_reverse($calls);
    }

    /**
     * The variable the fetch was assigned to, when it was assigned to one.
     */
    private function assignedVariable(Node\Expr $fetch): ?string
    {
        $parent = $fetch->getAttribute('parent');

        if ($parent instanceof Node\Expr\Assign
            && $parent->expr === $fetch
            && $parent->var instanceof Node\Expr\Variable
            && is_string($parent->var->name)) {
            return $parent->var->name;
        }

        return null;
    }

    /*
    |--------------------------------------------------------------------------
    | Exposure
    |--------------------------------------------------------------------------
    */

    /**
     * Whether the fetched record is handed back to the caller as a whole
     * object by a `return` in this method's own scope.
     */
    private function reachesClient(MethodShape $method, ?string $variable, Node\Expr $fetch, SemanticContext $semantic): bool
    {
        $statements = $method->statements();

        if ($statements === []) {
            return false;
        }

        $returns = (new NodeFinder)->findInstanceOf($statements, Node\Stmt\Return_::class);

        foreach ($returns as $return) {
            if ($return->expr === null || $this->isInsideNestedScope($return)) {
                continue;
            }

            if ($return->getStartLine() < $fetch->getStartLine()) {
                continue;
            }

            if ($this->exposes($return->expr, $variable, $fetch, $method, $semantic)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether an expression PROVABLY carries the fetched record itself into the
     * response.
     *
     * This is an allow-list, not a search. The previous version descended into
     * the arguments of ANY call, so `Inertia::render('…', ['data' =>
     * ContactShowViewHelper::data($contact, Auth::user())])` read as "the record
     * is published" when all that is proven is "the record was handed to a
     * helper". What that helper emits is not visible here, so it is not proof.
     */
    private function exposes(
        Node\Expr $expr,
        ?string $variable,
        Node\Expr $fetch,
        MethodShape $method,
        SemanticContext $semantic,
        int $depth = 0,
    ): bool {
        if ($depth > 10) {
            return false;
        }

        if ($expr === $fetch || $this->isTargetVariable($expr, $variable)) {
            return true;
        }

        if ($expr instanceof Node\Expr\Array_) {
            foreach ($expr->items as $item) {
                if ($this->exposes($item->value, $variable, $fetch, $method, $semantic, $depth + 1)) {
                    return true;
                }
            }

            return false;
        }

        if ($expr instanceof Node\Expr\Ternary) {
            foreach (array_values(array_filter([$expr->if, $expr->else])) as $branch) {
                if ($this->exposes($branch, $variable, $fetch, $method, $semantic, $depth + 1)) {
                    return true;
                }
            }

            return false;
        }

        if ($expr instanceof Node\Expr\BinaryOp\Coalesce) {
            return $this->exposes($expr->left, $variable, $fetch, $method, $semantic, $depth + 1)
                || $this->exposes($expr->right, $variable, $fetch, $method, $semantic, $depth + 1);
        }

        if ($expr instanceof Node\Expr\FuncCall) {
            return $this->exposesViaHelper($expr, $variable, $fetch, $method, $semantic, $depth);
        }

        if ($expr instanceof Node\Expr\New_) {
            return $this->isResourceClass($expr->class, $method, $semantic)
                && $this->exposesArguments($expr, $variable, $fetch, $method, $semantic, $depth);
        }

        if ($expr instanceof Node\Expr\StaticCall) {
            return $this->exposesViaStaticCall($expr, $variable, $fetch, $method, $semantic, $depth);
        }

        if ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\NullsafeMethodCall) {
            return $this->exposesViaMethodCall($expr, $variable, $fetch, $method, $semantic, $depth);
        }

        return false;
    }

    private function exposesViaHelper(
        Node\Expr\FuncCall $expr,
        ?string $variable,
        Node\Expr $fetch,
        MethodShape $method,
        SemanticContext $semantic,
        int $depth,
    ): bool {
        if (! $expr->name instanceof Node\Name) {
            return false;
        }

        $name = strtolower(TypeNames::shortName($expr->name->toString()));

        if (in_array($name, self::URL_HELPERS, true)) {
            return false;
        }

        if ($name === 'compact') {
            if ($variable === null || $expr->isFirstClassCallable()) {
                return false;
            }

            foreach ($expr->getArgs() as $argument) {
                if ($argument->value instanceof Node\Scalar\String_ && $argument->value->value === $variable) {
                    return true;
                }
            }

            return false;
        }

        return in_array($name, self::RESPONSE_HELPERS, true)
            && $this->exposesArguments($expr, $variable, $fetch, $method, $semantic, $depth);
    }

    private function exposesViaStaticCall(
        Node\Expr\StaticCall $expr,
        ?string $variable,
        Node\Expr $fetch,
        MethodShape $method,
        SemanticContext $semantic,
        int $depth,
    ): bool {
        if (! $expr->class instanceof Node\Name || ! $expr->name instanceof Node\Identifier) {
            return false;
        }

        $class = TypeNames::shortName($method->file()->resolveName($expr->class));
        $name = strtolower($expr->name->toString());

        // An API Resource publishes exactly what it is given.
        if ($this->isResourceClass($expr->class, $method, $semantic) && in_array($name, ['make', 'collection'], true)) {
            return $this->exposesArguments($expr, $variable, $fetch, $method, $semantic, $depth);
        }

        // Inertia and Response publish the payload they render. The payload is
        // walked as data: a record nested inside some other call is NOT proven
        // to come back out of it.
        if (($class === 'Inertia' && $name === 'render')
            || ($class === 'Response' && in_array($name, ['json', 'make'], true))
            || ($class === 'View' && $name === 'make')) {
            return $this->exposesArguments($expr, $variable, $fetch, $method, $semantic, $depth);
        }

        return false;
    }

    private function exposesViaMethodCall(
        Node\Expr\MethodCall|Node\Expr\NullsafeMethodCall $expr,
        ?string $variable,
        Node\Expr $fetch,
        MethodShape $method,
        SemanticContext $semantic,
        int $depth,
    ): bool {
        if (! $expr->name instanceof Node\Identifier) {
            return false;
        }

        $name = strtolower($expr->name->toString());

        // `$record->toArray()` / `->toJson()` serialises the record itself.
        if (in_array($name, ['toarray', 'tojson', 'jsonserialize'], true)) {
            return $expr->var === $fetch || $this->isTargetVariable($expr->var, $variable);
        }

        $root = $this->helperChainRoot($expr);

        // `response()->json($record)`, `view(...)->with('record', $record)`,
        // `response()->view(...)`.
        if ($root !== null && in_array($name, ['json', 'view', 'with', 'withviewdata', 'make', 'setdata'], true)) {
            return $this->exposesArguments($expr, $variable, $fetch, $method, $semantic, $depth);
        }

        // A Resource decorated with ->additional([...]) or ->response() still
        // publishes the record it wraps.
        if (in_array($name, ['additional', 'response', 'tojsonresponse'], true)) {
            return $this->exposes($expr->var, $variable, $fetch, $method, $semantic, $depth + 1)
                || $this->exposesArguments($expr, $variable, $fetch, $method, $semantic, $depth);
        }

        return false;
    }

    /**
     * The `response()` / `view()` helper a fluent response chain is built on,
     * or null when the chain is rooted at anything else.
     */
    private function helperChainRoot(Node\Expr $expr): ?string
    {
        $current = $expr;
        $depth = 0;

        while ($depth++ < 32) {
            if ($current instanceof Node\Expr\MethodCall || $current instanceof Node\Expr\NullsafeMethodCall) {
                $current = $current->var;

                continue;
            }

            break;
        }

        if (! $current instanceof Node\Expr\FuncCall || ! $current->name instanceof Node\Name) {
            return null;
        }

        $name = strtolower(TypeNames::shortName($current->name->toString()));

        if (in_array($name, self::URL_HELPERS, true)) {
            return null;
        }

        return in_array($name, self::RESPONSE_HELPERS, true) ? $name : null;
    }

    /**
     * Whether a class name denotes an API Resource: it descends from
     * JsonResource in the scan, or its name says so.
     */
    private function isResourceClass(Node\Name|Node\Expr|Node\Stmt\Class_ $class, MethodShape $method, SemanticContext $semantic): bool
    {
        if (! $class instanceof Node\Name) {
            return false;
        }

        $resolved = $method->file()->resolveName($class);

        if ($semantic->classes()->descendsFromAny($resolved, [
            'Illuminate\Http\Resources\Json\JsonResource',
            'Illuminate\Http\Resources\Json\ResourceCollection',
        ])) {
            return true;
        }

        $short = TypeNames::shortName($resolved);

        return str_ends_with($short, 'Resource') || str_ends_with($short, 'Collection');
    }

    private function exposesArguments(
        Node\Expr\CallLike $call,
        ?string $variable,
        Node\Expr $fetch,
        MethodShape $method,
        SemanticContext $semantic,
        int $depth,
    ): bool {
        if ($call->isFirstClassCallable()) {
            return false;
        }

        foreach ($call->getArgs() as $argument) {
            if ($this->exposes($argument->value, $variable, $fetch, $method, $semantic, $depth + 1)) {
                return true;
            }
        }

        return false;
    }

    private function isTargetVariable(Node\Expr $expr, ?string $variable): bool
    {
        return $variable !== null
            && $expr instanceof Node\Expr\Variable
            && is_string($expr->name)
            && $expr->name === $variable;
    }

    /*
    |--------------------------------------------------------------------------
    | Guards
    |--------------------------------------------------------------------------
    */

    /**
     * Whether anything in the method, its class or its ancestry authorises the
     * action.
     */
    private function hasAuthorizationGuard(MethodShape $method, ClassShape $class, SemanticContext $semantic): bool
    {
        if ($this->bodyAuthorizes($method->statements(), $method, $semantic)) {
            return true;
        }

        foreach ($this->ancestorClasses($class, $semantic) as $ancestor) {
            $constructor = $ancestor->constructor();

            if ($constructor === null) {
                continue;
            }

            if ($this->bodyAuthorizes($constructor->statements(), $constructor, $semantic)
                || $this->registersAuthorizationMiddleware($constructor)) {
                return true;
            }
        }

        return $this->formRequestAuthorizes($method, $semantic);
    }

    /**
     * The class and every ancestor of it that this scan actually contains.
     * A base controller that wires `authorizeResource()` or middleware in its
     * own constructor protects every child, and reading only the leaf class is
     * how that protection goes unseen.
     *
     * @return array<int, ClassShape>
     */
    private function ancestorClasses(ClassShape $class, SemanticContext $semantic): array
    {
        $shapes = [];

        foreach ($semantic->classes()->ancestry($class->fqcn()) as $name) {
            $shape = $semantic->classes()->find($name);

            if ($shape !== null) {
                $shapes[] = $shape;
            }
        }

        return $shapes;
    }

    /**
     * Whether a body contains an authorization call, an abort guard, an
     * authorization exception or an ownership comparison against the
     * authenticated user.
     *
     * Deliberately searched over the WHOLE body, closures included: this
     * function looks for reasons to STAY SILENT, so over-matching costs nothing
     * but a missed report, while under-matching costs a false accusation.
     *
     * @param  array<int, Node\Stmt>  $statements
     */
    private function bodyAuthorizes(array $statements, MethodShape $method, SemanticContext $semantic): bool
    {
        if ($statements === []) {
            return false;
        }

        $finder = new NodeFinder;

        foreach ($finder->findInstanceOf($statements, Node\Expr\MethodCall::class) as $call) {
            if ($call->name instanceof Node\Identifier && $this->isAuthorizationName($call->name->toString())) {
                return true;
            }
        }

        foreach ($finder->findInstanceOf($statements, Node\Expr\StaticCall::class) as $call) {
            if (! $call->class instanceof Node\Name || ! $call->name instanceof Node\Identifier) {
                continue;
            }

            $class = TypeNames::shortName($method->file()->resolveName($call->class));
            $name = strtolower($call->name->toString());

            if ($class === 'Gate' && in_array($name, self::GATE_METHODS, true)) {
                return true;
            }

            if ($this->isAuthorizationName($call->name->toString())) {
                return true;
            }
        }

        foreach ($finder->findInstanceOf($statements, Node\Expr\FuncCall::class) as $call) {
            if (! $call->name instanceof Node\Name) {
                continue;
            }

            if (in_array(strtolower(TypeNames::shortName($call->name->toString())), self::ABORT_FUNCTIONS, true)) {
                return true;
            }
        }

        foreach ($finder->findInstanceOf($statements, Node\Expr\New_::class) as $new) {
            if ($new->class instanceof Node\Name
                && in_array(TypeNames::shortName($method->file()->resolveName($new->class)), self::AUTHORIZATION_EXCEPTIONS, true)) {
                return true;
            }
        }

        return $this->comparesAgainstAuthenticatedUser($statements, $method, $semantic);
    }

    /**
     * Whether a method name asks the authorization layer a question — either
     * one of the framework primitives, or an application helper whose name says
     * so (`checkOwnablePermission`, `authorizeAccess`, `hasPermissionTo`).
     */
    private function isAuthorizationName(string $name): bool
    {
        $lower = strtolower($name);

        if (in_array($lower, self::AUTHORIZATION_METHODS, true)) {
            return true;
        }

        foreach (self::AUTHORIZATION_FRAGMENTS as $fragment) {
            if (str_contains($lower, $fragment)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the body compares something against the authenticated user's
     * identity — `abort_if($invoice->user_id !== auth()->id(), 403)` and its
     * relatives are ownership checks, and reporting past one is a false
     * positive.
     *
     * @param  array<int, Node\Stmt>  $statements
     */
    private function comparesAgainstAuthenticatedUser(array $statements, MethodShape $method, SemanticContext $semantic): bool
    {
        $comparisons = (new NodeFinder)->find($statements, static fn (Node $node): bool => $node instanceof Node\Expr\BinaryOp\Identical
            || $node instanceof Node\Expr\BinaryOp\NotIdentical
            || $node instanceof Node\Expr\BinaryOp\Equal
            || $node instanceof Node\Expr\BinaryOp\NotEqual);

        foreach ($comparisons as $comparison) {
            if (! $comparison instanceof Node\Expr\BinaryOp) {
                continue;
            }

            if ($this->isAuthenticatedIdentity($comparison->left, $method, $semantic)
                || $this->isAuthenticatedIdentity($comparison->right, $method, $semantic)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether an expression is the authenticated user's identity: `auth()->id()`,
     * `Auth::id()`, `auth()->user()->id`, `$request->user()->id`, or a local
     * variable assigned from one of those.
     */
    private function isAuthenticatedIdentity(Node\Expr $expr, MethodShape $method, SemanticContext $semantic, int $depth = 0): bool
    {
        if ($depth > 4) {
            return false;
        }

        if ($expr instanceof Node\Expr\StaticCall
            && $expr->class instanceof Node\Name
            && $expr->name instanceof Node\Identifier
            && TypeNames::shortName($method->file()->resolveName($expr->class)) === 'Auth'
            && in_array(strtolower($expr->name->toString()), ['id', 'user'], true)) {
            return strtolower($expr->name->toString()) === 'id';
        }

        if ($expr instanceof Node\Expr\MethodCall
            && $expr->name instanceof Node\Identifier
            && strtolower($expr->name->toString()) === 'id'
            && $this->isAuthFactory($expr->var)) {
            return true;
        }

        if ($expr instanceof Node\Expr\PropertyFetch
            && $expr->name instanceof Node\Identifier
            && in_array(strtolower($expr->name->toString()), ['id', 'uuid'], true)
            && $this->isAuthenticatedUser($expr->var, $method, $semantic)) {
            return true;
        }

        if ($expr instanceof Node\Expr\MethodCall
            && $expr->name instanceof Node\Identifier
            && in_array(strtolower($expr->name->toString()), ['getkey', 'getauthidentifier'], true)
            && $this->isAuthenticatedUser($expr->var, $method, $semantic)) {
            return true;
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            $assignment = $semantic->semantics()->receivers()
                ->assignmentsFor($method)
                ->reaching($expr->name, $expr->getStartLine());

            if ($assignment !== null) {
                return $this->isAuthenticatedIdentity($assignment['expr'], $method, $semantic, $depth + 1);
            }
        }

        return false;
    }

    /**
     * Whether an expression is the authenticated user object.
     */
    private function isAuthenticatedUser(Node\Expr $expr, MethodShape $method, SemanticContext $semantic, int $depth = 0): bool
    {
        if ($depth > 4) {
            return false;
        }

        if ($expr instanceof Node\Expr\StaticCall
            && $expr->class instanceof Node\Name
            && $expr->name instanceof Node\Identifier
            && TypeNames::shortName($method->file()->resolveName($expr->class)) === 'Auth'
            && strtolower($expr->name->toString()) === 'user') {
            return true;
        }

        if ($expr instanceof Node\Expr\MethodCall
            && $expr->name instanceof Node\Identifier
            && strtolower($expr->name->toString()) === 'user'
            && ($this->isAuthFactory($expr->var) || $semantic->semantics()->isRequestExpression($expr->var, $method))) {
            return true;
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            $assignment = $semantic->semantics()->receivers()
                ->assignmentsFor($method)
                ->reaching($expr->name, $expr->getStartLine());

            if ($assignment !== null) {
                return $this->isAuthenticatedUser($assignment['expr'], $method, $semantic, $depth + 1);
            }
        }

        return false;
    }

    private function isAuthFactory(Node\Expr $expr): bool
    {
        return $expr instanceof Node\Expr\FuncCall
            && $expr->name instanceof Node\Name
            && strtolower(TypeNames::shortName($expr->name->toString())) === 'auth';
    }

    /**
     * Whether the constructor registers middleware that may authorise —
     * `$this->middleware('can:update,post')`, or ANY middleware argument this
     * scan cannot read literally.
     *
     * BookStack writes `$this->middleware([Permission::SettingsManage->middleware()])`.
     * There is no string to match there, and treating "no readable string" as
     * "no middleware" is what let two of its settings-only screens be reported
     * as world-readable. An unreadable middleware argument is UNKNOWN, and
     * unknown means silence.
     */
    private function registersAuthorizationMiddleware(MethodShape $constructor): bool
    {
        $statements = $constructor->statements();

        if ($statements === []) {
            return false;
        }

        foreach ((new NodeFinder)->findInstanceOf($statements, Node\Expr\MethodCall::class) as $call) {
            if (! $call->name instanceof Node\Identifier || strtolower($call->name->toString()) !== 'middleware') {
                continue;
            }

            if (! $call->var instanceof Node\Expr\Variable || $call->var->name !== 'this') {
                continue;
            }

            if ($call->isFirstClassCallable()) {
                return true;
            }

            foreach ($call->getArgs() as $argument) {
                if ($argument->name !== null || $argument->unpack) {
                    return true;
                }

                if (! $this->isInertMiddlewareExpression($argument->value)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Whether a middleware argument is a literal — or a literal list — of names
     * this detector understands to perform no authorization.
     */
    private function isInertMiddlewareExpression(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Scalar\String_) {
            return $this->isInertMiddleware($expr->value);
        }

        if (! $expr instanceof Node\Expr\Array_) {
            return false;
        }

        foreach ($expr->items as $item) {
            if ($item->unpack || ! $this->isInertMiddlewareExpression($item->value)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether a FormRequest parameter of this action authorises the request.
     *
     * Only a FormRequest whose `authorize()` really asks the authorization
     * layer or compares against the authenticated user counts. A body that
     * returns `true` — or merely checks that somebody is logged in — decides
     * nothing about THIS record and is not a guard.
     */
    private function formRequestAuthorizes(MethodShape $method, SemanticContext $semantic): bool
    {
        foreach ($method->parameters() as $parameter) {
            $type = $parameter->classType($method->file());

            if ($type === null) {
                continue;
            }

            $shape = $semantic->classes()->resolve($type);

            if ($shape === null) {
                continue;
            }

            foreach ($this->ancestorClasses($shape, $semantic) as $ancestor) {
                $authorize = $ancestor->method('authorize');

                if ($authorize !== null && $this->bodyAuthorizes($authorize->statements(), $authorize, $semantic)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Whether any query in the method is constrained to an owning record —
     * `->where('user_id', …)`, `->whereBelongsTo($request->user())`.
     *
     * Deliberately method-wide rather than chain-local: a scope applied to a
     * sibling query is weak evidence that the action is owner-scoped, and
     * weak evidence is a reason to stay quiet, never a reason to report.
     */
    private function hasOwnershipScope(MethodShape $method): bool
    {
        $statements = $method->statements();

        if ($statements === []) {
            return false;
        }

        $calls = (new NodeFinder)->find(
            $statements,
            static fn (Node $node): bool => $node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall,
        );

        foreach ($calls as $call) {
            if (! $call instanceof Node\Expr\MethodCall && ! $call instanceof Node\Expr\StaticCall) {
                continue;
            }

            $name = $call->name instanceof Node\Identifier ? strtolower($call->name->toString()) : '';

            if (in_array($name, self::OWNERSHIP_CONSTRAINTS, true)) {
                return true;
            }

            if (! in_array($name, ['where', 'orwhere', 'wherein', 'whererelation', 'wherehas'], true)) {
                continue;
            }

            $column = $this->stringArgument($call, 0);

            if ($column !== null && in_array(strtolower($column), self::OWNERSHIP_COLUMNS, true)) {
                return true;
            }
        }

        return false;
    }

    /*
    |--------------------------------------------------------------------------
    | Global scopes
    |--------------------------------------------------------------------------
    */

    /**
     * Whether the model narrows every query of its own accord.
     *
     * Returns `scoped` when the model, an ancestor, or an application trait one
     * of them uses registers a global scope (`static::addGlobalScope(...)` or
     * `#[ScopedBy]`); `unscoped` when the whole chain is present in the scan and
     * none of them does; `unknown` when the model is not in the scan at all, in
     * which case nothing about its scoping is provable.
     *
     * This is the akaunting case: `App\Traits\Tenants::bootTenants()` adds
     * `App\Scopes\Company` to every model, so `Account::find($id)` cannot return
     * another company's row and twelve "IDOR" findings were fiction.
     *
     * Vendor traits (HasFactory, SoftDeletes, Notifiable) are not inspected:
     * they are not in a scan, and none of them scopes by owner.
     */
    private function globalScopeVerdict(string $model, SemanticContext $semantic): string
    {
        $shape = $semantic->classes()->find($model) ?? $semantic->classes()->resolve($model);

        if ($shape === null) {
            return 'unknown';
        }

        foreach ($this->ancestorClasses($shape, $semantic) as $ancestor) {
            if ($this->declaresGlobalScope($ancestor)) {
                return 'scoped';
            }

            foreach ($ancestor->traits() as $trait) {
                $traitShape = $semantic->classes()->find($trait);

                if ($traitShape !== null && $this->declaresGlobalScope($traitShape)) {
                    return 'scoped';
                }
            }
        }

        return 'unscoped';
    }

    /**
     * Whether the record can belong to anybody in particular.
     *
     * IDOR is the claim "you can read a record that belongs to someone else".
     * snipe-it's AssetModel is a shared catalogue — its columns are
     * category_id, manufacturer_id, fieldset_id, model_number and nothing
     * resembling an owner — so no caller can read "another user's AssetModel",
     * because there is no such thing. Asserting one is a false positive
     * whatever the routing and the guards look like.
     *
     * A model is owned when:
     *  - it IS a principal, i.e. it or an ancestor descends from
     *    Authenticatable, so the row belongs to the user it represents; or
     *  - THIS class — not a shared base class — names an ownership column as a
     *    string literal, in `$fillable`, in a `belongsTo()` foreign key or in a
     *    scope; or
     *  - THIS class references an authenticatable class, i.e. it relates to a
     *    user.
     *
     * The ownership scan deliberately stops at the class itself. snipe-it's
     * `SnipeModel` base declares `setCompanyIdAttribute()`, so reading the
     * ancestry would mark every one of its models as company-owned including
     * the ones whose tables carry no such column.
     *
     * Audit columns (`created_by`, `updated_by`) do not count either: almost
     * every table carries them and they record who typed, not who owns.
     */
    private function modelHasOwner(string $model, SemanticContext $semantic): bool
    {
        $shape = $semantic->classes()->find($model) ?? $semantic->classes()->resolve($model);

        if ($shape === null) {
            return false;
        }

        if ($semantic->classes()->descendsFromAny($shape->fqcn(), self::AUTHENTICATABLE_CLASSES)) {
            return true;
        }

        foreach ($semantic->classes()->ancestry($shape->fqcn()) as $ancestor) {
            if (TypeNames::shortName($ancestor) === 'Authenticatable') {
                return true;
            }
        }

        $node = [$shape->node()];
        $finder = new NodeFinder;

        foreach ($finder->findInstanceOf($node, Node\Scalar\String_::class) as $literal) {
            if (in_array(strtolower(trim($literal->value)), self::OWNER_COLUMNS, true)) {
                return true;
            }
        }

        foreach ($finder->findInstanceOf($node, Node\Expr\ClassConstFetch::class) as $reference) {
            if (! $reference->class instanceof Node\Name) {
                continue;
            }

            $target = $shape->file()->resolveName($reference->class);

            if ($semantic->classes()->descendsFromAny($target, self::AUTHENTICATABLE_CLASSES)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a class or trait registers a global scope.
     */
    private function declaresGlobalScope(ClassShape $class): bool
    {
        foreach ($class->node()->attrGroups as $group) {
            foreach ($group->attrs as $attribute) {
                if (TypeNames::shortName($class->file()->resolveName($attribute->name)) === 'ScopedBy') {
                    return true;
                }
            }
        }

        foreach ($class->methods() as $method) {
            $statements = $method->statements();

            if ($statements === []) {
                continue;
            }

            foreach ((new NodeFinder)->find($statements, static fn (Node $node): bool => $node instanceof Node\Expr\StaticCall || $node instanceof Node\Expr\MethodCall) as $call) {
                if (! $call instanceof Node\Expr\StaticCall && ! $call instanceof Node\Expr\MethodCall) {
                    continue;
                }

                if ($call->name instanceof Node\Identifier
                    && strtolower($call->name->toString()) === 'addglobalscope') {
                    return true;
                }
            }
        }

        return false;
    }

    /*
    |--------------------------------------------------------------------------
    | Identifier shape
    |--------------------------------------------------------------------------
    */

    /**
     * The name the identifier is known by in the source: a variable name, a
     * property name, or the key passed to a request accessor.
     */
    private function identifierLabel(Node\Expr $expr, int $depth = 0): ?string
    {
        if ($depth > 6) {
            return null;
        }

        if ($expr instanceof Node\Expr\Cast) {
            return $this->identifierLabel($expr->expr, $depth + 1);
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return $expr->name;
        }

        if (($expr instanceof Node\Expr\PropertyFetch || $expr instanceof Node\Expr\NullsafePropertyFetch)
            && $expr->name instanceof Node\Identifier) {
            return $expr->name->toString();
        }

        if ($expr instanceof Node\Expr\ArrayDimFetch && $expr->dim instanceof Node\Scalar\String_) {
            return $expr->dim->value;
        }

        if ($expr instanceof Node\Expr\MethodCall
            || $expr instanceof Node\Expr\NullsafeMethodCall
            || $expr instanceof Node\Expr\StaticCall
            || $expr instanceof Node\Expr\FuncCall) {
            return $this->stringArgument($expr, 0);
        }

        return null;
    }

    /**
     * Whether a name denotes a record identifier rather than a business key.
     * `$slug` and `input('email')` are looked up by value, not by id, and are
     * left alone.
     */
    private function looksLikeIdentifier(?string $label): bool
    {
        if ($label === null) {
            return false;
        }

        $label = strtolower($label);

        return $label === 'id' || str_ends_with($label, '_id') || str_ends_with($label, 'id');
    }

    /**
     * The expression at a positional argument. Named arguments and spreads
     * are refused rather than guessed at.
     */
    private function argument(Node\Expr\CallLike $call, int $position): ?Node\Expr
    {
        if ($call->isFirstClassCallable()) {
            return null;
        }

        $argument = $call->getArgs()[$position] ?? null;

        if (! $argument instanceof Node\Arg || $argument->name !== null || $argument->unpack) {
            return null;
        }

        return $argument->value;
    }

    /**
     * The literal string at a positional argument, when it is a literal.
     */
    private function stringArgument(Node\Expr\CallLike $call, int $position): ?string
    {
        $value = $this->argument($call, $position);

        return $value instanceof Node\Scalar\String_ ? $value->value : null;
    }

    /*
    |--------------------------------------------------------------------------
    | Reporting
    |--------------------------------------------------------------------------
    */

    /**
     * Build the finding. Every identifier quoted here is taken from the parsed
     * code; nothing is invented.
     *
     * @param  array{call: Node\Expr\MethodCall|Node\Expr\StaticCall, root: Node\Expr\StaticCall, model: string, id: Node\Expr, verb: string, chain: array<int, Node\Expr\MethodCall|Node\Expr\StaticCall>}  $fetch
     * @param  array{verdict: string, route: string|null, middleware: array<int, string>}  $entry
     */
    private function report(
        ParsedFile $parsed,
        ClassShape $class,
        MethodShape $method,
        array $fetch,
        ?string $variable,
        TaintJudgement $judgement,
        SemanticContext $semantic,
        array $entry,
        string $scoped,
        bool $proven,
    ): Vulnerability {
        $model = TypeNames::shortName($fetch['model']);
        $line = $fetch['call']->getStartLine();
        $record = $variable === null ? 'that record' : '$'.$variable;
        $lookup = in_array(strtolower($fetch['verb']), self::FIND_METHODS, true)
            ? sprintf('%s::%s()', $model, $fetch['verb'])
            : sprintf('a %s query constrained on `id` and materialised with ->%s()', $model, $fetch['verb']);

        $description = $proven
            ? sprintf(
                '%s::%s() loads one %s record on line %d with %s, keyed on a client-supplied identifier, and returns %s to the caller. Any caller can read another user\'s %s record by changing that identifier (IDOR).',
                $class->shortName(),
                $method->name(),
                $model,
                $line,
                $lookup,
                $record,
                $model,
            )
            : sprintf(
                'Is %s::%s() meant to be readable by any caller? It loads one %s record on line %d with %s, keyed on a client-supplied identifier, and returns %s. %s, so this is raised for review rather than reported as a proven IDOR.',
                $class->shortName(),
                $method->name(),
                $model,
                $line,
                $lookup,
                $record,
                $this->unprovenReason($entry, $model),
            );

        return new Vulnerability(
            type: VulnerabilityType::Idor,
            location: $parsed->path,
            line: $line,
            severity: SeverityLevel::High,
            description: $description,
            proof: $this->proof($class, $method, $judgement, $entry, $scoped, $model),
            // A review finding carries NO fix. Vulnerability drops it anyway;
            // passing an empty string states the intent at the call site rather
            // than relying on the invariant to clean up after this detector.
            fix: $proven
                ? $this->remedy($fetch['model'], $model, $this->quotableVariable($fetch['call'], $variable), $line, $class, $semantic)
                : '',
            findingClass: $proven ? FindingClass::Vulnerability : FindingClass::Review,
            confidence: $proven ? Confidence::Proven : Confidence::Possible,
        );
    }

    /**
     * The single link of the chain that could not be resolved, phrased for the
     * reader of a review finding.
     *
     * @param  array{verdict: string, route: string|null, middleware: array<int, string>}  $entry
     */
    private function unprovenReason(array $entry, string $model): string
    {
        if ($entry['verdict'] !== 'routed') {
            return 'This scan was given no route table, so it cannot confirm which middleware runs before this action';
        }

        return sprintf('%s is not present in this scan, so its global scopes — which could already restrict the query to the caller\'s own rows — could not be read', $model);
    }

    /**
     * @param  array{verdict: string, route: string|null, middleware: array<int, string>}  $entry
     */
    private function proof(
        ClassShape $class,
        MethodShape $method,
        TaintJudgement $judgement,
        array $entry,
        string $scoped,
        string $model,
    ): string {
        $route = $entry['verdict'] === 'routed'
            ? sprintf(
                'The action is bound to the route `%s`, whose middleware is [%s] — authentication and plumbing only, no authorization',
                (string) $entry['route'],
                $entry['middleware'] === [] ? 'none' : implode(', ', $entry['middleware']),
            )
            : 'No route table was supplied to this scan, so the middleware stack in front of this action is UNKNOWN and may authorise it';

        $scope = match ($scoped) {
            'unscoped' => sprintf('%s and every ancestor it declares are present in this scan and none of them registers a global scope, so the query is not narrowed by the model itself', $model),
            default => sprintf('%s is not present in this scan, so whether it registers a global scope is UNKNOWN', $model),
        };

        return sprintf(
            'The identifier is attacker controlled: %s. %s. %s. Nothing authorises the lookup: %s::%s() invokes no $this->authorize()/Gate::/->can() call and no application permission helper, no ancestor constructor registers authorization middleware or calls authorizeResource(), no injected form request authorises the call, the method never compares the record against the authenticated user\'s id, and the query is not constrained to an owner column or relation.',
            $judgement->evidence,
            $route,
            $scope,
            $class->shortName(),
            $method->name(),
        );
    }

    /**
     * The variable the remedy may quote back, which is not every variable the
     * description may mention.
     *
     * The description reports what the code DOES, so it may say the method
     * returns `$post` wherever `$post` is what the code returns. The remedy
     * says what the reader should WRITE, so it may name `$post` only where the
     * line it asks for can actually be written: immediately after a
     * statement-level assignment, inside whatever branch made the binding. An
     * assignment that is a match arm, a ternary limb or a `??` right-hand side
     * has no such point — the reader would have to place the call after the
     * enclosing statement, where the variable may never have been assigned —
     * and no call is written for it.
     */
    private function quotableVariable(Node\Expr $fetch, ?string $variable): ?string
    {
        if ($variable === null) {
            return null;
        }

        $assign = $fetch->getAttribute('parent');

        return $assign instanceof Node\Expr\Assign && DefiniteAssignment::holdsImmediatelyAfter($assign)
            ? $variable
            : null;
    }

    /**
     * Advice that is safe to apply verbatim.
     *
     * An `authorize()` call is only ever suggested when EVERY identifier it
     * needs is proven to exist: an ability declared by the policy class this
     * scan ACTUALLY RESOLVED for the model, a variable holding the fetched
     * record that is in scope at the insertion point, and — D-3 — a receiver
     * that really has an `authorize()` method. The policy is quoted by its real
     * class name — synthesising "{Model}Policy" once produced advice naming
     * `ContractPolicy` for a codebase whose registered policy was
     * `ContractAccessPolicy`, so the suggested call referenced a class that does
     * not exist. `$this->authorize()` was the same mistake one level up: on a
     * Laravel 11+ controller, which no longer uses AuthorizesRequests, the
     * receiver is the identifier that does not exist.
     */
    private function remedy(string $model, string $shortModel, ?string $variable, int $line, ClassShape $class, SemanticContext $semantic): string
    {
        $policy = $semantic->policies()->policyFor($model);
        $ability = $this->declaredViewAbility($model, $semantic);

        if ($policy !== null && $ability !== null && $variable !== null) {
            $receiver = AuthorizeAvailability::resolve($class, $semantic);

            if ($receiver->isCallable()) {
                return sprintf(
                    "%s declares a `%s` ability, so authorize the record before returning it: add \$this->authorize('%s', \$%s) immediately after the lookup on line %d. Scoping the query to its owner instead — resolving it from a relation on the authenticated user — is equally valid.",
                    $policy->shortName(),
                    $ability,
                    $ability,
                    $variable,
                    $line,
                );
            }

            return sprintf(
                "%s declares a `%s` ability, so authorize the record before returning it: add Gate::authorize('%s', \$%s) immediately after the lookup on line %d, importing Illuminate\\Support\\Facades\\Gate. %s Scoping the query to its owner instead — resolving it from a relation on the authenticated user — is equally valid.",
                $policy->shortName(),
                $ability,
                $ability,
                $variable,
                $line,
                $receiver->reason(),
            );
        }

        return sprintf(
            'Establish ownership before returning this %s: resolve it from a relation on the authenticated user, or constrain the query to the column that stores the owner. No authorize() call is suggested here because this scan resolved no policy class declaring a read ability for %s, and calling an ability that does not exist throws at runtime.',
            $shortModel,
            $shortModel,
        );
    }

    /**
     * The read ability the model's Policy actually declares, if any.
     */
    private function declaredViewAbility(string $model, SemanticContext $semantic): ?string
    {
        foreach ($semantic->policies()->abilitiesFor($model) as $ability) {
            if (strtolower($ability) === 'view') {
                return $ability;
            }
        }

        return null;
    }
}
