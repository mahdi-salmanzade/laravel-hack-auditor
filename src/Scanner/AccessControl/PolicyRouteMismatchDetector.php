<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\AccessControl;

use Mahdi\HackAuditor\Scanner\Php\ClassShape;
use Mahdi\HackAuditor\Scanner\Php\DefiniteAssignment;
use Mahdi\HackAuditor\Scanner\Php\MethodShape;
use Mahdi\HackAuditor\Scanner\Php\PolicyInspector;
use Mahdi\HackAuditor\Scanner\Php\ReceiverResolver;
use Mahdi\HackAuditor\Scanner\Php\SemanticContext;
use Mahdi\HackAuditor\Scanner\Php\SemanticWorkspace;
use Mahdi\HackAuditor\Scanner\Php\TypeNames;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\Confidence;
use Mahdi\HackAuditor\Support\FindingClass;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;
use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * Asks whether a state-changing controller action reaches a policy ability that
 * the policy declares — and answers in one of THREE ways, not two.
 *
 * TWO FINDING CLASSES, NOT ONE SEVERITY AXIS
 * ------------------------------------------
 * This detector reads controller source. It cannot read gates registered at
 * runtime, middleware bound in a service provider, policies wired through
 * `Gate::policy()` outside the scanned set, or a service layer that enforces
 * permissions of its own. "No authorization is visible in this file" is
 * therefore NOT evidence of "no authorization runs".
 *
 *   class: vulnerability — emitted only when the NEGATIVE IS PROVEN. The route
 *                          bound to the action is resolved, its middleware
 *                          stack is known and carries no authorization, the
 *                          controller's whole ancestry and trait set is
 *                          readable and applies none, the method (and one level
 *                          of same-class helpers it calls) invokes none, and no
 *                          injected form request authorises. Confidence: proven.
 *   class: review        — everything else. Phrased as a QUESTION. Carries NO
 *                          fix string, and is meant to be excluded from the
 *                          vulnerability count, the score and the exit code.
 *                          Confidence: possible.
 *
 * Severity answers "how bad if real"; class and confidence answer "how sure am
 * I". They are different questions, so a review finding is not a downgraded
 * HIGH — it is a different kind of statement. Both axes are carried by
 * FindingClass and Confidence, and Vulnerability enforces the invariant that a
 * Review finding cannot hold a fix even if one were passed in here.
 *
 * DESTRUCTIVE ADVICE THIS FILE EXISTS TO PREVENT
 * ----------------------------------------------
 * D-1  instanceVariableFor() used to run NodeFinder over the whole method node,
 *      which DESCENDS INTO CLOSURES. On a controller whose $contract is
 *      assigned only inside `DB::transaction(function () use (...) { ... })` it
 *      advised `$this->authorize('delete', $contract)` at the top of destroy().
 *      Applied verbatim that is `Undefined variable $contract` →
 *      `Gate::authorize('delete', null)` → AuthorizationException → every
 *      DELETE 403s. Assignments inside a nested scope are now skipped.
 * D-2  A policy class name is never synthesised from "{Model}Policy". It is
 *      quoted only when the policy class was actually parsed; when the ability
 *      list came from introspection instead, the finding says "the policy
 *      registered for {Model}" and names no class.
 * D-3  Scope-awareness was not enough. try/catch, match arms, switch cases,
 *      loop bodies and if branches do NOT open a new scope in PHP, so a
 *      variable bound only inside one of them looked like a method-scope
 *      binding and was quoted back in advice inserted at the top of the method.
 *      `try { ... } catch (Throwable $e) { $ledger = ...; }` produced
 *      `$this->authorize('delete', $ledger)` — undefined on the happy path,
 *      which is D-1's 403 reproduced through a different construct. The
 *      variable is now required to be DEFINITELY ASSIGNED (see
 *      DefiniteAssignment::holdsThroughout()); when it is not, the finding says
 *      so instead of writing a call.
 *
 * FIX SAFETY. A fix string is emitted only for a proven vulnerability, only
 * with an ability the policy itself declares, and only with a variable that is
 * bound in the method's own scope EXCLUDING nested closures AND reached on
 * every path through the method. If any identifier cannot be resolved, no call
 * is written. A missing fix is fine; a wrong fix is a catastrophe.
 *
 * Every structural question is answered against AST node types. No regex is
 * applied to PHP source anywhere in this file.
 */
final class PolicyRouteMismatchDetector implements AccessControlDetector
{
    /**
     * Opening token of every review-class description.
     *
     * FindingClass carries the class itself; this prefix keeps the question
     * legible in renderers that print a description without its heading.
     */
    private const REVIEW_PREFIX = 'Review: ';

    /**
     * Controller action => the policy ability Laravel maps it onto.
     *
     * `store` is NOT an ability; the ability a store action needs is `create`.
     * A policy that declares no `create` has nothing for a store action to
     * bypass. Read-only actions (index/show) are deliberately absent.
     *
     * @var array<string, string>
     */
    private const ACTION_ABILITIES = [
        'store' => 'create',
        'create' => 'create',
        'update' => 'update',
        'edit' => 'update',
        'destroy' => 'delete',
        'delete' => 'delete',
    ];

    /**
     * Abilities Laravel resolves against the model CLASS rather than an
     * instance, so advice for them may legitimately name `Model::class`.
     *
     * @var array<int, string>
     */
    private const CLASS_LEVEL_ABILITIES = ['create', 'viewAny'];

    /**
     * Static methods that only an Eloquent model or query builder exposes.
     * Used ONLY as a fallback when the receiver's class cannot be resolved to a
     * known Eloquent ancestor — a declared type always wins.
     *
     * @var array<int, string>
     */
    private const ELOQUENT_STATIC_METHODS = [
        'find', 'findorfail', 'findor', 'findmany', 'firstorfail', 'firstwhere',
        'firstorcreate', 'firstornew', 'create', 'forcecreate', 'destroy',
        'updateorcreate', 'where', 'wherein', 'wherekey', 'query', 'newquery',
        'with', 'withtrashed', 'onlytrashed', 'withoutglobalscopes', 'sole',
    ];

    /**
     * Static/chained methods that hand back a single MODEL INSTANCE, so the
     * variable they are assigned to can be named in advice as "the model".
     *
     * @var array<int, string>
     */
    private const INSTANCE_RETURNING_METHODS = [
        'find', 'findorfail', 'findor', 'first', 'firstorfail', 'firstwhere',
        'firstorcreate', 'firstornew', 'create', 'forcecreate', 'make',
        'updateorcreate', 'sole',
    ];

    /**
     * Method names whose presence proves an authorization check runs. Matched
     * receiver-agnostically ON PURPOSE: this list can only ever SUPPRESS a
     * finding, so a loose match here costs recall, never precision.
     *
     * @var array<int, string>
     */
    private const AUTHORIZATION_METHODS = [
        'authorize', 'authorizeforuser', 'authorizeresource', 'can', 'cannot',
        'cant', 'canany', 'allows', 'denies', 'forbids', 'checkauthorization',
    ];

    /**
     * Helper functions that abort the request on a failed check.
     *
     * @var array<int, string>
     */
    private const AUTHORIZATION_FUNCTIONS = [
        'abort_if', 'abort_unless', 'throw_if', 'throw_unless', 'abort',
    ];

    /**
     * Facades whose static calls are authorization decisions.
     *
     * @var array<int, string>
     */
    private const AUTHORIZATION_FACADES = [
        'Illuminate\Support\Facades\Gate',
        'Illuminate\Contracts\Auth\Access\Gate',
    ];

    /**
     * Middleware aliases that perform authorization (as opposed to merely
     * authenticating). Compared against the token before the first `:`.
     *
     * @var array<int, string>
     */
    private const AUTHORIZATION_MIDDLEWARE = [
        'can', 'authorize', 'authorization', 'role', 'roles', 'permission',
        'permissions', 'ability', 'abilities', 'scope', 'scopes', 'admin',
        'is_admin', 'owner', 'password.confirm',
    ];

    /**
     * Namespaces whose classes ship with the framework itself. A base class or
     * trait from one of these is KNOWN not to apply application authorization,
     * so it does not break the proof chain. Anything else that cannot be read
     * does break it — a vendor package's base controller may well authorise.
     *
     * @var array<int, string>
     */
    private const FRAMEWORK_NAMESPACES = ['Illuminate\\', 'Symfony\\', 'Psr\\'];

    private readonly SemanticWorkspace $workspace;

    private readonly PolicyInspector $inspector;

    private readonly ReceiverResolver $receivers;

    public function __construct(?SemanticWorkspace $workspace = null)
    {
        $this->workspace = $workspace ?? new SemanticWorkspace;
        $this->inspector = new PolicyInspector;
        $this->receivers = new ReceiverResolver;
    }

    /**
     * @param  array<int, SourceFile>  $files
     * @return array<int, Vulnerability>
     */
    public function detect(array $files, AccessControlContext $context): array
    {
        $sources = array_values($files);

        $semantic = $this->workspace->contextFor(array_map(
            static fn (SourceFile $file): array => [
                'path' => $file->path,
                'content' => $file->content,
                'type' => $file->type,
            ],
            $sources,
        ));

        $findings = [];

        // One file open at a time. Pre-parsing the whole set into an array — as
        // this used to — pinned every syntax tree in the scan at once, which is
        // what put a large application over PHP's default memory_limit.
        foreach ($sources as $file) {
            if (! $this->declaresController($file, $semantic)) {
                continue;
            }

            $parsedFile = $semantic->parsed($file->path);

            if ($parsedFile === null || ! $parsedFile->isAnalysable()) {
                continue;
            }

            foreach ($parsedFile->classes() as $class) {
                if (! $this->isController($class, $file)) {
                    continue;
                }

                foreach ($this->inspectController($file, $class, $semantic, $context) as $finding) {
                    $findings[] = $finding;
                }
            }
        }

        return $findings;
    }

    /**
     * @return array<int, Vulnerability>
     */
    private function inspectController(SourceFile $file, ClassShape $class, SemanticContext $semantic, AccessControlContext $context): array
    {
        // authorizeResource() maps the whole CRUD verb set onto the policy, and
        // authorization middleware registered in a constructor guards every
        // action it covers. Either one — in this class, in any parent we can
        // read, or in any trait it uses — means this controller cannot be shown
        // to skip authorization.
        if ($this->controllerAppliesAuthorization($class, $semantic)) {
            return [];
        }

        $findings = [];

        foreach ($class->publicMethods() as $method) {
            $finding = $this->inspectAction($file, $class, $method, $semantic, $context);

            if ($finding !== null) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }

    private function inspectAction(SourceFile $file, ClassShape $class, MethodShape $method, SemanticContext $semantic, AccessControlContext $context): ?Vulnerability
    {
        $ability = self::ACTION_ABILITIES[strtolower($method->name())] ?? null;

        if ($ability === null) {
            return null;
        }

        // Authorization the scan CAN see, anywhere it can look: the method
        // body (closures included), one level into same-class helpers the
        // method calls, an injected form request, or the route itself.
        if ($this->methodAuthorizes($method)
            || $this->delegatesAuthorization($method, $class, $semantic)
            || $this->injectedRequestAuthorizes($method, $semantic)
            || $this->routeAuthorizes($context, $class->shortName(), $method->name())) {
            return null;
        }

        $route = $context->routeFor($class->shortName(), $method->name());

        // The route table was read and this action is not on it. An action no
        // route reaches is not an access-control gap; it is dead code or an
        // internal helper, and saying otherwise is noise.
        if ($route === null && $this->routeTableCovers($context, $class->shortName())) {
            return null;
        }

        $candidates = $this->candidateModels($method, $semantic);

        if ($candidates === []) {
            return null;
        }

        $model = $this->attribute($candidates, $class, $ability, $semantic, $context);

        if ($model === null) {
            return null;
        }

        // Not "does a policy exist" but "does it declare the ability this
        // action would need". No proof, no finding.
        $policy = $this->policyEvidence($model, $ability, $semantic, $context);

        if ($policy === null) {
            return null;
        }

        // An unresolved route is never proof; proves() says so too, but stating
        // it here is what lets the vulnerability path be typed on a route that
        // exists rather than one that might not.
        if ($route !== null && $this->proves($class, $method, $semantic, $route)) {
            return $this->vulnerability($file, $class, $method, $model, $ability, $policy, $route, $semantic);
        }

        return $this->review($file, $class, $method, $model, $ability, $policy, $semantic, $route);
    }

    // -----------------------------------------------------------------------
    // CLASSIFICATION
    // -----------------------------------------------------------------------

    /**
     * Whether the NEGATIVE is proven: that no authorization runs for this
     * action anywhere, not merely that none is visible in this file.
     *
     * Every link must be resolved. A route whose middleware stack was never
     * read, a parent controller outside the scan, a trait we cannot open, a
     * parameter type we cannot resolve — any one of them leaves a place
     * authorization could live, and an unread place is not an empty one.
     *
     * @param  array{route: string, middleware: array<int, string>}|null  $route
     */
    private function proves(ClassShape $class, MethodShape $method, SemanticContext $semantic, ?array $route): bool
    {
        // The route must be resolved AND carry a middleware stack we actually
        // read. An empty stack is what a failed lookup also looks like, so it
        // is treated as unknown rather than as "no middleware".
        if ($route === null || $route['middleware'] === []) {
            return false;
        }

        return $this->ancestryFullyReadable($class, $semantic)
            && $this->traitsFullyReadable($class, $semantic)
            && $this->parameterTypesFullyReadable($method, $semantic);
    }

    /**
     * Whether the route table knows this controller at all. When it does, an
     * action missing from it is genuinely unrouted rather than merely
     * un-introspected.
     */
    private function routeTableCovers(AccessControlContext $context, string $shortClass): bool
    {
        foreach (array_keys($context->routedMethods) as $key) {
            $separator = strrpos($key, '@');

            if ($separator === false) {
                continue;
            }

            $classPart = substr($key, 0, $separator);

            if (TypeNames::shortName($classPart) === $shortClass) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether every ancestor of the controller is either readable in this scan
     * or a framework base class known to apply no application authorization.
     */
    private function ancestryFullyReadable(ClassShape $class, SemanticContext $semantic): bool
    {
        foreach ($semantic->classes()->ancestry($class->fqcn()) as $name) {
            if ($semantic->classes()->resolve($name) !== null || $this->isFrameworkName($name)) {
                continue;
            }

            return false;
        }

        return true;
    }

    /**
     * Whether every trait used by the controller or by any readable ancestor is
     * itself readable (or a framework trait).
     */
    private function traitsFullyReadable(ClassShape $class, SemanticContext $semantic): bool
    {
        foreach ($this->classChain($class, $semantic) as $link) {
            foreach ($link->traits() as $trait) {
                if ($semantic->classes()->resolve($trait) !== null || $this->isFrameworkName($trait)) {
                    continue;
                }

                return false;
            }
        }

        return true;
    }

    /**
     * Whether every class-typed parameter of the action can be read, so the
     * claim "no injected form request authorises this call" is checkable.
     */
    private function parameterTypesFullyReadable(MethodShape $method, SemanticContext $semantic): bool
    {
        foreach ($method->parameters() as $parameter) {
            $type = $parameter->classType($method->file());

            if ($type === null) {
                continue;
            }

            if ($semantic->classes()->resolve($type) !== null || $this->isFrameworkName($type)) {
                continue;
            }

            return false;
        }

        return true;
    }

    private function isFrameworkName(string $fqcn): bool
    {
        $fqcn = ltrim($fqcn, '\\');

        foreach (self::FRAMEWORK_NAMESPACES as $namespace) {
            if (str_starts_with($fqcn, $namespace)) {
                return true;
            }
        }

        return false;
    }

    // -----------------------------------------------------------------------
    // FINDING CONSTRUCTION
    // -----------------------------------------------------------------------

    /**
     * A proven defect: the ability is declared, the route is known, and nothing
     * on any path this scan can read applies it.
     *
     * @param  array{short: string, fqcn: string, written: string|null, variable: string|null}  $model
     * @param  array{label: string, evidence: string}  $policy
     * @param  array{route: string, middleware: array<int, string>}  $route
     */
    private function vulnerability(SourceFile $file, ClassShape $class, MethodShape $method, array $model, string $ability, array $policy, array $route, SemanticContext $semantic): Vulnerability
    {
        return new Vulnerability(
            type: VulnerabilityType::AuthBypass,
            location: $file->path,
            line: $method->declarationLine(),
            severity: SeverityLevel::High,
            description: sprintf(
                '%s::%s() is the %s action for %s, which Laravel authorises through the `%s` ability. %s declares `%s`, and nothing applies it: the route %s runs the middleware [%s], none of which authorises; the method and the helpers it calls invoke no authorize()/Gate/can() check; the controller, its parents and its traits call no authorizeResource() and register no authorization middleware; and no injected form request authorises the call. The declared ability never runs.',
                $class->shortName(),
                $method->name(),
                strtolower($method->name()),
                $model['short'],
                $ability,
                $policy['label'],
                $ability,
                $route['route'],
                implode(', ', $route['middleware']),
            ),
            proof: sprintf(
                '%s. %s::%s() reaches %s with no authorization call between them, and the route %s carries the middleware [%s].',
                $policy['evidence'],
                $class->shortName(),
                $method->name(),
                $model['short'],
                $route['route'],
                implode(', ', $route['middleware']),
            ),
            fix: $this->fixFor($model, $class, $method, $ability, $policy['label'], $semantic),
            findingClass: FindingClass::Vulnerability,
            confidence: Confidence::Proven,
        );
    }

    /**
     * A question, not an assertion: security-sensitive code whose guard — if
     * there is one — lives somewhere this scan could not read.
     *
     * Carries NO fix string. Advising a change on the strength of "I could not
     * see a check" is how a scanner breaks a working application. Confidence
     * Possible makes that structural: Vulnerability drops the fix at
     * construction, so the invariant cannot be lost to a later edit here.
     *
     * @param  array{short: string, fqcn: string, written: string|null, variable: string|null}  $model
     * @param  array{label: string, evidence: string}  $policy
     * @param  array{route: string, middleware: array<int, string>}|null  $route
     */
    private function review(SourceFile $file, ClassShape $class, MethodShape $method, array $model, string $ability, array $policy, SemanticContext $semantic, ?array $route): Vulnerability
    {
        $unreadable = $this->unreadableSurface($class, $method, $semantic, $route);
        $request = $this->injectedRequestName($method, $semantic);

        return new Vulnerability(
            type: VulnerabilityType::AuthBypass,
            location: $file->path,
            line: $method->declarationLine(),
            severity: SeverityLevel::High,
            description: sprintf(
                '%s%s::%s() is the %s action for %s and calls no authorization primitive this scan could see — not in the method, not in a same-class helper it calls, not in the controller. %s declares the `%s` ability Laravel would consult here. %s Is access enforced somewhere this scan cannot read — route middleware, a `can:` middleware, authorizeResource() on a parent controller, a Gate::before, %s, or a service layer that checks permissions of its own?',
                self::REVIEW_PREFIX,
                $class->shortName(),
                $method->name(),
                strtolower($method->name()),
                $model['short'],
                $policy['label'],
                $ability,
                $unreadable,
                $request === null ? "a form request's authorize()" : $request.'::authorize()',
            ),
            proof: sprintf(
                '%s. No authorization call was found in %s::%s(), in the same-class helpers it calls, or in %s itself. %s Absence of a visible check is not evidence that no check runs, so this is a question rather than a finding.',
                $policy['evidence'],
                $class->shortName(),
                $method->name(),
                $class->shortName(),
                $unreadable,
            ),
            // NO FIX ON A REVIEW FINDING, EVER.
            fix: '',
            findingClass: FindingClass::Review,
            confidence: Confidence::Possible,
        );
    }

    /**
     * The specific link in the proof chain that could not be resolved, stated
     * as a fact about the scan rather than about the code.
     *
     * @param  array{route: string, middleware: array<int, string>}|null  $route
     */
    private function unreadableSurface(ClassShape $class, MethodShape $method, SemanticContext $semantic, ?array $route): string
    {
        if ($route === null) {
            return 'No route was resolved for this action, so its middleware stack is unknown to this scan.';
        }

        if ($route['middleware'] === []) {
            return sprintf('The route %s was resolved but its middleware stack was not, so this scan cannot say what guards it.', $route['route']);
        }

        if (! $this->ancestryFullyReadable($class, $semantic)) {
            return sprintf('%s extends a class outside this scan, which may register authorization middleware or call authorizeResource().', $class->shortName());
        }

        if (! $this->traitsFullyReadable($class, $semantic)) {
            return sprintf('%s uses a trait outside this scan, which may apply authorization.', $class->shortName());
        }

        if (! $this->parameterTypesFullyReadable($method, $semantic)) {
            return 'This action injects a class this scan could not read, which may be a form request whose authorize() guards the call.';
        }

        return 'Part of the authorization surface for this action is outside the scanned set.';
    }

    /**
     * The short name of an injected class-typed request parameter, quoted only
     * because it was read from this method's own signature.
     */
    private function injectedRequestName(MethodShape $method, SemanticContext $semantic): ?string
    {
        foreach ($method->parameters() as $parameter) {
            $type = $parameter->classType($method->file());

            if ($type === null) {
                continue;
            }

            $short = TypeNames::shortName($type);

            if ($semantic->classes()->resolve($type) !== null && str_contains(strtolower($short), 'request')) {
                return $short;
            }
        }

        return null;
    }

    /**
     * Build advice that can only ever reference identifiers proven to exist.
     *
     * A fix string is executable advice. It may name an ability only because
     * the policy was read and declares it, and a variable only because that
     * variable is bound in this method's OWN scope — never inside a closure,
     * where it does not exist at the insertion point, and never on only some of
     * the paths through the method, where it is undefined on the rest. When
     * neither can be named, nothing is synthesised.
     *
     * D-3: the RECEIVER is the third identifier, and it is proven the same way.
     * `$this->authorize()` is written only where the controller is shown to have
     * that method; where it is not, the same ability is applied through the
     * `Gate` facade, which needs nothing of the controller at all.
     *
     * @param  array{short: string, fqcn: string, written: string|null, variable: string|null}  $model
     */
    private function fixFor(array $model, ClassShape $class, MethodShape $method, string $ability, string $policyLabel, SemanticContext $semantic): string
    {
        $receiver = AuthorizeAvailability::resolve($class, $semantic);

        if (in_array($ability, self::CLASS_LEVEL_ABILITIES, true)) {
            if ($model['written'] === null) {
                return sprintf(
                    '%s declares `%s`, which Laravel resolves against the %s class rather than an instance. Apply it before the action mutates anything. No call is suggested here because this method never names the %s class in a form that could be quoted back safely.',
                    $policyLabel,
                    $ability,
                    $model['short'],
                    $model['short'],
                );
            }

            if ($receiver->isCallable()) {
                return sprintf(
                    "Apply the ability %s already declares: add \$this->authorize('%s', %s::class) at the top of %s(), or attach the framework's `can:` authorization middleware to the route. `%s` takes the class, not an instance, so it is safe before the record exists.",
                    $policyLabel,
                    $ability,
                    $model['written'],
                    $method->name(),
                    $ability,
                );
            }

            return sprintf(
                "Apply the ability %s already declares: add Gate::authorize('%s', %s::class) at the top of %s(), importing Illuminate\\Support\\Facades\\Gate. `%s` takes the class, not an instance, so it is safe before the record exists. %s",
                $policyLabel,
                $ability,
                $model['written'],
                $method->name(),
                $ability,
                $receiver->reason(),
            );
        }

        if ($model['variable'] === null) {
            return $this->unnameableAdvice($model, $method, $ability, $policyLabel);
        }

        if ($receiver->isCallable()) {
            return sprintf(
                "Apply the ability %s already declares to the %s this method resolves: add \$this->authorize('%s', %s) in %s() once %s is loaded, or attach the framework's `can:` authorization middleware to the route.",
                $policyLabel,
                $model['short'],
                $ability,
                $model['variable'],
                $method->name(),
                $model['variable'],
            );
        }

        return sprintf(
            "Apply the ability %s already declares to the %s this method resolves: add Gate::authorize('%s', %s) in %s() once %s is loaded, importing Illuminate\\Support\\Facades\\Gate. %s The framework's `can:` authorization middleware on the route is the other option, and needs the route to bind the %s as a model parameter rather than an id.",
            $policyLabel,
            $model['short'],
            $ability,
            $model['variable'],
            $method->name(),
            $model['variable'],
            $receiver->reason(),
            $model['short'],
        );
    }

    /**
     * What to say when the record cannot be named — which is two different
     * situations, and saying the wrong one is saying something false.
     *
     * The method may bind NOTHING this advice could point at (the record only
     * ever exists inside a closure, or is never assigned at all), or it may
     * bind the record on SOME paths and not others. In the second case
     * "never binds it" would be untrue, and the reason a call is refused is
     * different: the variable exists, but a call written at the top of the
     * method would run on paths where it is undefined — which is exactly the
     * `Gate::authorize(..., null)` 403 this detector exists to prevent.
     *
     * @param  array{short: string, fqcn: string, written: string|null, variable: string|null}  $model
     */
    private function unnameableAdvice(array $model, MethodShape $method, string $ability, string $policyLabel): string
    {
        if ($this->bindsConditionally($method, $model['fqcn'])) {
            return sprintf(
                '%s declares `%s` for %s, but this method binds the %s instance on only some of its paths — inside a try/catch, a match arm, a loop or a branch — so a call written here would pass an undefined variable on the others and reject every request it was meant to protect. Apply `%s` on each path that resolves a %s, or attach the framework\'s `can:` authorization middleware to the route.',
                $policyLabel,
                $ability,
                $model['short'],
                $model['short'],
                $ability,
                $model['short'],
            );
        }

        return sprintf(
            '%s declares `%s` for %s, but this method never binds the %s instance to a named variable in its own scope, so no call can be written out without inventing one. Apply `%s` wherever the %s record is resolved, or attach the framework\'s `can:` authorization middleware to the route.',
            $policyLabel,
            $ability,
            $model['short'],
            $model['short'],
            $ability,
            $model['short'],
        );
    }

    /**
     * Prove the ability exists, and describe where that proof came from.
     *
     * Source order matters: a policy present in the scan is read from its own
     * AST; only when it is absent do we fall back to the ability list the
     * scanner introspected off disk. An ability list that was never gathered is
     * not an empty one — it is silence.
     *
     * D-2: the policy CLASS NAME is quoted only on the parsed path. On the
     * introspected path the class that declared those abilities is unknown —
     * it may be `ContractAccessPolicy` registered through `Gate::policy()` —
     * so the finding refers to "the policy registered for {Model}" and names
     * no class it did not resolve.
     *
     * @param  array{short: string, fqcn: string, written: string|null, variable: string|null}  $model
     * @return array{label: string, evidence: string}|null
     */
    private function policyEvidence(array $model, string $ability, SemanticContext $semantic, AccessControlContext $context): ?array
    {
        $policy = $semantic->policies()->policyFor($model['fqcn']) ?? $semantic->policies()->policyFor($model['short']);

        if ($policy !== null) {
            $declared = $this->inspector->ability($policy, $ability);

            if ($declared === null) {
                return null;
            }

            return [
                'label' => $policy->shortName(),
                'evidence' => sprintf(
                    '%s::%s() is declared at %s:%d',
                    $policy->shortName(),
                    $declared->name(),
                    $policy->file()->path,
                    $declared->declarationLine(),
                ),
            ];
        }

        if (! $context->knowsAbilitiesFor($model['short']) || ! $context->policyDefinesAbility($model['short'], $ability)) {
            return null;
        }

        return [
            'label' => sprintf('The policy registered for %s', $model['short']),
            'evidence' => sprintf(
                'the policy registered for %s declares the abilities [%s], including `%s`',
                $model['short'],
                implode(', ', $context->abilitiesFor($model['short'])),
                $ability,
            ),
        ];
    }

    /**
     * Decide which of the models an action touches the finding is about.
     *
     * Attribution stays conservative because blaming the wrong model produces a
     * confidently wrong report: a single candidate is used as-is, otherwise the
     * controller's own resource model wins if it needs the ability, otherwise a
     * single ability-declaring candidate wins, otherwise nothing is reported.
     *
     * @param  array<string, array{short: string, fqcn: string, written: string|null, variable: string|null}>  $candidates
     * @return array{short: string, fqcn: string, written: string|null, variable: string|null}|null
     */
    private function attribute(array $candidates, ClassShape $class, string $ability, SemanticContext $semantic, AccessControlContext $context): ?array
    {
        if (count($candidates) === 1) {
            return array_values($candidates)[0];
        }

        $resource = $this->resourceModelFor($class->shortName());

        foreach ($candidates as $candidate) {
            if ($resource !== null
                && strtolower($candidate['short']) === strtolower($resource)
                && $this->policyEvidence($candidate, $ability, $semantic, $context) !== null) {
                return $candidate;
            }
        }

        $withAbility = array_values(array_filter(
            $candidates,
            fn (array $candidate): bool => $this->policyEvidence($candidate, $ability, $semantic, $context) !== null,
        ));

        return count($withAbility) === 1 ? $withAbility[0] : null;
    }

    /**
     * Every Eloquent model an action touches, keyed by lowercased FQCN, with
     * the identifiers that may safely be quoted back in advice.
     *
     * @return array<string, array{short: string, fqcn: string, written: string|null, variable: string|null}>
     */
    private function candidateModels(MethodShape $method, SemanticContext $semantic): array
    {
        $candidates = [];
        $finder = new NodeFinder;

        foreach ($method->parameters() as $parameter) {
            $type = $parameter->classType($method->file());

            if ($type === null || ! $semantic->semantics()->isEloquentClass($type)) {
                continue;
            }

            $this->addCandidate($candidates, $type, null, $parameter->variable());
        }

        foreach ($finder->findInstanceOf($method->node(), Node\Expr\StaticCall::class) as $call) {
            if (! $call->class instanceof Node\Name || ! $call->name instanceof Node\Identifier) {
                continue;
            }

            $written = $call->class->toString();

            if (in_array(strtolower($written), ['self', 'static', 'parent'], true)) {
                continue;
            }

            $resolved = $method->file()->resolveName($call->class);

            if (! $semantic->semantics()->isEloquentClass($resolved)
                && ! in_array(strtolower($call->name->toString()), self::ELOQUENT_STATIC_METHODS, true)) {
                continue;
            }

            $this->addCandidate($candidates, $resolved, $written, null);
        }

        foreach ($finder->findInstanceOf($method->node(), Node\Expr\New_::class) as $new) {
            if (! $new->class instanceof Node\Name) {
                continue;
            }

            $resolved = $method->file()->resolveName($new->class);

            if ($semantic->semantics()->isEloquentClass($resolved)) {
                $this->addCandidate($candidates, $resolved, $new->class->toString(), null);
            }
        }

        foreach ($candidates as $key => $candidate) {
            if ($candidate['variable'] === null) {
                $candidates[$key]['variable'] = $this->instanceVariableFor($method, $candidate['fqcn']);
            }
        }

        return $candidates;
    }

    /**
     * @param  array<string, array{short: string, fqcn: string, written: string|null, variable: string|null}>  $candidates
     */
    private function addCandidate(array &$candidates, string $fqcn, ?string $written, ?string $variable): void
    {
        $fqcn = ltrim($fqcn, '\\');
        $key = strtolower($fqcn);

        if (! isset($candidates[$key])) {
            $candidates[$key] = [
                'short' => TypeNames::shortName($fqcn),
                'fqcn' => $fqcn,
                'written' => $written,
                'variable' => $variable,
            ];

            return;
        }

        $candidates[$key]['written'] ??= $written;
        $candidates[$key]['variable'] ??= $variable;
    }

    /**
     * The variable a model instance is assigned to that ADVICE MAY QUOTE BACK.
     *
     * D-1. A NodeFinder over the method node descends into closures and arrow
     * functions, so `DB::transaction(function () use (...) { $contract = ... })`
     * used to yield `$contract` as though it were a method-scope variable. It
     * is not: quoting it back in advice inserted at the top of the method
     * produces `Undefined variable`, `Gate::authorize(..., null)`, and a 403 on
     * every request the advice was supposed to protect.
     *
     * D-3. Being in the method's own scope is necessary and NOT sufficient. A
     * variable assigned inside try/catch, a match arm, a switch case, a loop
     * body, a non-exhaustive branch or a short-circuited expression is in this
     * scope and still undefined on the paths that skip the assignment, which
     * produces the same `null` and the same 403. The assignment must therefore
     * be DEFINITELY ASSIGNED: reached on every path from the method's entry, so
     * the binding holds wherever in the method the advice is applied.
     */
    private function instanceVariableFor(MethodShape $method, string $fqcn): ?string
    {
        foreach ($this->instanceAssignments($method, $fqcn) as $assign) {
            $name = DefiniteAssignment::assignedName($assign);

            if ($name !== null && DefiniteAssignment::holdsThroughout($assign)) {
                return '$'.$name;
            }
        }

        return null;
    }

    /**
     * Whether the method binds the model to a variable in its own scope, but
     * only on some of its paths.
     *
     * This is the difference between "there is nothing to name" and "there is
     * something to name and naming it would be destructive", which the finding
     * has to state honestly rather than collapse into one sentence.
     */
    private function bindsConditionally(MethodShape $method, string $fqcn): bool
    {
        foreach ($this->instanceAssignments($method, $fqcn) as $assign) {
            if (! DefiniteAssignment::isInsideNestedScope($assign) && ! DefiniteAssignment::holdsThroughout($assign)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Every assignment in the method that puts ONE instance of the model into a
     * plain local variable, in source order.
     *
     * Only an assignment whose chain starts at the model class AND ends in an
     * instance-returning method qualifies, so `$rooms = Room::where(...)->get()`
     * (a collection) is never quoted back as though it were one record. Whether
     * the binding is reachable, and from where, is a separate question the
     * callers ask of DefiniteAssignment.
     *
     * @return array<int, Node\Expr\Assign>
     */
    private function instanceAssignments(MethodShape $method, string $fqcn): array
    {
        $assignments = [];

        foreach ((new NodeFinder)->findInstanceOf($method->node(), Node\Expr\Assign::class) as $assign) {
            if (DefiniteAssignment::assignedName($assign) === null) {
                continue;
            }

            $root = $this->receivers->chainRoot($assign->expr);

            if (! $root instanceof Node\Expr\StaticCall || ! $root->class instanceof Node\Name) {
                continue;
            }

            if (strtolower($method->file()->resolveName($root->class)) !== strtolower($fqcn)) {
                continue;
            }

            $chain = $this->receivers->chainMethods($assign->expr);
            $last = $chain === [] ? null : strtolower((string) end($chain));

            if ($last === null || ! in_array($last, self::INSTANCE_RETURNING_METHODS, true)) {
                continue;
            }

            $assignments[] = $assign;
        }

        return $assignments;
    }

    /**
     * Whether any authorization check runs inside the method, including inside
     * closures it defines and passes to something else.
     */
    private function methodAuthorizes(MethodShape $method): bool
    {
        $finder = new NodeFinder;

        foreach ($finder->findInstanceOf($method->node(), Node\Expr\MethodCall::class) as $call) {
            if ($this->isAuthorizationName($call->name)) {
                return true;
            }
        }

        foreach ($finder->findInstanceOf($method->node(), Node\Expr\NullsafeMethodCall::class) as $call) {
            if ($this->isAuthorizationName($call->name)) {
                return true;
            }
        }

        foreach ($finder->findInstanceOf($method->node(), Node\Expr\StaticCall::class) as $call) {
            if ($this->isAuthorizationName($call->name)) {
                return true;
            }

            if ($call->class instanceof Node\Name
                && in_array($method->file()->resolveName($call->class), self::AUTHORIZATION_FACADES, true)) {
                return true;
            }
        }

        foreach ($finder->findInstanceOf($method->node(), Node\Expr\FuncCall::class) as $call) {
            if ($call->name instanceof Node\Name
                && in_array(strtolower(TypeNames::shortName($call->name->toString())), self::AUTHORIZATION_FUNCTIONS, true)) {
                return true;
            }
        }

        foreach ($finder->findInstanceOf($method->node(), Node\Expr\New_::class) as $new) {
            if ($new->class instanceof Node\Name
                && str_contains(TypeNames::shortName($method->file()->resolveName($new->class)), 'AuthorizationException')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the action hands authorization to a guard helper of its own
     * class: `$this->guardContract($contract)`, `self::assertOwner(...)`,
     * `parent::authorizeAccess(...)`.
     *
     * Followed ONE level, into the class itself, any readable ancestor and any
     * readable trait. One level is enough for the pattern that produced D-1 —
     * a controller that authorises inside the transaction closure through a
     * private helper — and stops well short of whole-program analysis.
     */
    private function delegatesAuthorization(MethodShape $method, ClassShape $class, SemanticContext $semantic): bool
    {
        $chain = $this->classChain($class, $semantic);
        $finder = new NodeFinder;
        $names = [];

        foreach ($finder->findInstanceOf($method->node(), Node\Expr\MethodCall::class) as $call) {
            if ($call->var instanceof Node\Expr\Variable
                && $call->var->name === 'this'
                && $call->name instanceof Node\Identifier) {
                $names[] = $call->name->toString();
            }
        }

        foreach ($finder->findInstanceOf($method->node(), Node\Expr\StaticCall::class) as $call) {
            if ($call->class instanceof Node\Name
                && in_array(strtolower($call->class->toString()), ['self', 'static', 'parent'], true)
                && $call->name instanceof Node\Identifier) {
                $names[] = $call->name->toString();
            }
        }

        foreach (array_unique($names) as $name) {
            if (strtolower($name) === strtolower($method->name())) {
                continue;
            }

            foreach ($chain as $link) {
                $helper = $link->method($name);

                if ($helper !== null && $this->methodAuthorizes($helper)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * The controller, every ancestor of it readable in this scan, and every
     * readable trait reachable from either.
     *
     * The traversal itself lives in ClassIndex::chain() so that this detector
     * and AuthorizeAvailability read one inheritance surface rather than two
     * that can drift apart.
     *
     * @return array<int, ClassShape>
     */
    private function classChain(ClassShape $class, SemanticContext $semantic): array
    {
        return $semantic->classes()->chain($class->fqcn())['shapes'];
    }

    /**
     * Whether the controller — or any parent or trait this scan can read —
     * wires authorizeResource() or registers authorization middleware in a
     * constructor, either of which guards actions from outside the method body.
     */
    private function controllerAppliesAuthorization(ClassShape $class, SemanticContext $semantic): bool
    {
        foreach ($this->classChain($class, $semantic) as $link) {
            if ($this->classAuthorizesResource($link) || $this->constructorRegistersAuthorization($link)) {
                return true;
            }
        }

        return false;
    }

    private function isAuthorizationName(Node\Identifier|Node\Expr $name): bool
    {
        return $name instanceof Node\Identifier
            && in_array(strtolower($name->toString()), self::AUTHORIZATION_METHODS, true);
    }

    /**
     * Whether the class wires authorizeResource(), which auto-authorises every
     * mapped CRUD action against the policy.
     */
    private function classAuthorizesResource(ClassShape $class): bool
    {
        foreach ((new NodeFinder)->findInstanceOf($class->node(), Node\Expr\MethodCall::class) as $call) {
            if ($call->name instanceof Node\Identifier
                && strtolower($call->name->toString()) === 'authorizeresource') {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the constructor registers authorization middleware, the
     * pre-Laravel-11 way of guarding a whole controller.
     */
    private function constructorRegistersAuthorization(ClassShape $class): bool
    {
        $constructor = $class->constructor();

        if ($constructor === null) {
            return false;
        }

        foreach ((new NodeFinder)->findInstanceOf($constructor->node(), Node\Expr\MethodCall::class) as $call) {
            if (! $call->name instanceof Node\Identifier || strtolower($call->name->toString()) !== 'middleware') {
                continue;
            }

            foreach ($call->args as $argument) {
                if (! $argument instanceof Node\Arg) {
                    continue;
                }

                if ($this->namesAuthorizationMiddleware($argument->value, $constructor)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function namesAuthorizationMiddleware(Node\Expr $expr, MethodShape $constructor): bool
    {
        if ($expr instanceof Node\Scalar\String_) {
            return $this->isAuthorizationMiddleware($expr->value);
        }

        if ($expr instanceof Node\Expr\ClassConstFetch && $expr->class instanceof Node\Name) {
            return str_contains(
                strtolower(TypeNames::shortName($constructor->file()->resolveName($expr->class))),
                'authorize',
            );
        }

        if ($expr instanceof Node\Expr\Array_) {
            foreach ($expr->items as $item) {
                if ($this->namesAuthorizationMiddleware($item->value, $constructor)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Whether a middleware string performs authorization. The alias is the part
     * before the first `:`, so `can:update,post` is the `can` middleware.
     */
    private function isAuthorizationMiddleware(string $middleware): bool
    {
        $separator = strpos($middleware, ':');
        $alias = strtolower($separator === false ? $middleware : substr($middleware, 0, $separator));

        if (in_array($alias, self::AUTHORIZATION_MIDDLEWARE, true)) {
            return true;
        }

        return str_contains(strtolower(TypeNames::shortName($alias)), 'authorize');
    }

    /**
     * Whether a form request injected into the action performs authorization.
     *
     * Laravel calls FormRequest::authorize() before the controller method runs
     * and aborts with a 403 when it returns false, so a request class that
     * implements it IS an authorization path. The scaffold default
     * `return true;` is excluded: it is a provable no-op, and treating it as a
     * guard would blind the detector to the most common real gap.
     */
    private function injectedRequestAuthorizes(MethodShape $method, SemanticContext $semantic): bool
    {
        foreach ($method->parameters() as $parameter) {
            $type = $parameter->classType($method->file());

            if ($type === null) {
                continue;
            }

            $request = $semantic->classes()->resolve($type);
            $authorize = $request?->method('authorize');

            if ($authorize === null || ! $authorize->isPublic() || $authorize->isAbstract()) {
                continue;
            }

            if (! $this->returnsLiteralTrue($authorize)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a method's entire body is `return true;`.
     */
    private function returnsLiteralTrue(MethodShape $method): bool
    {
        $statements = $method->statements();

        if (count($statements) !== 1) {
            return false;
        }

        $return = $statements[0];

        return $return instanceof Node\Stmt\Return_
            && $return->expr instanceof Node\Expr\ConstFetch
            && strtolower($return->expr->name->toString()) === 'true';
    }

    /**
     * Whether the route this action is bound to carries authorization
     * middleware, as introspected from the Laravel Router.
     */
    private function routeAuthorizes(AccessControlContext $context, string $shortClass, string $method): bool
    {
        $route = $context->routeFor($shortClass, $method);

        if ($route === null) {
            return false;
        }

        foreach ($route['middleware'] as $middleware) {
            if ($this->isAuthorizationMiddleware($middleware) || str_contains($middleware, 'Authorize')) {
                return true;
            }
        }

        return false;
    }

    /**
     * The resource model a controller is named for: PostController => Post.
     */
    private function resourceModelFor(string $shortClass): ?string
    {
        if (! str_ends_with($shortClass, 'Controller')) {
            return null;
        }

        $resource = substr($shortClass, 0, -strlen('Controller'));

        return $resource === '' ? null : $resource;
    }

    /**
     * Whether a declared class is a routed controller. Policies, models and
     * form requests are excluded by name, and abstract bases carry no routes.
     */
    private function isController(ClassShape $class, SourceFile $file): bool
    {
        if ($class->isInterface() || $class->isAbstract()) {
            return false;
        }

        return str_ends_with($class->shortName(), 'Controller') || $file->type === 'controller';
    }

    /**
     * The same test as isController(), asked of the node-free summaries the
     * index holds, so a file that cannot hold a controller is never opened. It
     * must stay an exact mirror: any divergence is a silently missed finding.
     */
    private function declaresController(SourceFile $file, SemanticContext $semantic): bool
    {
        foreach ($semantic->summariesIn($file->path) as $summary) {
            if ($summary->isInterface() || $summary->isAbstract()) {
                continue;
            }

            if (str_ends_with($summary->shortName(), 'Controller') || $file->type === 'controller') {
                return true;
            }
        }

        return false;
    }
}
