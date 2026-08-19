<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\AccessControl;

use Mahdi\HackAuditor\Scanner\Php\ClassShape;
use Mahdi\HackAuditor\Scanner\Php\MethodShape;
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
 * Flags credential material being serialised into an HTTP response.
 *
 * ---------------------------------------------------------------------------
 * THE EVIDENCE CHAIN
 * ---------------------------------------------------------------------------
 *
 * A finding is only class FindingClass::Vulnerability — an ASSERTION — when
 * every one of these links is resolved from the analysed file:
 *
 *  1. THE READ. A sensitive attribute is read EXPLICITLY (`$user->password`),
 *     in a VALUE position. An array KEY named 'password' is a label, not a
 *     leak, and is excluded structurally rather than by pattern.
 *  2. THE RECEIVER. The object is PROVEN to be an Eloquent model — from the
 *     assignment that reaches the read, a type hint, or `$request->user()`.
 *     An unresolved receiver means silence: `$dto->api_key` on an object we
 *     cannot type is not evidence of anything.
 *  3. THE SINK. The value reaches something the framework serialises to an
 *     HTTP caller: `response()->json([...])`, `view(..., [...])`, `->with()`
 *     on a response/view builder, `compact()`, or the array a RESPONDER class
 *     returns. A bare `return [...]` from a Job, a service or a repository is
 *     NOT a response — see RESPONDER below.
 *  4. NOT CONDITIONALLY WRAPPED. A value wrapped in `$this->when(...)`,
 *     `->unless(...)`, `->whenLoaded(...)`, `->whenNotNull(...)` or
 *     `->mergeWhen(...)` inside an API Resource is NOT unconditionally
 *     exposed: ConditionallyLoadsAttributes returns a MissingValue and
 *     JsonResource::removeMissingValues() strips the key before the response
 *     is built. Such a value is never asserted. If the condition resolves to a
 *     real access gate the read is dropped entirely; if the condition cannot
 *     be resolved it is a review QUESTION and nothing more.
 *  5. NOT DERIVED. The raw value must reach the payload. When a helper sits
 *     between the read and the payload — `route(...)`, `encrypt(...)`,
 *     `Str::mask(...)`, `Hash::make(...)` — what the caller receives is that
 *     helper's output, not the secret, and the analyzer cannot claim otherwise.
 *  6. NOT SELF-DIRECTED. `$request->user()->two_factor_secret` hands the
 *     CALLER their own secret. Fortify's TwoFactorSecretKeyController does
 *     exactly this, and so does every "show me my API key" settings screen.
 *     That is a design decision for a human, not a proven leak.
 *  7. NOT ALREADY GATED. When the method calls `authorize()` / `Gate::` /
 *     `->can()` naming the same receiver, access to the value is gated by a
 *     policy this analyzer has not read. A question, not an assertion.
 *
 * Anything short of the full chain is FindingClass::Review at
 * Confidence::Possible, phrased as a question, and carries `fix: ''`.
 *
 * ---------------------------------------------------------------------------
 * RESPONDER
 * ---------------------------------------------------------------------------
 *
 * A bare `return [...]` only reaches a caller when the class exists to answer
 * an HTTP request: a controller, or an API Resource whose toArray() the
 * framework serialises. `SyncIntegrationJob::headers()` returning
 * `['Authorization' => 'Bearer '.$integration->api_key]` builds OUTBOUND
 * request headers; nothing in that class is ever serialised to a caller.
 * Explicit builders (`response()`, `view()`, `new JsonResponse`) are sinks
 * wherever they appear, because they are responses by construction.
 *
 * ---------------------------------------------------------------------------
 * WHAT $hidden DOES AND DOES NOT DO
 * ---------------------------------------------------------------------------
 *
 * `$hidden` / `#[Hidden]` filters a model that ELOQUENT serialises for you. It
 * has no effect on `['password_hash' => $user->password]`, where the attribute
 * is read explicitly and the raw string is placed in an array. So the "not
 * redacted by $hidden" link of the chain is checked and REPORTED here, but a
 * declaration is never treated as proof of safety for an explicit read —
 * inverting it would delete the canonical true positive, since
 * `protected $hidden = ['password', 'remember_token'];` is Laravel's own
 * default on App\Models\User.
 *
 * Where a redaction declaration DOES carry weight is as evidence of INTENT:
 *
 *  - Returning a model, a collection, `$model->toArray()` or an API Resource
 *    is never reported. Those payloads are built by Eloquent, which honours
 *    `$hidden`/`$visible`, or by a Resource that whitelists its own fields.
 *  - `getAttributes()` / `makeVisible()` in a payload deliberately DEFEAT
 *    `$hidden`, so they are reported — but only when the model class is in the
 *    scan AND declares the column secret, in `$hidden`, `#[Hidden]`,
 *    `$guarded` or `#[Guarded]`. Attributes are read as well as properties:
 *    a Laravel 12+ model states this with `#[Hidden([...])]` and never
 *    declares a property at all.
 *  - A column the model declares secret AND the code emits behind a resolved
 *    condition is deliberate, controlled disclosure, not a leak.
 *
 * ---------------------------------------------------------------------------
 * ADVICE
 * ---------------------------------------------------------------------------
 *
 * A review finding carries no fix at all. An asserted finding whose payload
 * key is named in a response contract the file itself declares (a
 * `JSON_STRUCTURE`-style class constant) is never told to delete that key —
 * that would break the documented contract. It is told to redact the value.
 *
 * Every identifier named in a description, a proof or a fix is resolved from
 * the analysed file. Lines come from `Node::getStartLine()`, never a byte
 * offset. At most one finding is reported per method.
 */
final class SensitiveDataExposureDetector implements AccessControlDetector
{
    /**
     * Attribute names that are always credential material.
     *
     * @var array<int, string>
     */
    private const SENSITIVE_EXACT = [
        'password', 'password_hash', 'password_confirmation', 'plain_password',
        'remember_token', 'api_secret', 'api_key', 'api_token',
        'access_token', 'refresh_token', 'secret', 'client_secret',
        'private_key', 'secret_key', 'encryption_key', 'signing_key',
        'two_factor_secret', 'two_factor_recovery_codes',
        'ssn', 'social_security', 'social_security_number',
        'credit_card', 'card_number', 'cvv', 'cvc',
    ];

    /**
     * Names that LOOK like a secret under a suffix rule but provably are not.
     *
     * A public key is published on purpose, a CSRF token has to reach the page
     * to work, and `cache_key`/`sort_key`/`route_key`/`foreign_key` are
     * structural identifiers. Reporting any of them is a false positive.
     *
     * @var array<int, string>
     */
    private const NON_SECRET_NAMES = [
        'public_key', 'publishable_key', 'cache_key', 'sort_key', 'route_key',
        'foreign_key', 'primary_key', 'translation_key', 'locale_key',
        'group_key', 'meta_key', 'index_key', 'partition_key', 'unique_key',
        'idempotency_key', 'composite_key', 'natural_key', 'shard_key',
        'csrf_token', 'xsrf_token', '_token', 'page_token', 'next_page_token',
        'previous_page_token', 'continuation_token', 'cursor_token',
    ];

    /**
     * Qualifiers that turn a `*_key` name into a secret one. Without one of
     * these, a `_key` suffix means an identifier, not a credential.
     *
     * @var array<int, string>
     */
    private const SECRET_KEY_QUALIFIERS = [
        'secret', 'private', 'api', 'encryption', 'signing', 'master',
        'access', 'app', 'license', 'ssh', 'jwt', 'webhook',
    ];

    /**
     * Helpers whose result the framework serialises to the client. `redirect()`
     * and `back()` are deliberately absent: a password-reset URL legitimately
     * carries its token.
     *
     * @var array<int, string>
     */
    private const RESPONSE_HELPERS = ['response', 'view'];

    /**
     * Facades that build a serialised response.
     *
     * @var array<int, string>
     */
    private const RESPONSE_FACADES = [
        'Illuminate\Support\Facades\Response',
        'Illuminate\Support\Facades\View',
        'Illuminate\Http\JsonResponse',
        'Illuminate\Http\Response',
    ];

    /**
     * Base classes of an API Resource. A payload produced by one of these
     * whitelists its own fields, so the call site is not the place to report.
     *
     * @var array<int, string>
     */
    private const RESOURCE_CLASSES = [
        'Illuminate\Http\Resources\Json\JsonResource',
        'Illuminate\Http\Resources\Json\ResourceCollection',
        'Illuminate\Http\Resources\Json\AnonymousResourceCollection',
    ];

    /**
     * Model calls that deliberately defeat `$hidden`.
     *
     * @var array<int, string>
     */
    private const REDACTION_BYPASS_CALLS = ['getattributes', 'makevisible'];

    /**
     * `Illuminate\Http\Resources\ConditionallyLoadsAttributes` helpers.
     *
     * Every one of these returns a `MissingValue` when its condition is false,
     * and `JsonResource::removeMissingValues()` deletes the key before the
     * response is serialised. A value behind one of them is CONDITIONAL, and
     * describing it as "serialised directly" is factually false.
     *
     * @var array<int, string>
     */
    private const CONDITIONAL_ATTRIBUTE_CALLS = [
        'when', 'unless', 'whenhas', 'whennotnull', 'whenappended',
        'whencounted', 'whenloaded', 'whenpivotloaded', 'whenpivotloadedas',
        'mergewhen', 'mergeunless',
    ];

    /**
     * Calls that PROVE a condition is an access gate rather than a formatting
     * switch. `is()` is handled separately because it only proves ownership
     * when one of its arguments is the authenticated user.
     *
     * @var array<int, string>
     */
    private const GATE_CALLS = [
        'can', 'cant', 'cannot', 'allows', 'denies', 'authorize',
        'authorizeforuser', 'check', 'haspermissionto', 'hasanypermission',
        'checkpermissionto', 'hasrole', 'hasanyrole',
    ];

    /**
     * Calls that gate ACCESS to a value inside a method body.
     *
     * @var array<int, string>
     */
    private const AUTHORIZATION_CALLS = [
        'authorize', 'authorizeforuser', 'allows', 'denies', 'can', 'cant',
        'cannot', 'check', 'inspect',
    ];

    /**
     * Redaction declarations a model can carry, as property name => attribute
     * short name. `$guarded` / `#[Guarded]` are mass-assignment controls, not
     * serialisation controls, but naming a column there is still the
     * application stating that the column is not ordinary data.
     *
     * @var array<string, string>
     */
    private const REDACTION_DECLARATIONS = [
        'hidden' => 'Hidden',
        'guarded' => 'Guarded',
    ];

    private readonly SemanticWorkspace $workspace;

    public function __construct(?SemanticWorkspace $workspace = null)
    {
        $this->workspace = $workspace ?? new SemanticWorkspace;
    }

    public function detect(array $files, AccessControlContext $context): array
    {
        $semantics = $this->workspace->contextFor(
            array_map(
                static fn (SourceFile $file): array => [
                    'path' => $file->path,
                    'content' => $file->content,
                    'type' => $file->type,
                ],
                $files,
            ),
        );

        $findings = [];

        foreach ($files as $file) {
            $parsed = $semantics->parsed($file->path);

            if ($parsed === null || ! $parsed->isAnalysable()) {
                continue;
            }

            foreach ($parsed->classes() as $class) {
                $role = $this->classRole($class, $file, $semantics);

                foreach ($this->respondingMethods($class) as $method) {
                    $exposure = $this->firstExposureIn($method, $semantics, $role);

                    if ($exposure === null) {
                        continue;
                    }

                    $findings[] = $this->finding($file, $exposure);
                }
            }
        }

        return $findings;
    }

    /**
     * Methods that can build a response: every public, concrete, non-static one
     * plus `__invoke`, which the shared publicMethods() helper drops as magic
     * but which IS the action of a single-action controller.
     *
     * @return array<int, MethodShape>
     */
    private function respondingMethods(ClassShape $class): array
    {
        $methods = [];

        foreach ($class->methods() as $method) {
            if (! $method->isPublic() || $method->isStatic() || $method->isAbstract()) {
                continue;
            }

            if ($method->isMagic() && strtolower($method->name()) !== '__invoke') {
                continue;
            }

            $methods[] = $method;
        }

        return $methods;
    }

    /**
     * What this class is, and therefore what its bare `return [...]` means.
     *
     * @return array{responder: bool, kind: string, contract: array<int, string>}
     */
    private function classRole(ClassShape $class, SourceFile $file, SemanticContext $semantics): array
    {
        if ($this->isResourceClass($class->fqcn(), $semantics)) {
            return [
                'responder' => true,
                'kind' => 'API Resource',
                'contract' => $this->declaredContractKeys($class),
            ];
        }

        if ($semantics->semantics()->isController($class) || $file->type === 'controller') {
            return [
                'responder' => true,
                'kind' => 'controller',
                'contract' => $this->declaredContractKeys($class),
            ];
        }

        return [
            'responder' => false,
            'kind' => 'class',
            'contract' => $this->declaredContractKeys($class),
        ];
    }

    /**
     * Whether a class name is, or descends from, an API Resource.
     *
     * A `*Resource` / `*Collection` class outside the scan cannot be inspected;
     * treating it as a Resource keeps the analyzer silent at the call site,
     * which is the correct fallback.
     */
    private function isResourceClass(string $fqcn, SemanticContext $semantics): bool
    {
        if (in_array($fqcn, self::RESOURCE_CLASSES, true)) {
            return true;
        }

        if ($semantics->classes()->descendsFromAny($fqcn, self::RESOURCE_CLASSES)) {
            return true;
        }

        $short = TypeNames::shortName($fqcn);

        return str_ends_with($short, 'Resource') || str_ends_with($short, 'ResourceCollection');
    }

    /**
     * @param  array{line: int, assert: bool, location: string, description: string, proof: string, remedy: string}  $exposure
     */
    private function finding(SourceFile $file, array $exposure): Vulnerability
    {
        return new Vulnerability(
            type: VulnerabilityType::SensitiveDataExposure,
            location: $file->path,
            line: $exposure['line'],
            severity: SeverityLevel::High,
            description: $exposure['description'],
            proof: $exposure['proof'],
            fix: $exposure['assert'] ? $exposure['remedy'] : '',
            findingClass: $exposure['assert'] ? FindingClass::Vulnerability : FindingClass::Review,
            confidence: $exposure['assert'] ? Confidence::Proven : Confidence::Possible,
        );
    }

    /**
     * The single exposure this method is reported for, or null.
     *
     * Asserted exposures outrank review ones, so a method that both asks a
     * question at line 20 and proves a leak at line 40 reports the leak. Within
     * a class the earliest line wins.
     *
     * @param  array{responder: bool, kind: string, contract: array<int, string>}  $role
     * @return array{line: int, assert: bool, location: string, description: string, proof: string, remedy: string}|null
     */
    private function firstExposureIn(MethodShape $method, SemanticContext $semantics, array $role): ?array
    {
        $exposures = [];

        foreach ($this->serialisedExpressions($method, $semantics, $role) as $payload) {
            foreach ($this->explicitAttributeReads($payload, $method, $semantics, $role) as $exposure) {
                $exposures[] = $exposure;
            }

            foreach ($this->redactionBypasses($payload, $method, $semantics) as $exposure) {
                $exposures[] = $exposure;
            }
        }

        if ($exposures === []) {
            return null;
        }

        usort($exposures, static function (array $a, array $b): int {
            return [$b['assert'], $a['line']] <=> [$a['assert'], $b['line']];
        });

        return $exposures[0];
    }

    /**
     * Every expression this method hands to the framework for serialisation.
     *
     * @param  array{responder: bool, kind: string, contract: array<int, string>}  $role
     * @return array<int, array{expr: Node\Expr, sink: string}>
     */
    private function serialisedExpressions(MethodShape $method, SemanticContext $semantics, array $role): array
    {
        $statements = $method->statements();

        if ($statements === []) {
            return [];
        }

        $payloads = [];

        foreach ((new NodeFinder)->findInstanceOf($statements, Node\Stmt\Return_::class) as $return) {
            if ($return->expr === null) {
                continue;
            }

            foreach ($this->payloadsFrom($return->expr, $method, $semantics, $role, 0) as $payload) {
                $payloads[] = $payload;
            }
        }

        return $payloads;
    }

    /**
     * Unwrap a returned expression into the payload expressions it serialises.
     *
     * @param  array{responder: bool, kind: string, contract: array<int, string>}  $role
     * @return array<int, array{expr: Node\Expr, sink: string}>
     */
    private function payloadsFrom(Node\Expr $expr, MethodShape $method, SemanticContext $semantics, array $role, int $depth): array
    {
        if ($depth > 4) {
            return [];
        }

        if ($this->isApiResourceExpression($expr, $method, $semantics)) {
            // A Resource decides its own payload. If it leaks, the leak is in
            // the Resource's toArray(), which is analysed on its own terms.
            return [];
        }

        if ($expr instanceof Node\Expr\Array_) {
            // A bare array only reaches a caller when the class exists to
            // answer a request. A Job's headers() array is an outbound HTTP
            // header bag; a repository's array is a return value.
            return $role['responder']
                ? [['expr' => $expr, 'sink' => $this->bareArraySink($method, $role)]]
                : [];
        }

        if ($expr instanceof Node\Expr\Ternary) {
            $branches = [];

            foreach ([$expr->if, $expr->else] as $branch) {
                if (! $branch instanceof Node\Expr) {
                    continue;
                }

                foreach ($this->payloadsFrom($branch, $method, $semantics, $role, $depth + 1) as $payload) {
                    $branches[] = $payload;
                }
            }

            return $branches;
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            $assignment = $semantics->semantics()->receivers()
                ->assignmentsFor($method)
                ->reaching($expr->name, $expr->getStartLine());

            if ($assignment === null || $assignment['append'] || $assignment['iterated']) {
                return [];
            }

            return $this->payloadsFrom($assignment['expr'], $method, $semantics, $role, $depth + 1);
        }

        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            $name = strtolower(TypeNames::shortName($method->file()->resolveName($expr->name)));

            if ($name === 'compact') {
                return $role['responder']
                    ? [['expr' => $expr, 'sink' => $this->bareArraySink($method, $role)]]
                    : [];
            }

            if (in_array($name, self::RESPONSE_HELPERS, true)) {
                return $this->argumentPayloads($expr->args, $name.'()');
            }

            return [];
        }

        if ($expr instanceof Node\Expr\New_ && $expr->class instanceof Node\Name) {
            $class = $method->file()->resolveName($expr->class);

            return in_array($class, self::RESPONSE_FACADES, true)
                ? $this->argumentPayloads($expr->args, 'new '.TypeNames::shortName($class))
                : [];
        }

        if ($expr instanceof Node\Expr\StaticCall && $expr->class instanceof Node\Name) {
            $class = $method->file()->resolveName($expr->class);

            return in_array($class, self::RESPONSE_FACADES, true)
                ? $this->argumentPayloads($expr->args, TypeNames::shortName($class).'::'.$this->callName($expr).'()')
                : [];
        }

        if ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\NullsafeMethodCall) {
            return $this->isResponseBuilder($expr, $method, $semantics)
                ? $this->argumentPayloads($expr->args, $this->responseBuilderLabel($expr, $method))
                : [];
        }

        return [];
    }

    /**
     * How to describe the array a responder returns straight to the framework.
     *
     * @param  array{responder: bool, kind: string, contract: array<int, string>}  $role
     */
    private function bareArraySink(MethodShape $method, array $role): string
    {
        return sprintf(
            'the array %s::%s() returns, which the framework serialises to the caller because %s is %s %s',
            $method->class()->shortName(),
            $method->name(),
            $method->class()->shortName(),
            $role['kind'] === 'API Resource' ? 'an' : 'a',
            $role['kind'],
        );
    }

    /**
     * Name of a response builder chain, e.g. `response()->json()`.
     */
    private function responseBuilderLabel(Node\Expr $expr, MethodShape $method): string
    {
        $names = [];
        $current = $expr;

        for ($step = 0; $step < 8; $step++) {
            if (! $current instanceof Node\Expr\MethodCall && ! $current instanceof Node\Expr\NullsafeMethodCall) {
                break;
            }

            array_unshift($names, $this->callName($current).'()');
            $current = $current->var;
        }

        if ($current instanceof Node\Expr\FuncCall && $current->name instanceof Node\Name) {
            array_unshift($names, $current->name->toString().'()');
        }

        if ($current instanceof Node\Expr\StaticCall && $current->class instanceof Node\Name) {
            array_unshift($names, TypeNames::shortName($method->file()->resolveName($current->class)).'::'.$this->callName($current).'()');
        }

        return $names === [] ? 'the response builder' : implode('->', $names);
    }

    private function callName(Node\Expr\MethodCall|Node\Expr\NullsafeMethodCall|Node\Expr\StaticCall $call): string
    {
        return $call->name instanceof Node\Identifier ? $call->name->toString() : 'call';
    }

    /**
     * Whether a fluent call chain is rooted in a response/view builder.
     *
     * This is the guard that stops Eloquent's `->with('author')` eager load from
     * reading as `view()->with([...])` view data: the ROOT of the chain decides,
     * never the verb.
     */
    private function isResponseBuilder(Node\Expr $expr, MethodShape $method, SemanticContext $semantics): bool
    {
        $root = $semantics->semantics()->receivers()->chainRoot($expr);

        if ($root instanceof Node\Expr\FuncCall && $root->name instanceof Node\Name) {
            $name = strtolower(TypeNames::shortName($method->file()->resolveName($root->name)));

            return in_array($name, self::RESPONSE_HELPERS, true);
        }

        if ($root instanceof Node\Expr\StaticCall && $root->class instanceof Node\Name) {
            return in_array($method->file()->resolveName($root->class), self::RESPONSE_FACADES, true);
        }

        if ($root instanceof Node\Expr\New_ && $root->class instanceof Node\Name) {
            return in_array($method->file()->resolveName($root->class), self::RESPONSE_FACADES, true);
        }

        return false;
    }

    /**
     * Whether an expression builds an API Resource, whose own toArray() decides
     * what is emitted.
     */
    private function isApiResourceExpression(Node\Expr $expr, MethodShape $method, SemanticContext $semantics): bool
    {
        $class = null;

        if ($expr instanceof Node\Expr\New_ && $expr->class instanceof Node\Name) {
            $class = $method->file()->resolveName($expr->class);
        }

        if ($expr instanceof Node\Expr\StaticCall && $expr->class instanceof Node\Name) {
            $class = $method->file()->resolveName($expr->class);
        }

        if ($class === null) {
            return false;
        }

        if (in_array($class, self::RESOURCE_CLASSES, true)) {
            return true;
        }

        if ($semantics->classes()->descendsFromAny($class, self::RESOURCE_CLASSES)) {
            return true;
        }

        // A *Resource / *Collection class that is not part of this scan cannot
        // be inspected; treating it as a Resource keeps us silent, which is the
        // correct fallback.
        $short = TypeNames::shortName($class);

        return $semantics->classes()->find($class) === null
            && (str_ends_with($short, 'Resource') || str_ends_with($short, 'ResourceCollection'));
    }

    /**
     * Argument values of a serialising call, as payload expressions.
     *
     * @param  array<int, Node\Arg|Node\VariadicPlaceholder>  $args
     * @return array<int, array{expr: Node\Expr, sink: string}>
     */
    private function argumentPayloads(array $args, string $sink): array
    {
        $payloads = [];

        foreach ($args as $argument) {
            if ($argument instanceof Node\Arg) {
                $payloads[] = ['expr' => $argument->value, 'sink' => $sink];
            }
        }

        return $payloads;
    }

    /**
     * Sensitive attributes read EXPLICITLY inside a payload.
     *
     * @param  array{expr: Node\Expr, sink: string}  $payload
     * @param  array{responder: bool, kind: string, contract: array<int, string>}  $role
     * @return array<int, array{line: int, assert: bool, location: string, description: string, proof: string, remedy: string}>
     */
    private function explicitAttributeReads(array $payload, MethodShape $method, SemanticContext $semantics, array $role): array
    {
        $found = [];

        foreach ($this->attributeReadsIn($payload['expr'], $method, $semantics) as $read) {
            $fetch = $read['fetch'];

            if (! $fetch->name instanceof Node\Identifier) {
                continue;
            }

            $attribute = $fetch->name->toString();

            if (! $this->isSensitiveAttribute($attribute)) {
                continue;
            }

            $receiver = $this->modelReceiver($fetch->var, $method, $semantics);

            if ($receiver === null) {
                continue;
            }

            $exposure = $this->judgeRead(
                fetch: $fetch,
                boundary: $read['boundary'],
                attribute: $attribute,
                receiver: $receiver,
                payload: $payload,
                method: $method,
                semantics: $semantics,
                role: $role,
            );

            if ($exposure !== null) {
                $found[] = $exposure;
            }
        }

        return $found;
    }

    /**
     * Decide what, if anything, one sensitive read proves.
     *
     * Returns null when the read is provably not an exposure (a resolved access
     * gate), a Review exposure when a link of the chain is unresolved, and an
     * asserted exposure only when every link holds.
     *
     * @param  array{label: string, evidence: string, class: string|null, self: bool}  $receiver
     * @param  array{expr: Node\Expr, sink: string}  $payload
     * @param  array{responder: bool, kind: string, contract: array<int, string>}  $role
     * @return array{line: int, assert: bool, location: string, description: string, proof: string, remedy: string}|null
     */
    private function judgeRead(
        Node\Expr\PropertyFetch|Node\Expr\NullsafePropertyFetch $fetch,
        Node $boundary,
        string $attribute,
        array $receiver,
        array $payload,
        MethodShape $method,
        SemanticContext $semantics,
        array $role,
    ): ?array {
        $line = $fetch->getStartLine();
        $ancestors = $this->ancestorsWithin($fetch, $boundary);
        $key = $this->payloadKeyFor($ancestors);
        $redaction = $this->declaredRedaction($receiver['class'], $attribute, $semantics);

        $wrapper = $this->conditionalWrapper($ancestors, $method, $semantics);

        if ($wrapper !== null) {
            $gate = $this->resolvedGateFor($wrapper, $method, $semantics);
            $wrapperName = $this->callName($wrapper);

            if ($gate !== null) {
                // ConditionallyLoadsAttributes returns MissingValue when the
                // condition is false and removeMissingValues() strips the key,
                // and the condition itself is a resolved access gate. Nothing
                // to report and nothing to ask.
                return null;
            }

            return $this->reviewExposure(
                line: $line,
                attribute: $attribute,
                method: $method,
                reason: sprintf(
                    'the value is wrapped in ->%s(), so it is conditional, not direct',
                    $wrapperName,
                ),
                proof: sprintf(
                    "Line %d reads '%s' from %s, but the read sits inside ->%s() at line %d. %s returns a MissingValue when its condition is false and JsonResource::removeMissingValues() strips the key before the response is built, so the value is NOT serialised unconditionally. %s The analyzer could not resolve what the condition at line %d decides, so it asks rather than asserts.%s",
                    $line,
                    $attribute,
                    $receiver['label'],
                    $wrapperName,
                    $wrapper->getStartLine(),
                    $wrapperName.'()',
                    $receiver['evidence'],
                    $wrapper->getStartLine(),
                    $this->redactionSentence($receiver, $attribute, $redaction),
                ),
            );
        }

        if ($receiver['self']) {
            return $this->reviewExposure(
                line: $line,
                attribute: $attribute,
                method: $method,
                reason: 'the receiver is the authenticated caller, so this is self-disclosure',
                proof: sprintf(
                    "Line %d reads '%s' from the authenticated caller's own record, not from a record chosen by a request parameter, so nobody but the owner receives it on this path. Laravel Fortify's TwoFactorSecretKeyController and every \"show me my API key\" screen do the same thing deliberately. Whether this endpoint should hand the owner their own '%s' is a product decision this analyzer cannot make.%s",
                    $line,
                    $attribute,
                    $attribute,
                    $this->redactionSentence($receiver, $attribute, $redaction),
                ),
            );
        }

        $guard = $this->authorizationGuard($fetch->var, $method);

        if ($guard !== null) {
            return $this->reviewExposure(
                line: $line,
                attribute: $attribute,
                method: $method,
                reason: sprintf('access to %s is gated by %s', $receiver['label'], $guard),
                proof: sprintf(
                    "Line %d reads '%s' from %s, and %s guards %s earlier in the same method. Whether that policy admits anyone who should not receive '%s' is decided in the policy, which this analyzer has not evaluated. %s%s",
                    $line,
                    $attribute,
                    $receiver['label'],
                    $guard,
                    $receiver['label'],
                    $attribute,
                    $receiver['evidence'],
                    $this->redactionSentence($receiver, $attribute, $redaction),
                ),
            );
        }

        $derivation = $this->derivationBetween($ancestors, $method);

        if ($derivation !== null) {
            return $this->reviewExposure(
                line: $line,
                attribute: $attribute,
                method: $method,
                reason: sprintf('the value passes through %s before reaching the payload', $derivation),
                proof: sprintf(
                    "Line %d reads '%s' from %s, but the value is an argument to %s, so what the caller receives is that call's result and not necessarily the raw attribute. %s The analyzer does not know whether %s masks, signs, hashes or reproduces the value, so it asks rather than asserts.%s",
                    $line,
                    $attribute,
                    $receiver['label'],
                    $derivation,
                    $receiver['evidence'],
                    $derivation,
                    $this->redactionSentence($receiver, $attribute, $redaction),
                ),
            );
        }

        return [
            'line' => $line,
            'assert' => true,
            'location' => sprintf('%s::%s()', $method->class()->shortName(), $method->name()),
            'description' => sprintf(
                '%s::%s() serialises a sensitive attribute (%s) into the response. The raw value reaches every caller of this endpoint (Sensitive Data Exposure, CWE-200).',
                $method->class()->shortName(),
                $method->name(),
                $attribute,
            ),
            'proof' => sprintf(
                "Line %d reads '%s' from %s and places the value%s in %s. There is no when()/unless() wrapper around it and no call between the read and the payload, so the raw value is what the caller receives. %s %s%s",
                $line,
                $attribute,
                $receiver['label'],
                $key === null ? '' : sprintf(" under the key '%s'", $key),
                $payload['sink'],
                $receiver['evidence'],
                $this->hiddenIsNoDefenceSentence($receiver, $attribute, $redaction),
                $this->contractSentence($role, $key, $method),
            ),
            'remedy' => $this->remedy($attribute, $key, $method, $role),
        ];
    }

    /**
     * A review exposure: a question, never an assertion, and never a fix.
     *
     * @return array{line: int, assert: bool, location: string, description: string, proof: string, remedy: string}
     */
    private function reviewExposure(int $line, string $attribute, MethodShape $method, string $reason, string $proof): array
    {
        return [
            'line' => $line,
            'assert' => false,
            'location' => sprintf('%s::%s()', $method->class()->shortName(), $method->name()),
            'description' => sprintf(
                "Does %s::%s() intend to disclose '%s' here? The analyzer could not prove it does — %s — so this is a question for a human, not a finding (Sensitive Data Exposure, CWE-200).",
                $method->class()->shortName(),
                $method->name(),
                $attribute,
                $reason,
            ),
            'proof' => $proof,
            'remedy' => '',
        ];
    }

    /**
     * The sentence that reports the "$hidden does not redact this" link of the
     * chain, plus whatever the model itself declares.
     *
     * @param  array{label: string, evidence: string, class: string|null, self: bool}  $receiver
     * @param  array<int, string>  $redaction
     */
    private function hiddenIsNoDefenceSentence(array $receiver, string $attribute, array $redaction): string
    {
        $base = sprintf(
            "\$hidden does not redact this read: \$hidden and #[Hidden] filter a model that Eloquent serialises for you, and '%s' is read explicitly here, so the raw value reaches the payload either way.",
            $attribute,
        );

        if ($redaction === []) {
            return $base;
        }

        return $base.' '.sprintf(
            "%s declares '%s' in %s, so the application itself classifies the column as secret.",
            TypeNames::shortName((string) $receiver['class']),
            $attribute,
            $this->listOf($redaction),
        );
    }

    /**
     * The model-redaction sentence appended to a review proof.
     *
     * @param  array{label: string, evidence: string, class: string|null, self: bool}  $receiver
     * @param  array<int, string>  $redaction
     */
    private function redactionSentence(array $receiver, string $attribute, array $redaction): string
    {
        if ($redaction === [] || $receiver['class'] === null) {
            return '';
        }

        return ' '.sprintf(
            "%s declares '%s' in %s, so the disclosure that does happen on this path is one the application declared deliberately.",
            TypeNames::shortName($receiver['class']),
            $attribute,
            $this->listOf($redaction),
        );
    }

    /**
     * Note that the payload key belongs to a response contract the file itself
     * declares, so that the advice never contradicts it.
     *
     * @param  array{responder: bool, kind: string, contract: array<int, string>}  $role
     */
    private function contractSentence(array $role, ?string $key, MethodShape $method): string
    {
        if ($key === null || ! in_array($key, $role['contract'], true)) {
            return '';
        }

        return ' '.sprintf(
            "'%s' is also named in a response-contract constant %s declares, so the key itself is part of this file's published payload shape.",
            $key,
            $method->class()->shortName(),
        );
    }

    /**
     * Advice for an asserted exposure.
     *
     * A key the file's own response contract declares is never deleted — that
     * breaks the contract. It is redacted instead.
     *
     * @param  array{responder: bool, kind: string, contract: array<int, string>}  $role
     */
    private function remedy(string $attribute, ?string $key, MethodShape $method, array $role): string
    {
        if ($key !== null && in_array($key, $role['contract'], true)) {
            return sprintf(
                "Stop emitting the raw '%s' value from %s::%s() while keeping the '%s' key, which this file's own response-contract constant declares — deleting the key would break that contract. Emit a redacted or derived value instead (a masked suffix, a one-way fingerprint), or gate the value behind an ownership check so only the record's owner ever receives it. A \$hidden entry does NOT stop this leak: \$hidden only filters a model that Eloquent serialises for you, and an attribute read explicitly and placed in an array is serialised regardless.",
                $attribute,
                $method->class()->shortName(),
                $method->name(),
                $key,
            );
        }

        return sprintf(
            "Remove '%s' from the payload built by %s::%s(). A \$hidden entry does NOT stop this leak: \$hidden only filters a model that Eloquent serialises for you, and an attribute read explicitly and placed in an array is serialised regardless. Emit only the non-secret fields the caller needs, or an API Resource that whitelists them.",
            $attribute,
            $method->class()->shortName(),
            $method->name(),
        );
    }

    /**
     * Property reads inside a payload, excluding anything sitting in an array
     * KEY position. `['password' => $user->name]` names a field; it does not
     * read one.
     *
     * Each read carries the payload node it was found under, so the ancestor
     * walk that classifies it knows where to stop.
     *
     * @return array<int, array{fetch: Node\Expr\PropertyFetch|Node\Expr\NullsafePropertyFetch, boundary: Node}>
     */
    private function attributeReadsIn(Node\Expr $payload, MethodShape $method, SemanticContext $semantics): array
    {
        $sources = [$payload];

        if ($payload instanceof Node\Expr\FuncCall
            && $payload->name instanceof Node\Name
            && strtolower(TypeNames::shortName($method->file()->resolveName($payload->name))) === 'compact') {
            $sources = $this->compactSources($payload, $method, $semantics);
        }

        $reads = [];

        foreach ($sources as $source) {
            foreach ((new NodeFinder)->find($source, static fn (Node $node): bool => $node instanceof Node\Expr\PropertyFetch || $node instanceof Node\Expr\NullsafePropertyFetch) as $fetch) {
                if (! $fetch instanceof Node\Expr\PropertyFetch && ! $fetch instanceof Node\Expr\NullsafePropertyFetch) {
                    continue;
                }

                if ($this->isInsideArrayKey($fetch, $source)) {
                    continue;
                }

                $reads[] = ['fetch' => $fetch, 'boundary' => $source];
            }
        }

        return $reads;
    }

    /**
     * The expressions `compact('user', 'password')` actually serialises: the
     * assignment that reaches each named variable.
     *
     * @return array<int, Node\Expr>
     */
    private function compactSources(Node\Expr\FuncCall $compact, MethodShape $method, SemanticContext $semantics): array
    {
        $assignments = $semantics->semantics()->receivers()->assignmentsFor($method);
        $sources = [];

        foreach ($compact->args as $argument) {
            if (! $argument instanceof Node\Arg || ! $argument->value instanceof Node\Scalar\String_) {
                continue;
            }

            $assignment = $assignments->reaching($argument->value->value, $compact->getStartLine());

            if ($assignment === null || $assignment['iterated']) {
                continue;
            }

            $sources[] = $assignment['expr'];
        }

        return $sources;
    }

    /**
     * Ancestors of a node up to, but excluding, the payload boundary, nearest
     * first. An empty list means the node IS the payload.
     *
     * @return array<int, Node>
     */
    private function ancestorsWithin(Node $node, Node $boundary): array
    {
        if ($node === $boundary) {
            return [];
        }

        $chain = [];
        $current = $node;

        for ($step = 0; $step < 64; $step++) {
            $parent = $current->getAttribute('parent');

            if (! $parent instanceof Node || $parent === $boundary) {
                return $chain;
            }

            $chain[] = $parent;
            $current = $parent;
        }

        return $chain;
    }

    /**
     * Whether a node sits in the KEY half of an array item, walking the parent
     * links the parser attached rather than measuring text.
     */
    private function isInsideArrayKey(Node $node, Node $boundary): bool
    {
        $current = $node;

        for ($step = 0; $step < 64; $step++) {
            if ($current === $boundary) {
                return false;
            }

            $parent = $current->getAttribute('parent');

            if (! $parent instanceof Node) {
                return false;
            }

            if ($parent instanceof Node\ArrayItem && $parent->key === $current) {
                return true;
            }

            $current = $parent;
        }

        return false;
    }

    /**
     * The payload key a read is emitted under, when the code states one.
     *
     * @param  array<int, Node>  $ancestors
     */
    private function payloadKeyFor(array $ancestors): ?string
    {
        foreach ($ancestors as $ancestor) {
            if ($ancestor instanceof Node\ArrayItem && $ancestor->key instanceof Node\Scalar\String_) {
                return $ancestor->key->value;
            }
        }

        return null;
    }

    /**
     * The `ConditionallyLoadsAttributes` call a read sits inside, if any.
     *
     * Only `$this->when(...)` style calls count, plus any such call inside a
     * class that IS an API Resource — that is where the trait lives. A
     * Collection's `when()` elsewhere is not this mechanism.
     *
     * @param  array<int, Node>  $ancestors
     */
    private function conditionalWrapper(array $ancestors, MethodShape $method, SemanticContext $semantics): Node\Expr\MethodCall|Node\Expr\NullsafeMethodCall|null
    {
        foreach ($ancestors as $ancestor) {
            if (! $ancestor instanceof Node\Expr\MethodCall && ! $ancestor instanceof Node\Expr\NullsafeMethodCall) {
                continue;
            }

            if (! $ancestor->name instanceof Node\Identifier) {
                continue;
            }

            if (! in_array(strtolower($ancestor->name->toString()), self::CONDITIONAL_ATTRIBUTE_CALLS, true)) {
                continue;
            }

            $onThis = $ancestor->var instanceof Node\Expr\Variable && $ancestor->var->name === 'this';

            if ($onThis || $this->isResourceClass($method->class()->fqcn(), $semantics)) {
                return $ancestor;
            }
        }

        return null;
    }

    /**
     * The access gate a conditional wrapper's condition resolves to, or null.
     *
     * Resolved means: an authorization call, or an identity comparison against
     * the authenticated user. `$this->when($isCurrentUser, ...)` where
     * `$isCurrentUser = $this->user->is($request->user())` resolves; a
     * condition the analyzer cannot follow does not, and an unresolved
     * condition is a question.
     */
    private function resolvedGateFor(Node\Expr\MethodCall|Node\Expr\NullsafeMethodCall $wrapper, MethodShape $method, SemanticContext $semantics): ?string
    {
        $first = $wrapper->args[0] ?? null;

        if (! $first instanceof Node\Arg) {
            return null;
        }

        return $this->gateEvidence($first->value, $method, $semantics, 0);
    }

    /**
     * Describe the access gate an expression performs, following the
     * assignment that reaches a variable.
     */
    private function gateEvidence(Node\Expr $expr, MethodShape $method, SemanticContext $semantics, int $depth): ?string
    {
        if ($depth > 3) {
            return null;
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            $assignment = $semantics->semantics()->receivers()
                ->assignmentsFor($method)
                ->reaching($expr->name, $expr->getStartLine());

            if ($assignment === null || $assignment['append'] || $assignment['iterated']) {
                return null;
            }

            $inner = $this->gateEvidence($assignment['expr'], $method, $semantics, $depth + 1);

            return $inner === null
                ? null
                : sprintf('$%s, assigned on line %d from %s', $expr->name, $assignment['line'], $inner);
        }

        if ($expr instanceof Node\Expr\BooleanNot) {
            return $this->gateEvidence($expr->expr, $method, $semantics, $depth + 1);
        }

        foreach ((new NodeFinder)->find([$expr], static fn (Node $node): bool => $node instanceof Node\Expr\MethodCall
            || $node instanceof Node\Expr\NullsafeMethodCall
            || $node instanceof Node\Expr\StaticCall) as $call) {
            if (! $call instanceof Node\Expr\MethodCall && ! $call instanceof Node\Expr\NullsafeMethodCall && ! $call instanceof Node\Expr\StaticCall) {
                continue;
            }

            if (! $call->name instanceof Node\Identifier) {
                continue;
            }

            $name = strtolower($call->name->toString());

            if (in_array($name, self::GATE_CALLS, true)) {
                return sprintf('a %s() authorization check on line %d', $call->name->toString(), $call->getStartLine());
            }

            if ($name !== 'is') {
                continue;
            }

            foreach ($call->args as $argument) {
                if ($argument instanceof Node\Arg && $this->isAuthenticatedUser($argument->value, $method, $semantics)) {
                    return sprintf(
                        'an is() identity comparison against the authenticated user on line %d',
                        $call->getStartLine(),
                    );
                }
            }
        }

        return null;
    }

    /**
     * The call a read passes through before reaching the payload, if any.
     *
     * `route('notes.shared', $note->share_token)` emits a URL, not the token;
     * `decrypt($user->two_factor_secret)` emits plaintext the helper produced.
     * Either way the analyzer cannot claim the raw attribute is what the caller
     * receives. Concatenation and interpolation are NOT derivations — they
     * reproduce the value verbatim.
     *
     * @param  array<int, Node>  $ancestors
     */
    private function derivationBetween(array $ancestors, MethodShape $method): ?string
    {
        foreach ($ancestors as $ancestor) {
            if ($ancestor instanceof Node\Expr\FuncCall && $ancestor->name instanceof Node\Name) {
                return TypeNames::shortName($method->file()->resolveName($ancestor->name)).'()';
            }

            if ($ancestor instanceof Node\Expr\StaticCall && $ancestor->class instanceof Node\Name) {
                return TypeNames::shortName($method->file()->resolveName($ancestor->class)).'::'.$this->callName($ancestor).'()';
            }

            if ($ancestor instanceof Node\Expr\MethodCall || $ancestor instanceof Node\Expr\NullsafeMethodCall) {
                return '->'.$this->callName($ancestor).'()';
            }
        }

        return null;
    }

    /**
     * The authorization call in this method that names the same receiver, if
     * any. `$this->authorize('share', $note)` guards `$note`.
     */
    private function authorizationGuard(Node\Expr $receiver, MethodShape $method): ?string
    {
        $label = $this->label($receiver);

        if ($label === null) {
            return null;
        }

        $statements = $method->statements();

        if ($statements === []) {
            return null;
        }

        foreach ((new NodeFinder)->find($statements, static fn (Node $node): bool => $node instanceof Node\Expr\MethodCall
            || $node instanceof Node\Expr\NullsafeMethodCall
            || $node instanceof Node\Expr\StaticCall) as $call) {
            if (! $call instanceof Node\Expr\MethodCall && ! $call instanceof Node\Expr\NullsafeMethodCall && ! $call instanceof Node\Expr\StaticCall) {
                continue;
            }

            if (! $call->name instanceof Node\Identifier) {
                continue;
            }

            if (! in_array(strtolower($call->name->toString()), self::AUTHORIZATION_CALLS, true)) {
                continue;
            }

            foreach ($call->args as $argument) {
                if (! $argument instanceof Node\Arg) {
                    continue;
                }

                if ($this->mentionsLabel($argument->value, $label)) {
                    return sprintf('%s() on line %d', $call->name->toString(), $call->getStartLine());
                }
            }
        }

        return null;
    }

    /**
     * Whether an expression tree contains the exact receiver the read used.
     */
    private function mentionsLabel(Node $node, string $label): bool
    {
        return (new NodeFinder)->findFirst(
            [$node],
            fn (Node $candidate): bool => $candidate instanceof Node\Expr && $this->label($candidate) === $label,
        ) !== null;
    }

    /**
     * `getAttributes()` / `makeVisible()` inside a payload, reported only when
     * the model's OWN redaction declaration proves a secret column exists.
     *
     * @param  array{expr: Node\Expr, sink: string}  $payload
     * @return array<int, array{line: int, assert: bool, location: string, description: string, proof: string, remedy: string}>
     */
    private function redactionBypasses(array $payload, MethodShape $method, SemanticContext $semantics): array
    {
        $found = [];

        foreach ((new NodeFinder)->findInstanceOf([$payload['expr']], Node\Expr\MethodCall::class) as $call) {
            if (! $call->name instanceof Node\Identifier) {
                continue;
            }

            $verb = strtolower($call->name->toString());

            if (! in_array($verb, self::REDACTION_BYPASS_CALLS, true)) {
                continue;
            }

            $receiver = $this->modelReceiver($call->var, $method, $semantics);

            if ($receiver === null || $receiver['class'] === null) {
                continue;
            }

            $model = $semantics->classes()->find($receiver['class']);

            if ($model === null) {
                continue;
            }

            $hidden = $this->redactedColumns($model, 'hidden', $semantics);
            $attribute = $verb === 'makevisible'
                ? $this->firstNamedHiddenAttribute($call, $hidden)
                : $this->firstSensitive($hidden);

            if ($attribute === null) {
                continue;
            }

            $verbName = $call->name->toString();
            $guard = $this->authorizationGuard($call->var, $method);

            if ($guard !== null) {
                $found[] = $this->reviewExposure(
                    line: $call->getStartLine(),
                    attribute: $attribute,
                    method: $method,
                    reason: sprintf('access to %s is gated by %s', $receiver['label'], $guard),
                    proof: sprintf(
                        "Line %d calls %s->%s(), which bypasses the redaction %s declares for '%s', but %s guards %s earlier in the same method. Whether that policy admits anyone who should not receive '%s' is decided in the policy, which this analyzer has not evaluated.",
                        $call->getStartLine(),
                        $receiver['label'],
                        $verbName,
                        $model->shortName(),
                        $attribute,
                        $guard,
                        $receiver['label'],
                        $attribute,
                    ),
                );

                continue;
            }

            $found[] = [
                'line' => $call->getStartLine(),
                'assert' => true,
                'location' => sprintf('%s::%s()', $method->class()->shortName(), $method->name()),
                'description' => sprintf(
                    '%s::%s() serialises a sensitive attribute (%s) into the response. The raw value reaches every caller of this endpoint (Sensitive Data Exposure, CWE-200).',
                    $method->class()->shortName(),
                    $method->name(),
                    $attribute,
                ),
                'proof' => sprintf(
                    "Line %d calls %s->%s(), whose result is placed in %s. %s declares '%s' in %s, so the application itself states that the column must not be serialised, and %s() defeats exactly that redaction. \$hidden is the control being bypassed here, not a defence.",
                    $call->getStartLine(),
                    $receiver['label'],
                    $verbName,
                    $payload['sink'],
                    $model->shortName(),
                    $attribute,
                    $this->listOf($this->redactionSitesFor($model, $attribute, $semantics)),
                    $verbName,
                ),
                'remedy' => $verb === 'makevisible'
                    ? sprintf(
                        "Drop the %s() call at line %d. '%s' is listed in %s::\$hidden precisely so that it is never serialised; un-hiding it here republishes it to every caller of this endpoint.",
                        $verbName,
                        $call->getStartLine(),
                        $attribute,
                        $model->shortName(),
                    )
                    : sprintf(
                        "Serialise the model itself (or its toArray()), which honours the \$hidden array %s already declares. %s() returns the raw attribute bag and re-exposes '%s'.",
                        $model->shortName(),
                        $verbName,
                        $attribute,
                    ),
            ];
        }

        return $found;
    }

    /**
     * The `$hidden` attribute a `makeVisible(...)` call re-exposes, if any.
     *
     * @param  array<int, string>  $hidden
     */
    private function firstNamedHiddenAttribute(Node\Expr\MethodCall $call, array $hidden): ?string
    {
        foreach ($call->args as $argument) {
            if (! $argument instanceof Node\Arg) {
                continue;
            }

            $names = [];

            if ($argument->value instanceof Node\Scalar\String_) {
                $names[] = $argument->value->value;
            }

            if ($argument->value instanceof Node\Expr\Array_) {
                foreach ($argument->value->items as $item) {
                    if ($item->value instanceof Node\Scalar\String_) {
                        $names[] = $item->value->value;
                    }
                }
            }

            foreach ($names as $name) {
                if (in_array(strtolower($name), array_map('strtolower', $hidden), true)
                    && $this->isSensitiveAttribute($name)) {
                    return $name;
                }
            }
        }

        return null;
    }

    /**
     * @param  array<int, string>  $names
     */
    private function firstSensitive(array $names): ?string
    {
        foreach ($names as $name) {
            if ($this->isSensitiveAttribute($name)) {
                return $name;
            }
        }

        return null;
    }

    /**
     * Columns a model declares redacted under one heading, from BOTH the
     * `$hidden`-style property and the `#[Hidden]`-style attribute, across the
     * class and every ancestor that is in the scan.
     *
     * Laravel 12 models frequently declare `#[Hidden([...])]` and never write
     * the property at all; a detector that reads only properties sees an empty
     * list and concludes the application never classified the column.
     *
     * @return array<int, string>
     */
    private function redactedColumns(ClassShape $class, string $heading, SemanticContext $semantics): array
    {
        $names = [];

        foreach ($semantics->classes()->ancestry($class->fqcn()) as $ancestorName) {
            $ancestor = $semantics->classes()->find($ancestorName);

            if ($ancestor === null) {
                continue;
            }

            foreach ($this->declaredStringArray($ancestor, $heading) as $name) {
                $names[] = $name;
            }

            foreach ($this->declaredAttributeArray($ancestor, self::REDACTION_DECLARATIONS[$heading]) as $name) {
                $names[] = $name;
            }
        }

        return array_values(array_unique($names));
    }

    /**
     * Where a model declares a column redacted, named exactly as the source
     * writes it: `$hidden`, `#[Hidden]`, `$guarded`, `#[Guarded]`.
     *
     * @return array<int, string>
     */
    private function redactionSitesFor(ClassShape $class, string $attribute, SemanticContext $semantics): array
    {
        $sites = [];
        $needle = strtolower($attribute);

        foreach ($semantics->classes()->ancestry($class->fqcn()) as $ancestorName) {
            $ancestor = $semantics->classes()->find($ancestorName);

            if ($ancestor === null) {
                continue;
            }

            foreach (self::REDACTION_DECLARATIONS as $property => $attributeName) {
                if (in_array($needle, array_map('strtolower', $this->declaredStringArray($ancestor, $property)), true)) {
                    $sites[] = '$'.$property;
                }

                if (in_array($needle, array_map('strtolower', $this->declaredAttributeArray($ancestor, $attributeName)), true)) {
                    $sites[] = '#['.$attributeName.']';
                }
            }
        }

        return array_values(array_unique($sites));
    }

    /**
     * Every place the model that owns an attribute declares it redacted.
     *
     * @return array<int, string>
     */
    private function declaredRedaction(?string $modelClass, string $attribute, SemanticContext $semantics): array
    {
        if ($modelClass === null) {
            return [];
        }

        $model = $semantics->classes()->find($modelClass);

        return $model === null ? [] : $this->redactionSitesFor($model, $attribute, $semantics);
    }

    /**
     * The string literals of a declared array property, from the AST. A comment
     * inside the array is not a node, so it cannot influence the result.
     *
     * @return array<int, string>
     */
    private function declaredStringArray(ClassShape $class, string $property): array
    {
        foreach ($class->node()->stmts as $statement) {
            if (! $statement instanceof Node\Stmt\Property) {
                continue;
            }

            foreach ($statement->props as $item) {
                if ($item->name->toString() !== $property || ! $item->default instanceof Node\Expr\Array_) {
                    continue;
                }

                $values = [];

                foreach ($item->default->items as $element) {
                    if ($element->value instanceof Node\Scalar\String_) {
                        $values[] = $element->value->value;
                    }
                }

                return $values;
            }
        }

        return [];
    }

    /**
     * The string literals of a class ATTRIBUTE that carries a list, e.g.
     * `#[Hidden(['password', 'subsonic_api_key'])]` or
     * `#[Guarded('id', 'public_id')]`.
     *
     * @return array<int, string>
     */
    private function declaredAttributeArray(ClassShape $class, string $attributeName): array
    {
        $needle = strtolower($attributeName);
        $values = [];

        foreach ($class->node()->attrGroups as $group) {
            foreach ($group->attrs as $attribute) {
                if (strtolower(TypeNames::shortName($class->file()->resolveName($attribute->name))) !== $needle) {
                    continue;
                }

                foreach ($attribute->args as $argument) {
                    foreach ($this->stringLiteralsIn($argument->value) as $value) {
                        $values[] = $value;
                    }
                }
            }
        }

        return array_values(array_unique($values));
    }

    /**
     * Payload keys the class publishes as its response contract: the string
     * values and string keys of any array class constant it declares.
     *
     * koel's `UserResource::JSON_STRUCTURE` is exactly this — deleting a key it
     * names breaks the documented API shape, so advice must never suggest it.
     *
     * @return array<int, string>
     */
    private function declaredContractKeys(ClassShape $class): array
    {
        $keys = [];

        foreach ($class->node()->stmts as $statement) {
            if (! $statement instanceof Node\Stmt\ClassConst) {
                continue;
            }

            foreach ($statement->consts as $const) {
                if (! $const->value instanceof Node\Expr\Array_) {
                    continue;
                }

                foreach ($this->contractKeysIn($const->value) as $key) {
                    $keys[] = $key;
                }
            }
        }

        return array_values(array_unique($keys));
    }

    /**
     * String values AND string keys of a (possibly nested) array literal.
     *
     * @return array<int, string>
     */
    private function contractKeysIn(Node\Expr\Array_ $array, int $depth = 0): array
    {
        if ($depth > 4) {
            return [];
        }

        $keys = [];

        foreach ($array->items as $item) {
            if ($item->key instanceof Node\Scalar\String_) {
                $keys[] = $item->key->value;
            }

            if ($item->value instanceof Node\Scalar\String_) {
                $keys[] = $item->value->value;
            }

            if ($item->value instanceof Node\Expr\Array_) {
                foreach ($this->contractKeysIn($item->value, $depth + 1) as $nested) {
                    $keys[] = $nested;
                }
            }
        }

        return $keys;
    }

    /**
     * Every string literal in an expression, including the elements of an array
     * literal.
     *
     * @return array<int, string>
     */
    private function stringLiteralsIn(Node\Expr $expr): array
    {
        $values = [];

        foreach ((new NodeFinder)->findInstanceOf([$expr], Node\Scalar\String_::class) as $string) {
            $values[] = $string->value;
        }

        return $values;
    }

    /**
     * Join declaration sites into readable prose.
     *
     * @param  array<int, string>  $items
     */
    private function listOf(array $items): string
    {
        if ($items === []) {
            return 'its redaction declarations';
        }

        if (count($items) === 1) {
            return $items[0];
        }

        $last = array_pop($items);

        return implode(', ', $items).' and '.$last;
    }

    /**
     * Resolve the object a property is read from, and PROVE it is an Eloquent
     * model. Anything else — an unresolved variable, a DTO, an array, a local
     * service — yields null, and null means no finding.
     *
     * @return array{label: string, evidence: string, class: string|null, self: bool}|null
     */
    private function modelReceiver(Node\Expr $expr, MethodShape $method, SemanticContext $semantics): ?array
    {
        if ($this->isAuthenticatedUser($expr, $method, $semantics)) {
            return [
                'label' => $this->label($expr) ?? 'the authenticated user model',
                'evidence' => 'The receiver is the authenticated user object the framework resolved, which is an Eloquent model.',
                'class' => null,
                'self' => true,
            ];
        }

        $type = $semantics->semantics()->receivers()->resolve($expr, $method);

        if ($type->class === null || ! $semantics->semantics()->isEloquentClass($type->class)) {
            return null;
        }

        return [
            'label' => $this->label($expr) ?? sprintf('a %s model', TypeNames::shortName($type->class)),
            'evidence' => sprintf('The receiver is an Eloquent %s (%s).', TypeNames::shortName($type->class), $type->evidence),
            'class' => $type->class,
            'self' => false,
        ];
    }

    /**
     * Whether an expression is the authenticated user object. This is the one
     * receiver Laravel guarantees is a model without a type hint being present.
     */
    private function isAuthenticatedUser(Node\Expr $expr, MethodShape $method, SemanticContext $semantics): bool
    {
        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            $assignment = $semantics->semantics()->receivers()
                ->assignmentsFor($method)
                ->reaching($expr->name, $expr->getStartLine());

            return $assignment !== null
                && ! $assignment['append']
                && ! $assignment['iterated']
                && $this->isAuthenticatedUser($assignment['expr'], $method, $semantics);
        }

        if ($expr instanceof Node\Expr\StaticCall
            && $expr->class instanceof Node\Name
            && $expr->name instanceof Node\Identifier) {
            return $method->file()->resolveName($expr->class) === 'Illuminate\Support\Facades\Auth'
                && strtolower($expr->name->toString()) === 'user';
        }

        if (! $expr instanceof Node\Expr\MethodCall && ! $expr instanceof Node\Expr\NullsafeMethodCall) {
            return false;
        }

        if (! $expr->name instanceof Node\Identifier || strtolower($expr->name->toString()) !== 'user') {
            return false;
        }

        if ($expr->var instanceof Node\Expr\FuncCall
            && $expr->var->name instanceof Node\Name
            && strtolower($expr->var->name->toString()) === 'auth') {
            return true;
        }

        return $semantics->semantics()->isRequestExpression($expr->var, $method);
    }

    /**
     * A label for an expression, built only from identifiers the code declares.
     * Returns null when the shape cannot be named exactly.
     */
    private function label(Node\Expr $expr): ?string
    {
        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return '$'.$expr->name;
        }

        if (($expr instanceof Node\Expr\PropertyFetch || $expr instanceof Node\Expr\NullsafePropertyFetch)
            && $expr->name instanceof Node\Identifier
            && $expr->var instanceof Node\Expr\Variable
            && $expr->var->name === 'this') {
            return '$this->'.$expr->name->toString();
        }

        return null;
    }

    /**
     * Whether an attribute name is credential material.
     *
     * Deliberately narrow. A `_key` suffix on its own means an identifier —
     * `sort_key`, `cache_key`, `foreign_key`, `translation_key` — and a bare
     * `token`, `key`, `status` or `type` means nothing at all.
     */
    private function isSensitiveAttribute(string $attribute): bool
    {
        $name = strtolower($attribute);

        if (in_array($name, self::NON_SECRET_NAMES, true)) {
            return false;
        }

        if (in_array($name, self::SENSITIVE_EXACT, true)) {
            return true;
        }

        if (str_ends_with($name, '_secret') || str_ends_with($name, '_token')) {
            return true;
        }

        if (str_ends_with($name, '_key')) {
            foreach (self::SECRET_KEY_QUALIFIERS as $qualifier) {
                if (str_contains($name, $qualifier)) {
                    return true;
                }
            }

            return false;
        }

        if (str_ends_with($name, '_hash')) {
            return str_contains($name, 'password') || str_contains($name, 'secret');
        }

        return false;
    }
}
