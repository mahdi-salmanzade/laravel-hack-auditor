<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\AccessControl;

use Mahdi\HackAuditor\Scanner\Php\ClassShape;
use Mahdi\HackAuditor\Scanner\Php\MethodShape;
use Mahdi\HackAuditor\Scanner\Php\SemanticContext;
use Mahdi\HackAuditor\Scanner\Php\SemanticWorkspace;
use Mahdi\HackAuditor\Scanner\Php\TaintState;
use Mahdi\HackAuditor\Scanner\Php\TypeNames;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\Confidence;
use Mahdi\HackAuditor\Support\FindingClass;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;
use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * Flags a privilege- or ownership-bearing column that request data can actually
 * mass-assign (CWE-915).
 *
 * WHAT CHANGED AND WHY
 * --------------------
 * The previous implementation asserted a vulnerability from ONE fact: the
 * column is listed in `$fillable`. Measured over six real applications
 * (monica, akaunting, pixelfed, BookStack, snipe-it, koel) that produced 87
 * findings and 87 false positives. Not one of those applications passed
 * wholesale request data into any of the flagged models: every write was
 * explicit and server-derived (`['user_id' => auth()->id()]`, `firstOrCreate`
 * with server values, `Company::getIdForCurrentUser(...)`).
 *
 * Worse, the advice was destructive. Telling akaunting to "Remove 'company_id'
 * from Account::$fillable" on 25 models would have DISABLED its multi-tenancy:
 * `App\Traits\Tenants::isTenantable()` returns
 * `in_array('company_id', $this->getFillable())`, and `App\Scopes\Company`
 * applies the tenant scope only when the model is tenantable. Applying that fix
 * verbatim turns a non-issue into cross-tenant data exposure on 25 models.
 *
 * So the rule is now: a `$fillable` entry is EVIDENCE OF NOTHING on its own.
 *
 * THE EVIDENCE CHAIN
 * ------------------
 * A `class: vulnerability` finding is emitted only when every link is resolved
 * from the analysed code and can be printed with a file and a line:
 *
 *   1. SOURCE  — a request accessor that yields an ARRAY of client-supplied
 *                keys: `$request->all()`, `->input()`, `->post()`, `->json()`,
 *                `->only([...])`, `->except([...])`, `->validated()`,
 *                `->safe()->all()`, `$request->validate([...])`, a superglobal,
 *                or a local variable a reaching assignment proves holds one.
 *   2. SINK    — that array reaches a mass-assignment call on THIS model:
 *                `Model::create()`, `->fill()`, `->forceFill()`, `->update()`,
 *                `->firstOrCreate()`, `->updateOrCreate()` …, with the receiver
 *                resolved to the model class through the declared types, never
 *                guessed from a name.
 *   3. REACH   — the column survives the restriction the source imposes.
 *                `->only(['title','body'])` cannot carry `user_id`;
 *                `array_merge($request->all(), ['user_id' => auth()->id()])`
 *                overwrites it with a server value; `['user_id' => auth()->id()]`
 *                never carried it in the first place. Each of those is proof of
 *                SAFETY, and each is subtracted before anything is reported.
 *
 * If any link is unproven the finding is not a vulnerability:
 *
 *   - An UNAMBIGUOUS privilege column (`is_admin`, `role`, `permissions`,
 *     `balance` …) with no proven sink becomes a `class: review` finding: a
 *     QUESTION for a human, carrying no fix, excluded from the vulnerability
 *     count and from the exit code.
 *   - An OWNERSHIP column (`user_id`, `company_id`, `account_id`, `tenant_id` …)
 *     with no proven sink produces NOTHING AT ALL. On real applications those
 *     are ordinary tenancy and relationship keys and were wrong 100% of the time.
 *   - Everything else — ambiguous columns, lifecycle flags, account state —
 *     produces nothing without a sink.
 *
 * FIX SAFETY
 * ----------
 * No fix is ever emitted for a review finding. When a fix IS emitted it targets
 * the SINK, not the model: "stop passing $request->all() into this call". That
 * advice is correct for every model and cannot break tenancy, whereas removing
 * a column from `$fillable` can. Column removal is offered only for the
 * unambiguous privilege columns, where it is unambiguously right.
 *
 * Everything read here comes from the AST: `$fillable`/`$guarded`/`$casts` are
 * declared PROPERTY nodes, each field is a `String_` literal carrying its own
 * line, "is this an Eloquent model?" is answered from resolved ancestry, and a
 * compensating mutator is a declared METHOD. A comment is not a node, so it can
 * neither be mistaken for a field nor desynchronise the reader.
 */
final class SensitiveFillableDetector implements AccessControlDetector
{
    /**
     * Fields that are a privilege or money boundary on ANY model. There is no
     * common, legitimate reason to let a client mass-assign one. This is the
     * only group that may be raised as a REVIEW question without a sink.
     *
     * @var array<int, string>
     */
    private const ALWAYS_PRIVILEGE = [
        'is_admin', 'admin', 'is_superadmin', 'is_super_admin', 'is_staff',
        'role', 'role_id', 'roles', 'permissions', 'permission_id',
        'plan_id', 'balance', 'credits', 'wallet_balance',
    ];

    /**
     * Account-state fields: a privilege boundary on a model that authenticates,
     * ordinary moderation state anywhere else. `is_verified` on a Comment means
     * "a moderator approved it"; on a User it means "skip email verification".
     *
     * @var array<int, string>
     */
    private const AUTH_STATE = [
        'is_verified', 'verified', 'email_verified_at', 'is_active',
        'two_factor_confirmed_at', 'banned_at', 'is_banned', 'is_blocked',
    ];

    /**
     * Fields that are AMBIGUOUS: extremely common, legitimately mass-assignable
     * columns (post type, ticket status, character level, subscription tier)
     * that are only a privilege boundary in some applications.
     *
     * @var array<int, string>
     */
    private const AMBIGUOUS_PRIVILEGE = [
        'status', 'type', 'active', 'level', 'tier', 'plan',
        'account_type', 'user_type',
    ];

    /**
     * Sibling fields that, present in the SAME $fillable, prove the model
     * carries a privilege boundary — the corroboration an ambiguous field needs.
     *
     * @var array<int, string>
     */
    private const PRIVILEGE_SIBLINGS = [
        'is_admin', 'admin', 'is_superadmin', 'is_super_admin', 'is_staff',
        'role', 'role_id', 'roles', 'permissions', 'permission_id',
    ];

    /**
     * Ownership/identity fields that let an attacker reassign a record's owner
     * — but only through a proven sink. Without one they are ordinary tenancy
     * and relationship keys and are never reported, not even as a question.
     *
     * @var array<int, string>
     */
    private const OWNERSHIP_FIELDS = [
        'user_id', 'owner_id', 'author_id', 'account_id', 'team_id',
        'organization_id', 'org_id', 'company_id', 'tenant_id', 'customer_id',
    ];

    /**
     * Boolean flags that match the `is_*` convention but describe publishing,
     * lifecycle or display state rather than authorization.
     *
     * @var array<int, string>
     */
    private const BENIGN_FLAGS = [
        'is_active', 'is_default', 'is_featured', 'is_public', 'is_private',
        'is_visible', 'is_hidden', 'is_pinned', 'is_archived', 'is_draft',
        'is_published', 'is_completed', 'is_complete', 'is_done', 'is_read',
        'is_unread', 'is_deleted', 'is_enabled', 'is_disabled', 'is_favorite',
        'is_favourite', 'is_new', 'is_available', 'is_required', 'is_optional',
        'is_primary', 'is_online', 'is_offline', 'is_recurring', 'is_remote',
        'is_open', 'is_closed', 'is_locked', 'is_anonymous', 'is_test',
        'is_sample', 'is_temporary', 'is_system', 'is_global',
    ];

    /**
     * Base classes and contracts that mean "this model authenticates".
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
     * Calls that write an ARRAY of attributes through Eloquent's mass-assignment
     * path. `insert()` is absent on purpose: it writes raw columns and bypasses
     * `$fillable` entirely, so a `$fillable` entry is not what makes it unsafe.
     *
     * @var array<int, string>
     */
    private const MASS_ASSIGNMENT_VERBS = [
        'create', 'forcecreate', 'make', 'fill', 'forcefill', 'update',
        'updateorcreate', 'firstorcreate', 'firstornew', 'createquietly',
        'updatequietly',
    ];

    /**
     * Chain links that keep a query rooted at the SAME model, so the mass
     * assignment at the end of the chain can still be attributed to it.
     * `$user->posts()->create(...)` is deliberately excluded: `posts()` is a
     * relation to some other model that this layer does not resolve, and
     * attributing that write to User would be a lie.
     *
     * @var array<int, string>
     */
    private const MODEL_PRESERVING_LINKS = [
        'query', 'newquery', 'newmodelquery', 'where', 'wherein', 'orwhere',
        'wherenull', 'wherenotnull', 'wherekey', 'find', 'findorfail',
        'findornew', 'first', 'firstorfail', 'sole', 'withtrashed',
        'onlytrashed', 'withoutglobalscopes', 'withoutglobalscope', 'lockforupdate',
        'sharedlock', 'orderby', 'latest', 'oldest', 'when', 'unguarded',
    ];

    /**
     * Request accessors that return the WHOLE client-supplied array.
     *
     * @var array<int, string>
     */
    private const WHOLESALE_ACCESSORS = ['all', 'toarray', 'collect', 'input', 'post', 'json', 'query'];

    /**
     * Request accessors that return the whole array only when called with no
     * arguments — `$request->input('name')` is one scalar, not the payload.
     *
     * @var array<int, string>
     */
    private const ARGUMENTLESS_ACCESSORS = ['input', 'post', 'json', 'query', 'collect'];

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

        $sinks = $this->collectSinks($semantics);
        $findings = [];

        foreach ($files as $file) {
            $parsed = $semantics->parsed($file->path);

            if ($parsed === null || ! $parsed->isAnalysable()) {
                continue;
            }

            foreach ($parsed->classes() as $class) {
                foreach ($this->findingsFor($file, $class, $semantics, $sinks) as $finding) {
                    $findings[] = $finding;
                }
            }
        }

        return $findings;
    }

    /**
     * @param  array<string, array<int, array{model: string, path: string, line: int, call: string, source: string, reach: array{kind: string, fields: array<int, string>}}>>  $sinks
     * @return array<int, Vulnerability>
     */
    private function findingsFor(SourceFile $file, ClassShape $class, SemanticContext $semantics, array $sinks): array
    {
        if (! $this->isEloquentModel($class, $file, $semantics)) {
            return [];
        }

        $fillable = $this->declaredStringArray($class, 'fillable');

        if ($fillable === []) {
            return [];
        }

        $guarded = array_map(
            static fn (array $entry): string => $entry['value'],
            $this->declaredStringArray($class, 'guarded'),
        );

        if (in_array('*', $guarded, true)) {
            return [];
        }

        $names = array_map(
            static fn (array $entry): string => $entry['value'],
            $fillable,
        );

        $modelSinks = $this->sinksForModel($class, $sinks, $semantics);
        $findings = [];

        foreach ($fillable as $entry) {
            $field = $entry['value'];

            if ($field === '' || $field === '*' || in_array($field, $guarded, true)) {
                continue;
            }

            if ($this->hasAssignmentGuardFor($field, $class)) {
                continue;
            }

            $verdict = $this->classifyField($field, $class, $names, $semantics);

            if ($verdict === null) {
                continue;
            }

            $sink = $this->reachingSink($field, $modelSinks);

            if ($sink !== null) {
                $findings[] = $this->reportVulnerability($file, $class, $entry, $verdict, $sink);

                continue;
            }

            if ($verdict['question'] === null) {
                continue;
            }

            $findings[] = $this->reportReview($file, $class, $entry, $verdict);
        }

        return $findings;
    }

    /*
    |--------------------------------------------------------------------------
    | Findings
    |--------------------------------------------------------------------------
    */

    /**
     * A proven finding: source, sink and reach are all resolved, and both lines
     * are quoted.
     *
     * @param  array{value: string, original: string, line: int}  $entry
     * @param  array{reason: string, severity: SeverityLevel, question: string|null, removable: bool}  $verdict
     * @param  array{model: string, path: string, line: int, call: string, source: string, reach: array{kind: string, fields: array<int, string>}}  $sink
     */
    private function reportVulnerability(
        SourceFile $file,
        ClassShape $class,
        array $entry,
        array $verdict,
        array $sink,
    ): Vulnerability {
        return new Vulnerability(
            type: VulnerabilityType::MassAssignment,
            location: $file->path,
            line: $entry['line'],
            severity: $verdict['severity'],
            description: sprintf(
                "%s::\$fillable declares '%s' at %s:%d, and %s at %s:%d passes %s — client-supplied data that still carries '%s' — straight into it. %s A request body carrying \"%s\" therefore writes that column.",
                $class->shortName(),
                $entry['original'],
                $file->path,
                $entry['line'],
                $sink['call'],
                $sink['path'],
                $sink['line'],
                $sink['source'],
                $entry['original'],
                $verdict['reason'],
                $entry['original'],
            ),
            proof: sprintf(
                "SOURCE %s at %s:%d -> SINK %s at %s:%d -> REACHES '%s' because %s. %s::\$fillable lists '%s' at line %d, no \$guarded entry names it, and the model declares no set%sAttribute()/Attribute mutator that could re-check authorization for it.",
                $sink['source'],
                $sink['path'],
                $sink['line'],
                $sink['call'],
                $sink['path'],
                $sink['line'],
                $entry['original'],
                $this->reachEvidence($sink['reach']),
                $class->shortName(),
                $entry['original'],
                $entry['line'],
                $this->studly($entry['value']),
            ),
            fix: $this->remedy($class, $entry, $verdict, $sink),
            findingClass: FindingClass::Vulnerability,
            confidence: Confidence::Proven,
        );
    }

    /**
     * A question, not an assertion: the column is a privilege boundary but this
     * scan found no path from request input to it.
     *
     * @param  array{value: string, original: string, line: int}  $entry
     * @param  array{reason: string, severity: SeverityLevel, question: string|null, removable: bool}  $verdict
     */
    private function reportReview(SourceFile $file, ClassShape $class, array $entry, array $verdict): Vulnerability
    {
        return new Vulnerability(
            type: VulnerabilityType::MassAssignment,
            location: $file->path,
            line: $entry['line'],
            severity: $verdict['severity'],
            description: sprintf(
                "Should '%s' be mass-assignable on %s? %s This scan found no call that passes wholesale request data into %s, so there is no proven path from request input to this column and this is a question for review rather than a reported vulnerability.",
                $entry['original'],
                $class->shortName(),
                (string) $verdict['question'],
                $class->shortName(),
            ),
            proof: sprintf(
                "%s::\$fillable declares '%s' at %s:%d. No mass-assignment sink for %s was found in the scanned files: no create()/fill()/forceFill()/update()/firstOrCreate()/updateOrCreate() call on this model receives \$request->all(), ->input(), ->only()/->except(), ->validated() or a variable holding one of them. Absence of a sink in THIS scan is not proof that none exists elsewhere, which is why this is raised for review.",
                $class->shortName(),
                $entry['original'],
                $file->path,
                $entry['line'],
                $class->shortName(),
            ),
            // A review finding carries NO fix. Vulnerability drops it anyway;
            // passing an empty string states the intent at the call site rather
            // than relying on the invariant to clean up after this detector.
            fix: '',
            findingClass: FindingClass::Review,
            confidence: Confidence::Possible,
        );
    }

    /**
     * Advice that is safe to apply verbatim.
     *
     * It targets the SINK first, and every identifier it names — the model, the
     * column, the accessor, the file and the two lines — was resolved from the
     * analysed code. Removing the column from `$fillable` is offered only for
     * the unambiguous privilege columns: on an ownership key that same edit can
     * disable a tenancy scope that is keyed on `$fillable` membership, which is
     * how a non-issue becomes cross-tenant data exposure.
     *
     * @param  array{value: string, original: string, line: int}  $entry
     * @param  array{reason: string, severity: SeverityLevel, question: string|null, removable: bool}  $verdict
     * @param  array{model: string, path: string, line: int, call: string, source: string, reach: array{kind: string, fields: array<int, string>}}  $sink
     */
    private function remedy(ClassShape $class, array $entry, array $verdict, array $sink): string
    {
        $primary = sprintf(
            "Stop handing client-controlled keys to this write: at %s:%d, replace %s with an explicit array that names only the columns this endpoint may set, and assign '%s' separately from a server-derived value after an authorization check.",
            $sink['path'],
            $sink['line'],
            $sink['source'],
            $entry['original'],
        );

        if (! $verdict['removable']) {
            return $primary.sprintf(
                " Do NOT simply drop '%s' from %s::\$fillable: an ownership/tenancy key is often read back from \$fillable by scoping code, so removing it can silently disable the scope that isolates one owner's rows from another's.",
                $entry['original'],
                $class->shortName(),
            );
        }

        return $primary.sprintf(
            " Removing '%s' from %s::\$fillable (line %d) is also correct for a privilege column: promote through an explicit, authorized code path so the decision stays auditable.",
            $entry['original'],
            $class->shortName(),
            $entry['line'],
        );
    }

    /**
     * @param  array{kind: string, fields: array<int, string>}  $reach
     */
    private function reachEvidence(array $reach): string
    {
        return match ($reach['kind']) {
            'only' => sprintf('the payload is restricted to [%s], which includes it', $this->quoteList($reach['fields'])),
            'except' => sprintf('the payload excludes only [%s], which does not include it', $this->quoteList($reach['fields'])),
            default => 'the payload is the unrestricted request array',
        };
    }

    /**
     * @param  array<int, string>  $fields
     */
    private function quoteList(array $fields): string
    {
        return implode(', ', array_map(static fn (string $field): string => "'".$field."'", $fields));
    }

    /*
    |--------------------------------------------------------------------------
    | Field classification
    |--------------------------------------------------------------------------
    */

    /**
     * Classify a normalised field name, or null when it is not sensitive.
     *
     * `question` is non-null only for the columns that may be raised for review
     * WITHOUT a proven sink. `removable` states whether "delete it from
     * $fillable" is safe advice for this column.
     *
     * @param  array<int, string>  $fillable  Every normalised fillable field, for corroboration
     * @return array{reason: string, severity: SeverityLevel, question: string|null, removable: bool}|null
     */
    private function classifyField(string $field, ClassShape $class, array $fillable, SemanticContext $semantics): ?array
    {
        if (in_array($field, self::ALWAYS_PRIVILEGE, true)) {
            return [
                'reason' => 'This is a privilege/identity attribute that governs authorization.',
                'severity' => SeverityLevel::High,
                'question' => 'It is a privilege/identity attribute that governs authorization, and there is no common reason for a client to set it.',
                'removable' => true,
            ];
        }

        if (in_array($field, self::AUTH_STATE, true)) {
            if (! $this->authenticatesUsers($class, $fillable, $semantics)) {
                return null;
            }

            return [
                'reason' => 'This is account state on a model that authenticates users, so mass-assigning it lets a client change its own account standing.',
                'severity' => SeverityLevel::High,
                'question' => null,
                'removable' => true,
            ];
        }

        if (in_array($field, self::AMBIGUOUS_PRIVILEGE, true)) {
            if (! $this->hasCorroboratingPrivilegeSignal($field, $class, $fillable)) {
                return null;
            }

            return [
                'reason' => 'This attribute commonly maps to a privilege boundary, and this model carries a corroborating privilege signal (a sibling admin/role field or a privilege cast).',
                'severity' => SeverityLevel::Medium,
                'question' => null,
                'removable' => true,
            ];
        }

        if (in_array($field, self::OWNERSHIP_FIELDS, true)) {
            return [
                'reason' => 'This is an ownership/identity foreign key, so writing it from the request body reassigns the record to another owner.',
                'severity' => SeverityLevel::High,
                'question' => null,
                'removable' => false,
            ];
        }

        if ($this->looksLikePrivilegeFlag($field)) {
            // The `is_*` convention alone is far too weak: `is_unique` on a
            // custom-field definition matches it and is a schema attribute, not
            // an authorization boundary. It counts only on a model that carries
            // an independent privilege signal.
            if (! $this->hasCorroboratingPrivilegeSignal($field, $class, $fillable)) {
                return null;
            }

            return [
                'reason' => 'The naming convention (is_*/*_admin/can_*) indicates a boolean privilege flag, and this model carries a corroborating privilege signal.',
                'severity' => SeverityLevel::High,
                'question' => null,
                'removable' => true,
            ];
        }

        if (str_starts_with($field, 'subscription') || $field === 'subscribed' || str_ends_with($field, '_credits')) {
            return [
                'reason' => 'This attribute controls billing/subscription state.',
                'severity' => SeverityLevel::Medium,
                'question' => null,
                'removable' => true,
            ];
        }

        return null;
    }

    /**
     * Whether a name matches the privilege-flag convention, once the ordinary
     * publishing and lifecycle booleans have been subtracted.
     */
    private function looksLikePrivilegeFlag(string $field): bool
    {
        if (in_array($field, self::BENIGN_FLAGS, true)) {
            return false;
        }

        return str_starts_with($field, 'is_')
            || str_starts_with($field, 'can_')
            || str_ends_with($field, '_admin');
    }

    /**
     * Whether an ambiguous field is corroborated as a real privilege boundary
     * by a sibling field in the same $fillable or by a boolean cast.
     *
     * @param  array<int, string>  $fillable
     */
    private function hasCorroboratingPrivilegeSignal(string $field, ClassShape $class, array $fillable): bool
    {
        foreach ($fillable as $sibling) {
            if ($sibling === $field) {
                continue;
            }

            if (in_array($sibling, self::PRIVILEGE_SIBLINGS, true) || $this->looksLikePrivilegeFlag($sibling)) {
                return true;
            }
        }

        $cast = $this->casts($class)[$field] ?? null;

        return $cast === 'boolean' || $cast === 'bool';
    }

    /**
     * Whether the model authenticates users: it descends from an Authenticatable
     * base or contract, or it keeps a password.
     *
     * @param  array<int, string>  $fillable
     */
    private function authenticatesUsers(ClassShape $class, array $fillable, SemanticContext $semantics): bool
    {
        if ($semantics->classes()->descendsFromAny($class->fqcn(), self::AUTHENTICATABLE_CLASSES)) {
            return true;
        }

        foreach ($semantics->classes()->ancestry($class->fqcn()) as $ancestor) {
            if (TypeNames::shortName($ancestor) === 'Authenticatable') {
                return true;
            }
        }

        if (in_array('password', $fillable, true)) {
            return true;
        }

        foreach ($this->declaredStringArray($class, 'hidden') as $entry) {
            if ($entry['value'] === 'password' || $entry['value'] === 'remember_token') {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the model declares a mutator that can re-check authorization for
     * the field: the classic `set{Field}Attribute()` or a Laravel 9+ attribute
     * accessor named after the column.
     */
    private function hasAssignmentGuardFor(string $field, ClassShape $class): bool
    {
        $studly = $this->studly($field);

        if ($class->method('set'.$studly.'Attribute') !== null) {
            return true;
        }

        $accessor = $class->method(lcfirst($studly));

        return $accessor !== null
            && $accessor->returnType() === 'Illuminate\Database\Eloquent\Casts\Attribute';
    }

    private function studly(string $field): string
    {
        return str_replace(' ', '', ucwords(str_replace('_', ' ', $field)));
    }

    /*
    |--------------------------------------------------------------------------
    | Mass-assignment sinks
    |--------------------------------------------------------------------------
    */

    /**
     * Every mass-assignment sink in the scan, keyed by lowercased model FQCN.
     *
     * @return array<string, array<int, array{model: string, path: string, line: int, call: string, source: string, reach: array{kind: string, fields: array<int, string>}}>>
     */
    private function collectSinks(SemanticContext $semantics): array
    {
        $sinks = [];

        foreach ($semantics->analysable() as $parsed) {
            foreach ($parsed->classes() as $class) {
                foreach ($class->methods() as $method) {
                    foreach ($this->sinksIn($parsed->path, $method, $semantics) as $sink) {
                        $sinks[strtolower($sink['model'])][] = $sink;
                    }
                }
            }
        }

        return $sinks;
    }

    /**
     * @return array<int, array{model: string, path: string, line: int, call: string, source: string, reach: array{kind: string, fields: array<int, string>}}>
     */
    private function sinksIn(string $path, MethodShape $method, SemanticContext $semantics): array
    {
        $statements = $method->statements();

        if ($statements === []) {
            return [];
        }

        $calls = (new NodeFinder)->find(
            $statements,
            static fn (Node $node): bool => $node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall,
        );

        $state = $semantics->taint()->track($method);
        $sinks = [];

        foreach ($calls as $call) {
            if (! $call instanceof Node\Expr\MethodCall && ! $call instanceof Node\Expr\StaticCall) {
                continue;
            }

            if (! $call->name instanceof Node\Identifier || $call->isFirstClassCallable()) {
                continue;
            }

            $verb = $call->name->toString();

            if (! in_array(strtolower($verb), self::MASS_ASSIGNMENT_VERBS, true)) {
                continue;
            }

            $model = $this->sinkModel($call, $method, $semantics);

            if ($model === null) {
                continue;
            }

            $nested = $this->isInsideNestedScope($call);

            foreach ($call->getArgs() as $argument) {
                if ($argument->name !== null || $argument->unpack) {
                    continue;
                }

                $reach = $this->requestArrayReach($argument->value, $method, $semantics, $state, $nested);

                if ($reach === null) {
                    continue;
                }

                // `$accessory->fill($request->all());` immediately followed by
                // `$accessory->company_id = Company::getIdForCurrentUser(...);`
                // is SAFE for company_id: the server value lands last and wins.
                // This is the dominant shape in real Laravel applications, and
                // reporting past it is a false positive.
                $instance = $this->sinkInstanceVariable($call);

                if ($instance !== null && ! $nested) {
                    $reach = $this->subtract(
                        $reach,
                        $this->serverWrittenColumns($instance, $method, $semantics, $state, $call->getStartLine()),
                        $reach['label'],
                    );
                }

                $sinks[] = [
                    'model' => $model,
                    'path' => $path,
                    'line' => $call->getStartLine(),
                    'call' => $this->sinkLabel($call, $verb, $model),
                    'source' => $reach['label'],
                    'reach' => ['kind' => $reach['kind'], 'fields' => $reach['fields']],
                ];

                break;
            }
        }

        return $sinks;
    }

    /**
     * The model a mass-assignment call writes to, resolved from declared types.
     * Null whenever the receiver cannot be pinned to one model class that this
     * scan actually contains.
     */
    private function sinkModel(Node\Expr\MethodCall|Node\Expr\StaticCall $call, MethodShape $method, SemanticContext $semantics): ?string
    {
        $resolved = $semantics->semantics()->receivers()->resolveChain($call, $method);
        $chain = $resolved['chain'];

        // Everything between the root and the verb must keep the query on the
        // same model. A relation call (`$user->posts()`) does not, and there is
        // no honest way to name the model it lands on from here.
        foreach (array_slice($chain, 0, max(0, count($chain) - 1)) as $link) {
            if (! in_array(strtolower($link), self::MODEL_PRESERVING_LINKS, true)) {
                return null;
            }
        }

        $root = $resolved['root'];

        if ($root instanceof Node\Expr\StaticCall && $root->class instanceof Node\Name) {
            $name = $root->class->toString();

            if (in_array(strtolower($name), ['self', 'static'], true)) {
                $enclosing = $method->class()->fqcn();

                return $semantics->semantics()->isEloquentClass($enclosing) ? $enclosing : null;
            }
        }

        $type = $semantics->semantics()->receivers()->resolve($root, $method);

        if ($type->class === null) {
            return null;
        }

        // The class must be a model this scan declares. A bare Builder or the
        // Model base class names no columns, so a $fillable entry cannot be
        // attributed to it.
        $shape = $semantics->classes()->find($type->class);

        if ($shape === null || ! $semantics->semantics()->isEloquentClass($type->class)) {
            return null;
        }

        return $type->class;
    }

    /**
     * The variable that holds the model instance a sink writes to: the receiver
     * of `$accessory->fill(...)`, or the variable `Model::create(...)` is
     * assigned to.
     */
    private function sinkInstanceVariable(Node\Expr\MethodCall|Node\Expr\StaticCall $call): ?string
    {
        if ($call instanceof Node\Expr\MethodCall
            && $call->var instanceof Node\Expr\Variable
            && is_string($call->var->name)) {
            return $call->var->name;
        }

        $parent = $call->getAttribute('parent');

        if ($parent instanceof Node\Expr\Assign
            && $parent->expr === $call
            && $parent->var instanceof Node\Expr\Variable
            && is_string($parent->var->name)) {
            return $parent->var->name;
        }

        return null;
    }

    /**
     * Columns written onto the model instance from a NON-client value after the
     * mass assignment. Eloquent applies them last, so those columns are
     * server-controlled whatever the request body said.
     *
     * @return array<int, string>
     */
    private function serverWrittenColumns(
        string $variable,
        MethodShape $method,
        SemanticContext $semantics,
        TaintState $state,
        int $afterLine,
    ): array {
        $statements = $method->statements();

        if ($statements === []) {
            return [];
        }

        $columns = [];

        foreach ((new NodeFinder)->findInstanceOf($statements, Node\Expr\Assign::class) as $assign) {
            if ($assign->getStartLine() < $afterLine) {
                continue;
            }

            $target = $assign->var;

            if (! $target instanceof Node\Expr\PropertyFetch
                || ! $target->name instanceof Node\Identifier
                || ! $target->var instanceof Node\Expr\Variable
                || $target->var->name !== $variable) {
                continue;
            }

            if ($semantics->semantics()->judge($assign->expr, $method, $state)->isTainted()) {
                continue;
            }

            $columns[] = strtolower($target->name->toString());
        }

        return array_values(array_unique($columns));
    }

    /**
     * A label for the sink built only from resolved identifiers: the model's
     * short name (or the receiver variable as written) and the verb.
     */
    private function sinkLabel(Node\Expr\MethodCall|Node\Expr\StaticCall $call, string $verb, string $model): string
    {
        if ($call instanceof Node\Expr\StaticCall) {
            return sprintf('%s::%s()', TypeNames::shortName($model), $verb);
        }

        if ($call->var instanceof Node\Expr\Variable && is_string($call->var->name)) {
            return sprintf('$%s->%s()', $call->var->name, $verb);
        }

        return sprintf('->%s() on %s', $verb, TypeNames::shortName($model));
    }

    /**
     * Sinks that write to this model, including sinks that write to a subclass
     * of it (a child inherits its parent's $fillable).
     *
     * @param  array<string, array<int, array{model: string, path: string, line: int, call: string, source: string, reach: array{kind: string, fields: array<int, string>}}>>  $sinks
     * @return array<int, array{model: string, path: string, line: int, call: string, source: string, reach: array{kind: string, fields: array<int, string>}}>
     */
    private function sinksForModel(ClassShape $class, array $sinks, SemanticContext $semantics): array
    {
        $fqcn = $class->fqcn();
        $matched = $sinks[strtolower($fqcn)] ?? [];

        foreach ($sinks as $key => $group) {
            if ($key === strtolower($fqcn)) {
                continue;
            }

            $target = $group[0]['model'] ?? null;

            if ($target === null || ! $semantics->classes()->descendsFromAny($target, [$fqcn])) {
                continue;
            }

            $matched = [...$matched, ...$group];
        }

        return $matched;
    }

    /**
     * The first sink whose payload can actually carry this column.
     *
     * @param  array<int, array{model: string, path: string, line: int, call: string, source: string, reach: array{kind: string, fields: array<int, string>}}>  $sinks
     * @return array{model: string, path: string, line: int, call: string, source: string, reach: array{kind: string, fields: array<int, string>}}|null
     */
    private function reachingSink(string $field, array $sinks): ?array
    {
        foreach ($sinks as $sink) {
            $reach = $sink['reach'];

            $carries = match ($reach['kind']) {
                'only' => in_array($field, $reach['fields'], true),
                'except' => ! in_array($field, $reach['fields'], true),
                default => true,
            };

            if ($carries) {
                return $sink;
            }
        }

        return null;
    }

    /*
    |--------------------------------------------------------------------------
    | Request-array analysis
    |--------------------------------------------------------------------------
    */

    /**
     * Decide whether an expression is an ARRAY of client-supplied keys, and
     * which keys survive into it.
     *
     * `kind` is one of:
     *  - `all`    every request key reaches the sink
     *  - `only`   only `fields` reach it
     *  - `except` every key except `fields` reaches it
     *
     * Returns null when the expression is not client-supplied at all, when its
     * restriction cannot be read literally (an unreadable restriction is not a
     * licence to assume there is none), or when it is a variable inside a nested
     * scope whose assignments this layer does not model.
     *
     * @return array{kind: string, fields: array<int, string>, label: string}|null
     */
    private function requestArrayReach(
        Node\Expr $expr,
        MethodShape $method,
        SemanticContext $semantics,
        TaintState $state,
        bool $nested,
        int $depth = 0,
    ): ?array {
        if ($depth > 6) {
            return null;
        }

        if ($expr instanceof Node\Expr\Variable) {
            return $this->variableReach($expr, $method, $semantics, $state, $nested, $depth);
        }

        if ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\NullsafeMethodCall) {
            return $this->accessorReach($expr, $method, $semantics, $state, $nested, $depth);
        }

        if ($expr instanceof Node\Expr\StaticCall) {
            return $this->staticAccessorReach($expr, $method, $semantics, $state, $nested, $depth);
        }

        if ($expr instanceof Node\Expr\FuncCall) {
            return $this->functionReach($expr, $method, $semantics, $state, $nested, $depth);
        }

        if ($expr instanceof Node\Expr\Array_) {
            return $this->arrayLiteralReach($expr, $method, $semantics, $state, $nested, $depth);
        }

        if ($expr instanceof Node\Expr\Ternary) {
            foreach (array_values(array_filter([$expr->if, $expr->else])) as $branch) {
                $reach = $this->requestArrayReach($branch, $method, $semantics, $state, $nested, $depth + 1);

                if ($reach !== null) {
                    return $reach;
                }
            }

            return null;
        }

        if ($expr instanceof Node\Expr\BinaryOp\Coalesce) {
            return $this->requestArrayReach($expr->left, $method, $semantics, $state, $nested, $depth + 1)
                ?? $this->requestArrayReach($expr->right, $method, $semantics, $state, $nested, $depth + 1);
        }

        return null;
    }

    /**
     * @return array{kind: string, fields: array<int, string>, label: string}|null
     */
    private function variableReach(
        Node\Expr\Variable $expr,
        MethodShape $method,
        SemanticContext $semantics,
        TaintState $state,
        bool $nested,
        int $depth,
    ): ?array {
        if (! is_string($expr->name)) {
            return null;
        }

        if (in_array($expr->name, ['_GET', '_POST', '_REQUEST', '_COOKIE'], true)) {
            return ['kind' => 'all', 'fields' => [], 'label' => '$'.$expr->name];
        }

        // Inside a closure the reaching-assignment table is a different scope,
        // and this layer does not model it. Silence, not a guess.
        if ($nested) {
            return null;
        }

        $assignment = $semantics->semantics()->receivers()
            ->assignmentsFor($method)
            ->reaching($expr->name, $expr->getStartLine());

        if ($assignment === null || $assignment['iterated']) {
            return null;
        }

        $reach = $this->requestArrayReach($assignment['expr'], $method, $semantics, $state, $nested, $depth + 1);

        if ($reach === null) {
            return null;
        }

        // Keys written onto the array between the assignment and the sink are
        // server-controlled from that point on: `$data = $request->all();`
        // followed by `$data['user_id'] = auth()->id();` no longer carries a
        // client-chosen user_id.
        $overwritten = $this->overwrittenKeys(
            $expr->name,
            $method,
            $semantics,
            $state,
            $assignment['line'],
            $expr->getStartLine(),
        );

        return $this->subtract($reach, $overwritten, '$'.$expr->name);
    }

    /**
     * Literal string keys assigned onto `$name[...]` (or unset from it) between
     * two lines with a value that is NOT client controlled.
     *
     * @return array<int, string>
     */
    private function overwrittenKeys(
        string $name,
        MethodShape $method,
        SemanticContext $semantics,
        TaintState $state,
        int $from,
        int $to,
    ): array {
        $statements = $method->statements();

        if ($statements === []) {
            return [];
        }

        $keys = [];
        $finder = new NodeFinder;

        foreach ($finder->findInstanceOf($statements, Node\Expr\Assign::class) as $assign) {
            if ($assign->getStartLine() < $from || $assign->getStartLine() > $to) {
                continue;
            }

            $target = $assign->var;

            if (! $target instanceof Node\Expr\ArrayDimFetch
                || ! $target->var instanceof Node\Expr\Variable
                || $target->var->name !== $name
                || ! $target->dim instanceof Node\Scalar\String_) {
                continue;
            }

            if ($semantics->semantics()->judge($assign->expr, $method, $state)->isTainted()) {
                continue;
            }

            $keys[] = strtolower($target->dim->value);
        }

        foreach ($finder->findInstanceOf($statements, Node\Stmt\Unset_::class) as $unset) {
            if ($unset->getStartLine() < $from || $unset->getStartLine() > $to) {
                continue;
            }

            foreach ($unset->vars as $variable) {
                if ($variable instanceof Node\Expr\ArrayDimFetch
                    && $variable->var instanceof Node\Expr\Variable
                    && $variable->var->name === $name
                    && $variable->dim instanceof Node\Scalar\String_) {
                    $keys[] = strtolower($variable->dim->value);
                }
            }
        }

        return array_values(array_unique($keys));
    }

    /**
     * @return array{kind: string, fields: array<int, string>, label: string}|null
     */
    private function accessorReach(
        Node\Expr\MethodCall|Node\Expr\NullsafeMethodCall $expr,
        MethodShape $method,
        SemanticContext $semantics,
        TaintState $state,
        bool $nested,
        int $depth,
    ): ?array {
        if (! $expr->name instanceof Node\Identifier || $expr->isFirstClassCallable()) {
            return null;
        }

        $name = strtolower($expr->name->toString());

        // `$request->safe()->only([...])` and friends: the validated bag keeps
        // the FormRequest's restriction and then narrows it further.
        if ($expr->var instanceof Node\Expr\MethodCall
            && $expr->var->name instanceof Node\Identifier
            && strtolower($expr->var->name->toString()) === 'safe'
            && $semantics->semantics()->isRequestExpression($expr->var->var, $method)) {
            $base = $this->validatedReach($expr->var->var, $method, $semantics, '$request->safe()');

            return $this->narrow($base, $expr, $name);
        }

        if (! $semantics->semantics()->isRequestExpression($expr->var, $method)) {
            return null;
        }

        $receiver = $this->receiverLabel($expr->var);

        if ($name === 'validated' || $name === 'safe') {
            return $this->validatedReach($expr->var, $method, $semantics, $receiver.'->'.$name.'()');
        }

        if ($name === 'validate') {
            $fields = $this->ruleKeys($this->positional($expr, 0));

            return $fields === null
                ? null
                : ['kind' => 'only', 'fields' => $fields, 'label' => $receiver.'->validate([...])'];
        }

        if ($name === 'only' || $name === 'except') {
            $fields = $this->literalFieldList($expr);

            return $fields === null
                ? null
                : ['kind' => $name === 'only' ? 'only' : 'except', 'fields' => $fields, 'label' => $receiver.'->'.$name.'([...])'];
        }

        if (! in_array($name, self::WHOLESALE_ACCESSORS, true)) {
            return null;
        }

        if (in_array($name, self::ARGUMENTLESS_ACCESSORS, true) && $expr->getArgs() !== []) {
            return null;
        }

        if ($name === 'all' && $expr->getArgs() !== []) {
            $fields = $this->literalFieldList($expr);

            return $fields === null
                ? null
                : ['kind' => 'only', 'fields' => $fields, 'label' => $receiver.'->all([...])'];
        }

        return ['kind' => 'all', 'fields' => [], 'label' => $receiver.'->'.$name.'()'];
    }

    /**
     * `$request->validated()` on a FormRequest carries exactly the keys that
     * FormRequest's own rules() declares — when this scan can read them. When it
     * cannot, the validated set is not provably restricted and is treated as the
     * whole payload, which is what the brief calls for.
     *
     * @return array{kind: string, fields: array<int, string>, label: string}
     */
    private function validatedReach(Node\Expr $request, MethodShape $method, SemanticContext $semantics, string $label): array
    {
        $type = $semantics->semantics()->receivers()->resolve($request, $method);
        $shape = $type->class === null ? null : $semantics->classes()->find($type->class);
        $rules = $shape?->method('rules');

        if ($rules !== null) {
            foreach ($rules->statements() as $statement) {
                if ($statement instanceof Node\Stmt\Return_ && $statement->expr instanceof Node\Expr\Array_) {
                    $fields = $this->arrayKeys($statement->expr);

                    if ($fields !== null) {
                        return ['kind' => 'only', 'fields' => $fields, 'label' => $label];
                    }
                }
            }
        }

        return ['kind' => 'all', 'fields' => [], 'label' => $label];
    }

    /**
     * Narrow an already-restricted payload with a trailing `->only()`/`->except()`.
     *
     * @param  array{kind: string, fields: array<int, string>, label: string}  $base
     * @return array{kind: string, fields: array<int, string>, label: string}|null
     */
    private function narrow(array $base, Node\Expr\MethodCall|Node\Expr\NullsafeMethodCall $expr, string $name): ?array
    {
        if ($name === 'all' || $name === 'toarray' || $name === 'collect') {
            return $base;
        }

        $fields = $this->literalFieldList($expr);

        if ($fields === null) {
            return null;
        }

        if ($name === 'only') {
            $allowed = $base['kind'] === 'only'
                ? array_values(array_intersect($fields, $base['fields']))
                : ($base['kind'] === 'except' ? array_values(array_diff($fields, $base['fields'])) : $fields);

            return ['kind' => 'only', 'fields' => $allowed, 'label' => $base['label'].'->only([...])'];
        }

        if ($name === 'except') {
            return $this->subtract($base, $fields, $base['label'].'->except([...])');
        }

        return null;
    }

    /**
     * @return array{kind: string, fields: array<int, string>, label: string}|null
     */
    private function staticAccessorReach(
        Node\Expr\StaticCall $expr,
        MethodShape $method,
        SemanticContext $semantics,
        TaintState $state,
        bool $nested,
        int $depth,
    ): ?array {
        if (! $expr->class instanceof Node\Name || ! $expr->name instanceof Node\Identifier || $expr->isFirstClassCallable()) {
            return null;
        }

        $class = TypeNames::shortName($method->file()->resolveName($expr->class));
        $name = strtolower($expr->name->toString());

        if ($class === 'Arr' && ($name === 'only' || $name === 'except')) {
            $inner = $this->positional($expr, 0);
            $base = $inner === null
                ? null
                : $this->requestArrayReach($inner, $method, $semantics, $state, $nested, $depth + 1);

            if ($base === null) {
                return null;
            }

            $fields = $this->literalFieldList($expr, 1);

            if ($fields === null) {
                return null;
            }

            return $name === 'only'
                ? ['kind' => 'only', 'fields' => $fields, 'label' => 'Arr::only('.$base['label'].', [...])']
                : $this->subtract($base, $fields, 'Arr::except('.$base['label'].', [...])');
        }

        if ($class !== 'Request' && $class !== 'Input') {
            return null;
        }

        if ($name === 'only' || $name === 'except') {
            $fields = $this->literalFieldList($expr);

            return $fields === null
                ? null
                : ['kind' => $name === 'only' ? 'only' : 'except', 'fields' => $fields, 'label' => $class.'::'.$name.'([...])'];
        }

        if (! in_array($name, self::WHOLESALE_ACCESSORS, true)) {
            return null;
        }

        if (in_array($name, self::ARGUMENTLESS_ACCESSORS, true) && $expr->getArgs() !== []) {
            return null;
        }

        return ['kind' => 'all', 'fields' => [], 'label' => $class.'::'.$name.'()'];
    }

    /**
     * @return array{kind: string, fields: array<int, string>, label: string}|null
     */
    private function functionReach(
        Node\Expr\FuncCall $expr,
        MethodShape $method,
        SemanticContext $semantics,
        TaintState $state,
        bool $nested,
        int $depth,
    ): ?array {
        if (! $expr->name instanceof Node\Name || $expr->isFirstClassCallable()) {
            return null;
        }

        $name = strtolower(TypeNames::shortName($expr->name->toString()));

        if ($name === 'request' && $expr->getArgs() !== []) {
            return ['kind' => 'all', 'fields' => [], 'label' => 'request(...)'];
        }

        if ($name !== 'array_merge') {
            return null;
        }

        // array_merge() with a literal array AFTER the request payload rewrites
        // those keys with server values; only the surviving keys are attacker
        // controlled.
        $reach = null;
        $overwritten = [];

        foreach ($expr->getArgs() as $argument) {
            if ($argument->name !== null || $argument->unpack) {
                return null;
            }

            $candidate = $this->requestArrayReach($argument->value, $method, $semantics, $state, $nested, $depth + 1);

            if ($candidate !== null) {
                $reach = $reach === null ? $candidate : ['kind' => 'all', 'fields' => [], 'label' => $reach['label']];

                continue;
            }

            if ($argument->value instanceof Node\Expr\Array_) {
                $keys = $this->arrayKeys($argument->value);

                if ($keys !== null) {
                    $overwritten = [...$overwritten, ...$keys];
                }
            }
        }

        if ($reach === null) {
            return null;
        }

        return $this->subtract($reach, $overwritten, 'array_merge('.$reach['label'].', ...)');
    }

    /**
     * An array literal carries client data only through the entries whose VALUE
     * is client controlled, plus any spread of a request array. This is what
     * separates `['user_id' => $request->input('user_id')]` (a real sink for
     * user_id) from `['user_id' => auth()->id()]` (a server-derived write, and
     * the overwhelmingly common shape in real applications).
     *
     * @return array{kind: string, fields: array<int, string>, label: string}|null
     */
    private function arrayLiteralReach(
        Node\Expr\Array_ $expr,
        MethodShape $method,
        SemanticContext $semantics,
        TaintState $state,
        bool $nested,
        int $depth,
    ): ?array {
        $fields = [];
        $spread = null;

        foreach ($expr->items as $item) {
            if ($item->unpack) {
                $spread = $this->requestArrayReach($item->value, $method, $semantics, $state, $nested, $depth + 1);

                continue;
            }

            if (! $item->key instanceof Node\Scalar\String_) {
                continue;
            }

            if ($semantics->semantics()->judge($item->value, $method, $state)->isTainted()) {
                $fields[] = strtolower($item->key->value);
            }
        }

        if ($spread !== null) {
            return $spread['kind'] === 'only'
                ? ['kind' => 'only', 'fields' => array_values(array_unique([...$spread['fields'], ...$fields])), 'label' => $spread['label'].' spread into an array literal']
                : $spread;
        }

        return $fields === []
            ? null
            : ['kind' => 'only', 'fields' => array_values(array_unique($fields)), 'label' => 'an array literal built from request input'];
    }

    /**
     * Remove keys from a reach.
     *
     * @param  array{kind: string, fields: array<int, string>, label: string}  $reach
     * @param  array<int, string>  $keys
     * @return array{kind: string, fields: array<int, string>, label: string}
     */
    private function subtract(array $reach, array $keys, string $label): array
    {
        if ($keys === []) {
            return ['kind' => $reach['kind'], 'fields' => $reach['fields'], 'label' => $label];
        }

        if ($reach['kind'] === 'only') {
            return ['kind' => 'only', 'fields' => array_values(array_diff($reach['fields'], $keys)), 'label' => $label];
        }

        return [
            'kind' => 'except',
            'fields' => array_values(array_unique([...$reach['fields'], ...$keys])),
            'label' => $label,
        ];
    }

    /**
     * The literal, lowercased column names passed to `only()`/`except()`, either
     * as one array literal or as variadic strings. Null when any entry is not a
     * literal — a restriction we cannot read is not a restriction we may ignore.
     *
     * @return array<int, string>|null
     */
    private function literalFieldList(Node\Expr\CallLike $call, int $from = 0): ?array
    {
        if ($call->isFirstClassCallable()) {
            return null;
        }

        $arguments = array_slice($call->getArgs(), $from);

        if ($arguments === []) {
            return null;
        }

        $fields = [];

        foreach ($arguments as $argument) {
            if ($argument->name !== null || $argument->unpack) {
                return null;
            }

            if ($argument->value instanceof Node\Scalar\String_) {
                $fields[] = strtolower($argument->value->value);

                continue;
            }

            if (! $argument->value instanceof Node\Expr\Array_) {
                return null;
            }

            foreach ($argument->value->items as $item) {
                if (! $item->value instanceof Node\Scalar\String_) {
                    return null;
                }

                $fields[] = strtolower($item->value->value);
            }
        }

        return $fields === [] ? null : array_values(array_unique($fields));
    }

    /**
     * The lowercased string keys of an array literal, or null when any key is
     * not a literal string.
     *
     * @return array<int, string>|null
     */
    private function arrayKeys(Node\Expr\Array_ $array): ?array
    {
        $keys = [];

        foreach ($array->items as $item) {
            if ($item->unpack || ! $item->key instanceof Node\Scalar\String_) {
                return null;
            }

            $keys[] = strtolower($item->key->value);
        }

        return $keys === [] ? null : array_values(array_unique($keys));
    }

    /**
     * The column names a validation rule set names, taken from its keys with
     * any `field.*` / `field.0` suffix removed.
     *
     * @return array<int, string>|null
     */
    private function ruleKeys(?Node\Expr $expr): ?array
    {
        if (! $expr instanceof Node\Expr\Array_) {
            return null;
        }

        $keys = $this->arrayKeys($expr);

        if ($keys === null) {
            return null;
        }

        return array_values(array_unique(array_map(
            static fn (string $key): string => str_contains($key, '.') ? substr($key, 0, (int) strpos($key, '.')) : $key,
            $keys,
        )));
    }

    private function positional(Node\Expr\CallLike $call, int $position): ?Node\Expr
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

    private function receiverLabel(Node\Expr $expr): string
    {
        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return '$'.$expr->name;
        }

        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            return $expr->name->toString().'()';
        }

        return '$request';
    }

    /**
     * Whether the node sits inside a closure, arrow function or anonymous class
     * — a different variable scope, which the reaching-assignment table does not
     * model.
     */
    private function isInsideNestedScope(Node $node): bool
    {
        $current = $node->getAttribute('parent');

        while ($current instanceof Node) {
            if ($current instanceof Node\Stmt\ClassMethod) {
                return false;
            }

            if ($current instanceof Node\Expr\Closure
                || $current instanceof Node\Expr\ArrowFunction
                || $current instanceof Node\Stmt\Function_
                || $current instanceof Node\Stmt\Class_) {
                return true;
            }

            $current = $current->getAttribute('parent');
        }

        return false;
    }

    /*
    |--------------------------------------------------------------------------
    | Model shape
    |--------------------------------------------------------------------------
    */

    /**
     * Casts declared by the model, keyed by lowercased column.
     *
     * Reads both the `$casts` property and the Laravel 11 `casts(): array`
     * method, in that order.
     *
     * @return array<string, string>
     */
    private function casts(ClassShape $class): array
    {
        foreach ($class->node()->stmts as $statement) {
            if (! $statement instanceof Node\Stmt\Property) {
                continue;
            }

            foreach ($statement->props as $item) {
                if ($item->name->toString() === 'casts' && $item->default instanceof Node\Expr\Array_) {
                    return $this->castPairs($item->default);
                }
            }
        }

        $method = $class->method('casts');

        if ($method === null) {
            return [];
        }

        foreach ($method->statements() as $statement) {
            if ($statement instanceof Node\Stmt\Return_ && $statement->expr instanceof Node\Expr\Array_) {
                return $this->castPairs($statement->expr);
            }
        }

        return [];
    }

    /**
     * @return array<string, string>
     */
    private function castPairs(Node\Expr\Array_ $array): array
    {
        $casts = [];

        foreach ($array->items as $item) {
            if (! $item->key instanceof Node\Scalar\String_ || ! $item->value instanceof Node\Scalar\String_) {
                continue;
            }

            $casts[strtolower(trim($item->key->value))] = strtolower(trim($item->value->value));
        }

        return $casts;
    }

    /**
     * Whether a declared class is an Eloquent model.
     *
     * Resolved ancestry first. The `type === 'model'` fallback exists for a
     * model that extends a base class the scan did not include, and still
     * requires an ancestor that NAMES a model base — it is not "the file lives
     * in app/Models".
     */
    private function isEloquentModel(ClassShape $class, SourceFile $file, SemanticContext $semantics): bool
    {
        if ($class->isInterface()) {
            return false;
        }

        if ($semantics->semantics()->isEloquentClass($class->fqcn())) {
            return true;
        }

        if ($file->type !== 'model') {
            return false;
        }

        foreach ($semantics->classes()->ancestry($class->fqcn()) as $ancestor) {
            if ($ancestor === $class->fqcn()) {
                continue;
            }

            $short = TypeNames::shortName($ancestor);

            if ($short === 'Authenticatable' || $short === 'Eloquent' || str_ends_with($short, 'Model')) {
                return true;
            }
        }

        return false;
    }

    /**
     * The string literals of a declared array property, each with the exact line
     * of its own node.
     *
     * Non-literal entries (constants, spreads, interpolation) are skipped rather
     * than guessed at: a field we cannot name is a field we cannot report.
     *
     * @return array<int, array{value: string, original: string, line: int}>
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
                    if (! $element->value instanceof Node\Scalar\String_) {
                        continue;
                    }

                    $original = trim($element->value->value);

                    $values[] = [
                        'value' => strtolower($original),
                        'original' => $original,
                        'line' => $element->getStartLine(),
                    ];
                }

                return $values;
            }
        }

        return [];
    }
}
