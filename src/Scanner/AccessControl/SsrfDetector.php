<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\AccessControl;

use Mahdi\HackAuditor\Scanner\Php\ClassShape;
use Mahdi\HackAuditor\Scanner\Php\LaravelSemantics;
use Mahdi\HackAuditor\Scanner\Php\MethodShape;
use Mahdi\HackAuditor\Scanner\Php\ParsedFile;
use Mahdi\HackAuditor\Scanner\Php\ReceiverKind;
use Mahdi\HackAuditor\Scanner\Php\ReceiverResolver;
use Mahdi\HackAuditor\Scanner\Php\SemanticContext;
use Mahdi\HackAuditor\Scanner\Php\SemanticWorkspace;
use Mahdi\HackAuditor\Scanner\Php\TaintJudgement;
use Mahdi\HackAuditor\Scanner\Php\TypeNames;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;
use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * Flags a controller action that dispatches an OUTBOUND request to a URL the
 * client chose, with nothing constraining the destination (CWE-918, OWASP A10).
 *
 * WHY THIS CLASS WAS REWRITTEN ON THE AST
 * ---------------------------------------
 * The previous implementation matched `/->\s*(?:get|post|...)\s*\(/` over raw
 * source. A verb name says nothing about what is being called:
 *
 *   $this->imageUpload->delete($user->profile_image)   // local disk storage
 *   User::query()->whereIn(...)->lockForUpdate()->get() // a database read
 *   $participants->get($blockedId)                     // a Collection lookup
 *
 * all read as "an HTTP client" to a verb-matching regex, and each produced a
 * HIGH-severity false positive on a clean application. The second half of the
 * defect was `isInlineRequestInput()` treating `$request->` as proof of
 * attacker control, which made `$request->user()` — the AUTHENTICATED USER
 * OBJECT — a taint source.
 *
 * THE RULES THIS DETECTOR OBEYS
 * -----------------------------
 *  1. THE RECEIVER MUST BE A PROVEN HTTP CLIENT. The Http facade, a
 *     PendingRequest, a Guzzle/PSR-18/Symfony client resolved from a promoted
 *     or typed property, a parameter type hint, an import or a `new`. Anything
 *     that resolves to Eloquent, a Collection, the filesystem, the request or a
 *     local application service is silent, and so is an UNRESOLVED receiver.
 *     A bare `->get()` / `->delete()` on an unknown receiver is never evidence.
 *     The one shape allowed without a resolved type is
 *     `->request('GET', $url)`: a literal HTTP method in argument one is a
 *     signature no query builder, Collection or storage service has. Even then
 *     the URL argument must independently look like a URL, and the rule is
 *     skipped entirely the moment the receiver resolves to something else.
 *  2. THE URL MUST BE PROVABLY CLIENT CONTROLLED. The argument is judged by
 *     LaravelSemantics over the AST, through assignments, in line order. Only
 *     genuine input readers taint — input()/query()/all()/json()/post()/
 *     get('key')/header()/cookie()/route('param')/validated()/$_GET/$_POST/
 *     $_REQUEST. `$request->user()`, `auth()->user()`, `$request->ip()`,
 *     `config()`, `route()`, `url()` and route-model-bound parameters are
 *     framework state, not input. An UNKNOWN verdict emits nothing.
 *  3. SANITISATION SILENCES THE FINDING. An `in_array()` allow-list over the
 *     destination (or over a `parse_url()` host taken from it), a
 *     `Str::startsWith()` check against a fixed base, or a `url`/`active_url`
 *     validation rule — declared inline or in the action's FormRequest — all
 *     mean the code already constrains the destination.
 *  4. EVERY LINE COMES FROM THE AST NODE (`getStartLine()`).
 *  5. THE FIX NAMES NO IDENTIFIER THAT IS NOT IN THE ANALYSED CODE. It
 *     describes the control to add; it never synthesises a call.
 */
final class SsrfDetector implements AccessControlDetector
{
    private readonly SemanticWorkspace $workspace;

    /**
     * Accepts the run-wide workspace so the file set is indexed once for all
     * detectors rather than once each.
     */
    public function __construct(?SemanticWorkspace $workspace = null)
    {
        $this->workspace = $workspace ?? new SemanticWorkspace;
    }

    /**
     * Request verbs on a PROVEN HTTP client whose FIRST argument is the URL.
     * Lower-cased; matching is case-insensitive.
     *
     * @var array<int, string>
     */
    private const URL_FIRST_VERBS = [
        'get', 'post', 'put', 'patch', 'delete', 'head', 'options',
        'getasync', 'postasync', 'putasync', 'patchasync', 'deleteasync',
        'headasync', 'optionsasync',
    ];

    /**
     * Request verbs on a PROVEN HTTP client whose SECOND argument is the URL
     * (`send($method, $url)`, `request($method, $uri)`).
     *
     * @var array<int, string>
     */
    private const URL_SECOND_VERBS = ['send', 'request', 'requestasync'];

    /**
     * Verbs whose `('GET', $url)` shape is itself evidence of an HTTP client,
     * used only when the receiver's type is genuinely unresolved.
     *
     * @var array<int, string>
     */
    private const SHAPE_EVIDENCE_VERBS = ['request', 'requestasync'];

    /**
     * @var array<int, string>
     */
    private const HTTP_METHOD_LITERALS = [
        'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT',
    ];

    /**
     * Receiver kinds that positively prove the call is NOT outbound HTTP.
     * Seeing one of these cancels every fallback rule.
     *
     * @var array<int, ReceiverKind>
     */
    private const NON_HTTP_KINDS = [
        ReceiverKind::Eloquent,
        ReceiverKind::Collection,
        ReceiverKind::Storage,
        ReceiverKind::Request,
        ReceiverKind::LocalService,
    ];

    /**
     * Word stems that make an identifier or literal read as a destination URL.
     * Required for the stream sinks (file_get_contents/fopen), which are just as
     * often local paths, and for the shape-evidence rule.
     *
     * @var array<int, string>
     */
    private const URL_WORDS = [
        'url', 'uri', 'endpoint', 'webhook', 'callback', 'href', 'link',
        'host', 'domain', 'feed', 'remote', 'origin',
    ];

    /**
     * Functions that constrain a value to a fixed set of permitted values.
     *
     * @var array<int, string>
     */
    private const ALLOW_LIST_FUNCTIONS = ['in_array', 'array_key_exists', 'array_search', 'array_flip'];

    /**
     * Calls whose array argument may carry validation rules.
     *
     * @var array<int, string>
     */
    private const VALIDATION_CALLS = ['validate', 'validatewithbag', 'make', 'sometimes', 'rules'];

    /**
     * Validation rules that constrain a value to a URL.
     *
     * @var array<int, string>
     */
    private const URL_RULES = ['url', 'active_url'];

    /**
     * @param  array<int, SourceFile>  $files
     * @return array<int, Vulnerability>
     */
    public function detect(array $files, AccessControlContext $context): array
    {
        $payload = [];
        $sources = [];

        foreach ($files as $file) {
            $payload[] = ['path' => $file->path, 'content' => $file->content, 'type' => $file->type];
            $sources[$file->path] = $file;
        }

        if ($payload === []) {
            return [];
        }

        $semantics = $this->workspace->contextFor($payload);
        $findings = [];

        // Decide from the class INDEX whether a file can hold a controller, and
        // only then open it. Four fifths of a real application declares none, and
        // parsing those to discover it is the difference between a
        // bounded-memory pass and a slow one.
        foreach ($semantics->paths() as $path) {
            $source = $sources[$path] ?? null;

            if (! $this->declaresControllerClass($path, $source, $semantics)) {
                continue;
            }

            $parsed = $semantics->parsed($path);

            if ($parsed === null || ! $parsed->isAnalysable()) {
                continue;
            }

            foreach ($parsed->classes() as $class) {
                if (! $this->isControllerClass($class, $source, $semantics)) {
                    continue;
                }

                foreach ($class->methods() as $method) {
                    if ($method->isAbstract()) {
                        continue;
                    }

                    $finding = $this->inspectMethod($parsed, $class, $method, $semantics);

                    if ($finding !== null) {
                        $findings[] = $finding;
                    }
                }
            }
        }

        return $findings;
    }

    /**
     * Only routed controller code is in scope: a request the client can reach.
     */
    private function isControllerClass(ClassShape $class, ?SourceFile $source, SemanticContext $semantics): bool
    {
        if ($class->isInterface()) {
            return false;
        }

        return $source?->type === 'controller' || $semantics->semantics()->isController($class);
    }

    /**
     * The same test as isControllerClass(), asked of the node-free summaries the
     * index holds. It must stay an exact mirror: a file this rejects is never
     * opened, so any divergence is a silently missed finding.
     */
    private function declaresControllerClass(string $path, ?SourceFile $source, SemanticContext $semantics): bool
    {
        foreach ($semantics->summariesIn($path) as $summary) {
            if ($summary->isInterface()) {
                continue;
            }

            if ($source?->type === 'controller' || $semantics->semantics()->isController($summary)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Report at most ONE finding per method: the first sink whose destination
     * is provably client controlled. One flow is one bug, and a method that
     * forwards the same tainted URL to two clients is still that one bug.
     */
    private function inspectMethod(ParsedFile $parsed, ClassShape $class, MethodShape $method, SemanticContext $semantics): ?Vulnerability
    {
        $statements = $method->statements();

        if ($statements === []) {
            return null;
        }

        $laravel = $semantics->semantics();
        $state = $semantics->taint()->track($method);

        foreach ($this->sinksIn($statements, $method, $laravel) as $sink) {
            $judgement = $laravel->judge($sink['url'], $method, $state);

            if (! $judgement->isTainted()) {
                continue;
            }

            if ($sink['needsUrlEvidence'] && ! $this->looksLikeUrl($sink['url'], $method, $laravel->receivers())) {
                continue;
            }

            if ($this->isConstrained($method, $sink['url'], $laravel)) {
                return null;
            }

            return $this->finding($parsed, $class, $method, $sink, $judgement);
        }

        return null;
    }

    /**
     * Every outbound-request sink in a method body, in source order, each with
     * the expression that supplies its destination URL.
     *
     * @param  array<int, Node\Stmt>  $statements
     * @return array<int, array{url: Node\Expr, label: string, line: int, needsUrlEvidence: bool}>
     */
    private function sinksIn(array $statements, MethodShape $method, LaravelSemantics $laravel): array
    {
        $finder = new NodeFinder;
        $sinks = [];

        $candidates = $finder->find($statements, static fn (Node $node): bool => $node instanceof Node\Expr\MethodCall
            || $node instanceof Node\Expr\NullsafeMethodCall
            || $node instanceof Node\Expr\StaticCall
            || $node instanceof Node\Expr\FuncCall);

        foreach ($candidates as $candidate) {
            if (! $candidate instanceof Node\Expr) {
                continue;
            }

            $sink = $candidate instanceof Node\Expr\FuncCall
                ? $this->functionSink($candidate, $method)
                : $this->clientSink($candidate, $method, $laravel);

            if ($sink !== null) {
                $sinks[] = $sink;
            }
        }

        usort($sinks, static fn (array $a, array $b): int => $a['line'] <=> $b['line']);

        return $sinks;
    }

    /**
     * A call on a receiver: reported ONLY when that receiver is proven to speak
     * HTTP, with the single narrow shape exception documented on the class.
     *
     * @return array{url: Node\Expr, label: string, line: int, needsUrlEvidence: bool}|null
     */
    private function clientSink(Node\Expr $call, MethodShape $method, LaravelSemantics $laravel): ?array
    {
        if (! $call instanceof Node\Expr\MethodCall
            && ! $call instanceof Node\Expr\NullsafeMethodCall
            && ! $call instanceof Node\Expr\StaticCall) {
            return null;
        }

        if (! $call->name instanceof Node\Identifier) {
            return null;
        }

        $verb = strtolower($call->name->toString());
        $classification = $laravel->classifyCall($call, $method);

        if ($classification->kind === ReceiverKind::HttpClient) {
            $index = match (true) {
                in_array($verb, self::URL_FIRST_VERBS, true) => 0,
                in_array($verb, self::URL_SECOND_VERBS, true) => 1,
                default => null,
            };

            if ($index === null) {
                return null;
            }

            $url = $this->argument($call, $index, ['url', 'uri']);

            if ($url === null) {
                return null;
            }

            $receiver = $classification->receiver->shortName();

            return [
                'url' => $url,
                'label' => $call instanceof Node\Expr\StaticCall
                    ? sprintf('%s::%s()', $receiver ?? 'the HTTP client', $call->name->toString())
                    : sprintf('->%s() on %s', $call->name->toString(), $receiver ?? 'the resolved HTTP client'),
                'line' => $call->getStartLine(),
                'needsUrlEvidence' => false,
            ];
        }

        // A receiver we positively identified as something else is never an
        // outbound request, whatever the verb is called. This is the rule that
        // keeps $this->imageUpload->delete(), User::query()->...->get() and
        // $participants->get() silent.
        if (in_array($classification->kind, self::NON_HTTP_KINDS, true)) {
            return null;
        }

        if (! in_array($verb, self::SHAPE_EVIDENCE_VERBS, true)) {
            return null;
        }

        $verbArgument = $this->argument($call, 0);
        $url = $this->argument($call, 1);

        if ($url === null || ! $verbArgument instanceof Node\Scalar\String_) {
            return null;
        }

        if (! in_array(strtoupper($verbArgument->value), self::HTTP_METHOD_LITERALS, true)) {
            return null;
        }

        return [
            'url' => $url,
            'label' => sprintf("->%s('%s', ...)", $call->name->toString(), strtoupper($verbArgument->value)),
            'line' => $call->getStartLine(),
            'needsUrlEvidence' => true,
        ];
    }

    /**
     * cURL and the stream wrappers. cURL is unambiguously a network client, so
     * its URL needs no further evidence; file_get_contents()/fopen() read local
     * paths just as often as remote ones, so they additionally require the
     * destination to read as a URL.
     *
     * @return array{url: Node\Expr, label: string, line: int, needsUrlEvidence: bool}|null
     */
    private function functionSink(Node\Expr\FuncCall $call, MethodShape $method): ?array
    {
        if (! $call->name instanceof Node\Name) {
            return null;
        }

        $name = strtolower(TypeNames::shortName($method->file()->resolveName($call->name)));

        $sink = match ($name) {
            'curl_init' => $this->simpleSink($call, 0, 'curl_init()', false),
            'file_get_contents' => $this->simpleSink($call, 0, 'file_get_contents()', true),
            'fopen' => $this->simpleSink($call, 0, 'fopen()', true),
            'get_headers' => $this->simpleSink($call, 0, 'get_headers()', false),
            'curl_setopt' => $this->curlSetoptSink($call),
            'curl_setopt_array' => $this->curlSetoptArraySink($call),
            default => null,
        };

        return $sink;
    }

    /**
     * @return array{url: Node\Expr, label: string, line: int, needsUrlEvidence: bool}|null
     */
    private function simpleSink(Node\Expr\FuncCall $call, int $index, string $label, bool $needsUrlEvidence): ?array
    {
        $url = $this->argument($call, $index);

        if ($url === null) {
            return null;
        }

        return [
            'url' => $url,
            'label' => $label,
            'line' => $call->getStartLine(),
            'needsUrlEvidence' => $needsUrlEvidence,
        ];
    }

    /**
     * curl_setopt($handle, CURLOPT_URL, $destination).
     *
     * @return array{url: Node\Expr, label: string, line: int, needsUrlEvidence: bool}|null
     */
    private function curlSetoptSink(Node\Expr\FuncCall $call): ?array
    {
        $option = $this->argument($call, 1);
        $url = $this->argument($call, 2);

        if ($url === null || ! $this->isCurloptUrl($option)) {
            return null;
        }

        return [
            'url' => $url,
            'label' => 'curl_setopt(..., CURLOPT_URL, ...)',
            'line' => $call->getStartLine(),
            'needsUrlEvidence' => false,
        ];
    }

    /**
     * curl_setopt_array($handle, [CURLOPT_URL => $destination, ...]).
     *
     * @return array{url: Node\Expr, label: string, line: int, needsUrlEvidence: bool}|null
     */
    private function curlSetoptArraySink(Node\Expr\FuncCall $call): ?array
    {
        $options = $this->argument($call, 1);

        if (! $options instanceof Node\Expr\Array_) {
            return null;
        }

        foreach ($options->items as $item) {
            if (! $this->isCurloptUrl($item->key)) {
                continue;
            }

            return [
                'url' => $item->value,
                'label' => 'curl_setopt_array(..., [CURLOPT_URL => ...])',
                'line' => $call->getStartLine(),
                'needsUrlEvidence' => false,
            ];
        }

        return null;
    }

    private function isCurloptUrl(?Node\Expr $expr): bool
    {
        return $expr instanceof Node\Expr\ConstFetch
            && strtoupper(TypeNames::shortName($expr->name->toString())) === 'CURLOPT_URL';
    }

    /**
     * The nth positional argument of a call, or the argument passed under one
     * of `$names` if the caller used named arguments.
     *
     * A spread (`...$args`) or a variadic placeholder makes the position
     * unknowable, and an unknowable argument is not evidence: the whole sink is
     * abandoned rather than guessed at.
     *
     * @param  array<int, string>  $names  Lower-cased named-argument aliases
     */
    private function argument(Node\Expr\MethodCall|Node\Expr\NullsafeMethodCall|Node\Expr\StaticCall|Node\Expr\FuncCall $call, int $index, array $names = []): ?Node\Expr
    {
        $positional = [];

        foreach ($call->args as $argument) {
            if (! $argument instanceof Node\Arg || $argument->unpack) {
                return null;
            }

            if ($argument->name !== null) {
                if (in_array(strtolower($argument->name->toString()), $names, true)) {
                    return $argument->value;
                }

                continue;
            }

            $positional[] = $argument->value;
        }

        return $positional[$index] ?? null;
    }

    /**
     * Whether an expression reads as a destination URL rather than a local
     * path: an identifier, key or literal along its assignment trail contains a
     * URL word. Used only to NARROW the stream and shape-evidence sinks.
     */
    private function looksLikeUrl(Node\Expr $expr, MethodShape $method, ReceiverResolver $receivers, int $depth = 0): bool
    {
        if ($depth > 4) {
            return false;
        }

        $finder = new NodeFinder;
        $variables = [];

        $tokens = $finder->find($expr, static fn (Node $node): bool => $node instanceof Node\Expr\Variable
            || $node instanceof Node\Identifier
            || $node instanceof Node\Scalar\String_);

        foreach ($tokens as $token) {
            if ($token instanceof Node\Expr\Variable && is_string($token->name)) {
                if ($this->isUrlWord($token->name)) {
                    return true;
                }

                $variables[] = $token->name;

                continue;
            }

            if ($token instanceof Node\Identifier && $this->isUrlWord($token->toString())) {
                return true;
            }

            if ($token instanceof Node\Scalar\String_ && $this->isUrlWord($token->value)) {
                return true;
            }
        }

        foreach ($variables as $name) {
            $assignment = $receivers->assignmentsFor($method)->reaching($name, $expr->getStartLine());

            if ($assignment !== null && $this->looksLikeUrl($assignment['expr'], $method, $receivers, $depth + 1)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether one identifier reads as a URL.
     *
     * The pattern here normalises a SINGLE token the parser already isolated —
     * a variable name, a property name, an array key — never PHP source. It can
     * only ever REMOVE a candidate finding, so a miss here costs recall and can
     * never invent a vulnerability.
     */
    private function isUrlWord(string $token): bool
    {
        $normalised = strtolower((string) preg_replace('/[^a-z0-9]/i', '', $token));

        if ($normalised === '') {
            return false;
        }

        foreach (self::URL_WORDS as $word) {
            if (str_contains($normalised, $word)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the method already constrains the destination.
     *
     * Any of: an allow-list membership test over the destination (or over a
     * value derived from it, which covers
     * `$host = parse_url($url, PHP_URL_HOST)` followed by
     * `in_array($host, $permitted)`); a `Str::startsWith()` prefix check; or a
     * `url`/`active_url` validation rule declared inline or in the action's
     * FormRequest.
     */
    private function isConstrained(MethodShape $method, Node\Expr $url, LaravelSemantics $laravel): bool
    {
        $aliases = $this->aliasesOf($url, $method, $laravel->receivers());

        if ($aliases !== [] && $this->hasAllowListCheck($method, $aliases)) {
            return true;
        }

        return $this->validatesAUrl($method, $laravel);
    }

    /**
     * The variable names that carry the destination: those read by the URL
     * expression, plus every local variable derived from one of them.
     *
     * @return array<int, string>
     */
    private function aliasesOf(Node\Expr $url, MethodShape $method, ReceiverResolver $receivers): array
    {
        $finder = new NodeFinder;
        $aliases = [];

        foreach ($finder->findInstanceOf($url, Node\Expr\Variable::class) as $variable) {
            if (is_string($variable->name) && $variable->name !== 'this') {
                $aliases[$variable->name] = true;
            }
        }

        if ($aliases === []) {
            return [];
        }

        $assignments = $receivers->assignmentsFor($method)->all();

        for ($round = 0; $round < 4; $round++) {
            $grew = false;

            foreach ($assignments as $assignment) {
                if (isset($aliases[$assignment['name']])) {
                    continue;
                }

                if (! $this->referencesAny($assignment['expr'], array_keys($aliases))) {
                    continue;
                }

                $aliases[$assignment['name']] = true;
                $grew = true;
            }

            if (! $grew) {
                break;
            }
        }

        return array_keys($aliases);
    }

    /**
     * @param  array<int, string>  $aliases
     */
    private function hasAllowListCheck(MethodShape $method, array $aliases): bool
    {
        $finder = new NodeFinder;

        $calls = $finder->find($method->statements(), static fn (Node $node): bool => $node instanceof Node\Expr\FuncCall
            || $node instanceof Node\Expr\StaticCall
            || $node instanceof Node\Expr\MethodCall);

        foreach ($calls as $call) {
            if (! $call instanceof Node\Expr) {
                continue;
            }

            if (! $this->isAllowListCall($call, $method)) {
                continue;
            }

            if (! $call instanceof Node\Expr\FuncCall
                && ! $call instanceof Node\Expr\StaticCall
                && ! $call instanceof Node\Expr\MethodCall) {
                continue;
            }

            foreach ($call->args as $argument) {
                if ($argument instanceof Node\Arg && $this->referencesAny($argument->value, $aliases)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function isAllowListCall(Node\Expr $call, MethodShape $method): bool
    {
        if ($call instanceof Node\Expr\FuncCall) {
            return $call->name instanceof Node\Name
                && in_array(strtolower(TypeNames::shortName($method->file()->resolveName($call->name))), self::ALLOW_LIST_FUNCTIONS, true);
        }

        if ($call instanceof Node\Expr\StaticCall) {
            return $call->name instanceof Node\Identifier
                && $call->class instanceof Node\Name
                && $method->file()->resolveName($call->class) === 'Illuminate\Support\Str'
                && in_array(strtolower($call->name->toString()), ['startswith', 'is'], true);
        }

        if ($call instanceof Node\Expr\MethodCall) {
            return $call->name instanceof Node\Identifier
                && strtolower($call->name->toString()) === 'startswith';
        }

        return false;
    }

    /**
     * Whether a `url`/`active_url` rule governs the request data — declared
     * inline via validate()/Validator::make(), or by the FormRequest injected
     * into the action.
     */
    private function validatesAUrl(MethodShape $method, LaravelSemantics $laravel): bool
    {
        $finder = new NodeFinder;

        $calls = $finder->find($method->statements(), static fn (Node $node): bool => $node instanceof Node\Expr\MethodCall
            || $node instanceof Node\Expr\StaticCall);

        foreach ($calls as $call) {
            if (! $call instanceof Node\Expr\MethodCall && ! $call instanceof Node\Expr\StaticCall) {
                continue;
            }

            if (! $call->name instanceof Node\Identifier
                || ! in_array(strtolower($call->name->toString()), self::VALIDATION_CALLS, true)) {
                continue;
            }

            foreach ($call->args as $argument) {
                if ($argument instanceof Node\Arg && $this->declaresUrlRule($argument->value)) {
                    return true;
                }
            }
        }

        foreach ($method->parameters() as $parameter) {
            $class = $parameter->classType($method->file());

            if ($class === null || ! $laravel->isRequestClass($class)) {
                continue;
            }

            $shape = $laravel->index()->find($class);
            $rules = $shape?->method('rules');

            if ($rules !== null && $this->declaresUrlRule($rules->statements())) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a rules array declares a `url`/`active_url` rule.
     *
     * Only array VALUES are read. A rules array is keyed by field name, and a
     * field that happens to be called "url" is not a rule — reading keys would
     * silence `validate(['url' => 'required'])`, which constrains nothing.
     *
     * @param  Node|array<int, Node>  $nodes
     */
    private function declaresUrlRule(Node|array $nodes): bool
    {
        if ($nodes === []) {
            return false;
        }

        foreach ((new NodeFinder)->findInstanceOf($nodes, Node\ArrayItem::class) as $item) {
            if (! $item->value instanceof Node\Scalar\String_) {
                continue;
            }

            foreach (explode('|', $item->value->value) as $token) {
                $name = strtolower(trim(explode(':', $token, 2)[0]));

                if (in_array($name, self::URL_RULES, true)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Whether an expression reads any of the given variables.
     *
     * @param  array<int, string>  $names
     */
    private function referencesAny(Node\Expr $expr, array $names): bool
    {
        foreach ((new NodeFinder)->findInstanceOf($expr, Node\Expr\Variable::class) as $variable) {
            if (is_string($variable->name) && in_array($variable->name, $names, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  array{url: Node\Expr, label: string, line: int, needsUrlEvidence: bool}  $sink
     */
    private function finding(ParsedFile $parsed, ClassShape $class, MethodShape $method, array $sink, TaintJudgement $judgement): Vulnerability
    {
        $source = $judgement->source ?? 'client-supplied request data';

        return new Vulnerability(
            type: VulnerabilityType::Ssrf,
            location: $parsed->path,
            line: $sink['line'],
            severity: SeverityLevel::High,
            description: sprintf(
                '%s::%s() dispatches an outbound request through %s to a destination taken from client input (%s). Nothing restricts the host, so a client can steer the request at internal services, a localhost-only admin panel, or the cloud metadata endpoint 169.254.169.254 (SSRF, CWE-918).',
                $class->shortName(),
                $method->name(),
                $sink['label'],
                $source,
            ),
            proof: sprintf(
                'The destination argument of %s on line %d is client controlled — %s. No allow-list membership test and no url/active_url validation rule constrains it anywhere in %s() before the request is dispatched.',
                $sink['label'],
                $sink['line'],
                $judgement->evidence,
                $method->name(),
            ),
            fix: 'Constrain the destination before the request is made: take its host with parse_url(), require that host to appear in a configured allow-list of permitted hosts, and reject everything else — including private and link-local ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16). A `url`/`active_url` validation rule is not sufficient on its own, because http://169.254.169.254/ satisfies it.',
            taintTrace: sprintf(
                'SOURCE: %s → SINK: %s at %s:%d',
                $source,
                $sink['label'],
                $parsed->path,
                $sink['line'],
            ),
        );
    }
}
