<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

use PhpParser\Node;

/**
 * Laravel-aware interpretation of a resolved AST.
 *
 * Two questions, both answered with evidence:
 *
 *  1. WHAT IS THIS RECEIVER? An outbound HTTP client, an Eloquent model or
 *     query builder, a Collection, the filesystem, the request, or a local
 *     application service. A verb such as `get`/`post`/`delete` means nothing
 *     on its own — `Http::get($url)` is an outbound request,
 *     `User::query()->lockForUpdate()->get()` is a database read, and
 *     `$this->imageUpload->delete($path)` is a local file delete.
 *
 *  2. IS THIS VALUE ATTACKER CONTROLLED? `$request->input('url')` is.
 *     `$request->user()` is the AUTHENTICATED USER OBJECT and is not.
 *     `auth()->user()`, `$request->ip()`, `config()` and route-model-bound
 *     parameters are not either.
 *
 * Anything the code does not state is InputTrust::Unknown / ReceiverKind::Unknown.
 * Neither is a hedge toward "dangerous" — both mean detectors emit nothing.
 */
final class LaravelSemantics
{
    private const MAX_DEPTH = 8;

    /**
     * Classes whose instances make outbound HTTP requests.
     *
     * @var array<int, string>
     */
    public const HTTP_CLIENT_CLASSES = [
        'Illuminate\Support\Facades\Http',
        'Illuminate\Http\Client\Factory',
        'Illuminate\Http\Client\PendingRequest',
        'GuzzleHttp\Client',
        'GuzzleHttp\ClientInterface',
        'Psr\Http\Client\ClientInterface',
        'Symfony\Component\HttpClient\HttpClient',
        'Symfony\Contracts\HttpClient\HttpClientInterface',
    ];

    /**
     * Base classes and facades that mean "this is the database".
     *
     * @var array<int, string>
     */
    public const ELOQUENT_CLASSES = [
        'Illuminate\Database\Eloquent\Model',
        'Illuminate\Database\Eloquent\Builder',
        'Illuminate\Database\Query\Builder',
        'Illuminate\Database\Eloquent\Relations\Relation',
        'Illuminate\Foundation\Auth\User',
        'Illuminate\Support\Facades\DB',
    ];

    /**
     * @var array<int, string>
     */
    public const COLLECTION_CLASSES = [
        'Illuminate\Support\Collection',
        'Illuminate\Support\LazyCollection',
        'Illuminate\Database\Eloquent\Collection',
    ];

    /**
     * @var array<int, string>
     */
    public const STORAGE_CLASSES = [
        'Illuminate\Support\Facades\Storage',
        'Illuminate\Contracts\Filesystem\Filesystem',
        'Illuminate\Filesystem\Filesystem',
        'Illuminate\Filesystem\FilesystemAdapter',
    ];

    /**
     * @var array<int, string>
     */
    public const REQUEST_CLASSES = [
        'Illuminate\Http\Request',
        'Illuminate\Foundation\Http\FormRequest',
        'Symfony\Component\HttpFoundation\Request',
    ];

    /**
     * Methods that exist on a query builder and on nothing that speaks HTTP.
     * Seeing one anywhere in a call chain proves the chain is a database query,
     * whatever the verb at the end of it happens to be called.
     *
     * @var array<int, string>
     */
    private const BUILDER_METHODS = [
        'query', 'newquery', 'where', 'wherein', 'wherenotin', 'wherehas',
        'wherenull', 'wherenotnull', 'wherebetween', 'wheredate', 'wherecolumn',
        'orwhere', 'orwherein', 'orderby', 'orderbydesc', 'latest', 'oldest',
        'groupby', 'having', 'join', 'leftjoin', 'rightjoin', 'select',
        'selectraw', 'withcount', 'withtrashed', 'onlytrashed', 'lockforupdate',
        'sharedlock', 'findorfail', 'firstorfail', 'firstorcreate',
        'updateorcreate', 'firstornew', 'paginate', 'simplepaginate',
        'cursorpaginate', 'chunk', 'chunkbyid', 'doesntexist', 'tosql',
        'limit', 'offset', 'skip', 'take', 'distinct', 'inrandomorder',
        'withoutglobalscopes', 'scopes', 'whererelation', 'wheredoesnthave',
    ];

    /**
     * Methods that exist on a Collection and not on an HTTP client.
     *
     * @var array<int, string>
     */
    private const COLLECTION_METHODS = [
        'map', 'filter', 'reject', 'each', 'mapwithkeys', 'flatmap', 'sortby',
        'sortbydesc', 'unique', 'collapse', 'flatten', 'partition', 'avg',
        'groupby', 'keyby', 'zip',
    ];

    /**
     * Request accessors that return CLIENT-SUPPLIED data.
     *
     * @var array<int, string>
     */
    private const TAINTED_REQUEST_METHODS = [
        'input', 'query', 'post', 'json', 'all', 'get', 'string', 'str',
        'integer', 'float', 'boolean', 'date', 'enum', 'only', 'except',
        'collect', 'keys', 'header', 'cookie', 'file', 'files', 'allfiles',
        'segment', 'segments', 'bearertoken', 'getcontent', 'useragent',
    ];

    /**
     * Request accessors that return VALIDATED client data. Still the client's
     * data, but a detector may reasonably treat a validated value differently,
     * so the judgement carries a flag rather than a different verdict.
     *
     * @var array<int, string>
     */
    private const VALIDATED_REQUEST_METHODS = ['validated', 'safe'];

    /**
     * Request accessors that return framework or server state, NOT input.
     * `user()` heads this list on purpose: mistaking the authenticated user
     * object for attacker input is the exact defect this class exists to stop.
     *
     * @var array<int, string>
     */
    private const TRUSTED_REQUEST_METHODS = [
        'user', 'ip', 'ips', 'getclientip', 'method', 'getmethod', 'ismethod',
        'ajax', 'pjax', 'wantsjson', 'expectsjson', 'acceptsjson', 'routeis',
        'is', 'fullurlis', 'hasvalidsignature', 'hasvalidrelativesignature',
        'session', 'fingerprint', 'isjson',
    ];

    /**
     * Request properties that hold framework state rather than input.
     * Everything else read as a property goes through Request::__get(), which
     * reads request input, so it IS client supplied.
     *
     * @var array<int, string>
     */
    private const NON_INPUT_REQUEST_PROPERTIES = ['attributes', 'session', 'userResolver', 'routeResolver'];

    /**
     * Helpers whose result is server-side configuration or generated state.
     *
     * @var array<int, string>
     */
    private const TRUSTED_FUNCTIONS = [
        'config', 'env', 'base_path', 'storage_path', 'public_path',
        'resource_path', 'database_path', 'app_path', 'route', 'url',
        'secure_url', 'action', 'asset', 'secure_asset', 'csrf_token', 'now',
        'today', 'trans', '__', 'app', 'auth', 'str_random', 'uniqid',
    ];

    /**
     * Helpers that return client input.
     *
     * @var array<int, string>
     */
    private const TAINTED_FUNCTIONS = ['old'];

    /**
     * Functions that transform a value without changing who controls it.
     *
     * @var array<int, string>
     */
    private const TAINT_PRESERVING_FUNCTIONS = [
        'trim', 'ltrim', 'rtrim', 'strtolower', 'strtoupper', 'ucfirst',
        'ucwords', 'strval', 'sprintf', 'vsprintf', 'implode', 'join',
        'str_replace', 'preg_replace', 'substr', 'urldecode', 'rawurldecode',
        'urlencode', 'rawurlencode', 'json_decode', 'base64_decode',
        'htmlspecialchars', 'html_entity_decode', 'strip_tags', 'nl2br', 'e',
        'intval', 'floatval', 'number_format', 'data_get', 'explode', 'str_pad',
    ];

    /**
     * @var array<int, string>
     */
    private const SUPERGLOBALS = ['_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES', '_SERVER'];

    /**
     * Identifier stems that make a SERVER-CONTROLLED value read as the base of
     * a URL — the part that carries scheme, host and port.
     *
     * Used only to recognise `config('services.crm.base_url')` as an origin
     * that a later concatenated segment cannot move. It can only ever NARROW a
     * taint, never create one.
     *
     * @var array<int, string>
     */
    private const URL_BASE_WORDS = ['url', 'uri', 'endpoint', 'host', 'domain', 'origin', 'gateway'];

    /**
     * Characters that close the authority of a URL. Once one of them has been
     * written by server-controlled text, everything after it is path or query.
     *
     * @var array<int, string>
     */
    private const AUTHORITY_TERMINATORS = ['/', '?', '#'];

    /**
     * A scheme followed by `://`: the point at which an authority begins.
     */
    private const SCHEME_PATTERN = '~^[a-z][a-z0-9+.\-]*://~i';

    /**
     * Longest rendering of a source expression that may appear in finding text.
     * Beyond this the expression is described, not quoted.
     */
    private const MAX_RENDERED_LENGTH = 80;

    private readonly ReceiverResolver $receivers;

    private readonly ClassIndex $index;

    public function __construct(?ReceiverResolver $receivers = null, ?ClassIndex $index = null)
    {
        $this->receivers = $receivers ?? new ReceiverResolver;
        $this->index = $index ?? new ClassIndex;
    }

    public function receivers(): ReceiverResolver
    {
        return $this->receivers;
    }

    public function index(): ClassIndex
    {
        return $this->index;
    }

    /**
     * Classify one call site: what is being called, on what, and why we believe it.
     */
    public function classifyCall(Node\Expr\MethodCall|Node\Expr\NullsafeMethodCall|Node\Expr\StaticCall $call, MethodShape $method): CallClassification
    {
        $verb = $call->name instanceof Node\Identifier ? $call->name->toString() : '';
        $resolved = $this->receivers->resolveChain($call, $method);
        $root = $resolved['root'];
        $chain = $resolved['chain'];
        $receiver = $this->receivers->resolve($root, $method);

        [$kind, $evidence] = $this->kindFor($receiver, $chain);

        return new CallClassification(
            kind: $kind,
            method: $verb,
            receiver: $receiver,
            chain: $chain,
            evidence: $evidence,
            line: $call->getStartLine(),
        );
    }

    /**
     * @param  array<int, string>  $chain
     * @return array{0: ReceiverKind, 1: string}
     */
    private function kindFor(ResolvedType $receiver, array $chain): array
    {
        if ($receiver->isAnyOf(self::HTTP_CLIENT_CLASSES)) {
            return [ReceiverKind::HttpClient, sprintf('%s is an HTTP client (%s)', $receiver->describe(), $receiver->evidence)];
        }

        if ($receiver->class !== null && $this->isEloquentClass($receiver->class)) {
            return [ReceiverKind::Eloquent, sprintf('%s is an Eloquent model/builder (%s)', $receiver->describe(), $receiver->evidence)];
        }

        if ($receiver->isAnyOf(self::COLLECTION_CLASSES)) {
            return [ReceiverKind::Collection, sprintf('%s is a Collection (%s)', $receiver->describe(), $receiver->evidence)];
        }

        if ($receiver->isAnyOf(self::STORAGE_CLASSES)) {
            return [ReceiverKind::Storage, sprintf('%s is the filesystem (%s)', $receiver->describe(), $receiver->evidence)];
        }

        if ($receiver->class !== null && $this->isRequestClass($receiver->class)) {
            return [ReceiverKind::Request, sprintf('%s is the HTTP request (%s)', $receiver->describe(), $receiver->evidence)];
        }

        // Only once the receiver's declared type has failed to settle the
        // question do we fall back to the shape of the chain. A method name is
        // weaker evidence than a type hint and must never override one.
        $builder = $this->firstIn($chain, self::BUILDER_METHODS);

        if ($builder !== null) {
            return [ReceiverKind::Eloquent, sprintf(
                'the call chain includes %s(), which exists on a query builder and on no HTTP client',
                $builder,
            )];
        }

        $collectionMethod = $this->firstIn($chain, self::COLLECTION_METHODS);

        if ($collectionMethod !== null && ! $receiver->isKnown()) {
            return [ReceiverKind::Collection, sprintf(
                'the call chain includes %s(), a Collection method',
                $collectionMethod,
            )];
        }

        if ($receiver->class !== null) {
            return [ReceiverKind::LocalService, sprintf('%s is a local application service (%s)', $receiver->describe(), $receiver->evidence)];
        }

        return [ReceiverKind::Unknown, $receiver->evidence];
    }

    /**
     * Whether a class is, or descends from, an Eloquent model / query builder.
     * The App\Models convention is honoured only as a fallback, after the
     * declared ancestry has been consulted.
     */
    public function isEloquentClass(string $fqcn): bool
    {
        $fqcn = ltrim($fqcn, '\\');

        if (in_array($fqcn, self::ELOQUENT_CLASSES, true)) {
            return true;
        }

        if (str_starts_with($fqcn, 'Illuminate\Database\Eloquent\Relations\\')) {
            return true;
        }

        if ($this->index->descendsFromAny($fqcn, self::ELOQUENT_CLASSES)) {
            return true;
        }

        return ! $this->index->has($fqcn) && str_contains($fqcn, '\\Models\\');
    }

    public function isRequestClass(string $fqcn): bool
    {
        $fqcn = ltrim($fqcn, '\\');

        if (in_array($fqcn, self::REQUEST_CLASSES, true)) {
            return true;
        }

        if ($this->index->descendsFromAny($fqcn, self::REQUEST_CLASSES)) {
            return true;
        }

        return ! $this->index->has($fqcn) && str_ends_with(TypeNames::shortName($fqcn), 'Request');
    }

    public function isCollectionClass(string $fqcn): bool
    {
        return in_array(ltrim($fqcn, '\\'), self::COLLECTION_CLASSES, true)
            || $this->index->descendsFromAny($fqcn, self::COLLECTION_CLASSES);
    }

    /**
     * Whether a class is a routed controller.
     *
     * Takes a summary as readily as a shape: the question is answered from the
     * class NAME and its ancestry, never from a node, so it must not force a
     * caller holding only a summary to re-open the file.
     */
    public function isController(ClassShape|ClassSummary $class): bool
    {
        if (str_ends_with($class->shortName(), 'Controller')) {
            return true;
        }

        foreach ($this->index->ancestry($class->fqcn()) as $ancestor) {
            if (str_ends_with(TypeNames::shortName($ancestor), 'Controller')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether an expression evaluates to the HTTP request object.
     */
    public function isRequestExpression(Node\Expr $expr, MethodShape $method): bool
    {
        if ($expr instanceof Node\Expr\FuncCall
            && $expr->name instanceof Node\Name
            && strtolower($expr->name->toString()) === 'request'
            && $expr->args === []) {
            return true;
        }

        $type = $this->receivers->resolve($expr, $method);

        return $type->class !== null && $this->isRequestClass($type->class);
    }

    /**
     * Decide whether an expression is attacker controlled.
     *
     * @param  TaintState|null  $state  Known variable verdicts, when a full
     *                                  method walk has already been performed
     */
    public function judge(Node\Expr $expr, MethodShape $method, ?TaintState $state = null, int $depth = 0): TaintJudgement
    {
        if ($depth > self::MAX_DEPTH) {
            return TaintJudgement::unknown('expression nesting exceeded the analysis depth limit');
        }

        if ($expr instanceof Node\Scalar || $expr instanceof Node\Expr\ConstFetch || $expr instanceof Node\Expr\ClassConstFetch) {
            if ($expr instanceof Node\Scalar\InterpolatedString) {
                return $this->judgeConcatenation($expr, $method, $state, $depth, 'string interpolation');
            }

            return TaintJudgement::trusted('literal value');
        }

        if ($expr instanceof Node\Expr\Variable) {
            return $this->judgeVariable($expr, $method, $state, $depth);
        }

        if ($expr instanceof Node\Expr\ArrayDimFetch) {
            return $this->judge($expr->var, $method, $state, $depth + 1);
        }

        if ($expr instanceof Node\Expr\Array_) {
            $values = [];

            foreach ($expr->items as $item) {
                $values[] = $item->value;
            }

            return $this->judgeParts($values, $method, $state, $depth, 'array literal');
        }

        if ($expr instanceof Node\Expr\PropertyFetch || $expr instanceof Node\Expr\NullsafePropertyFetch) {
            return $this->judgeProperty($expr, $method, $state, $depth);
        }

        if ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\NullsafeMethodCall) {
            return $this->judgeMethodCall($expr, $method);
        }

        if ($expr instanceof Node\Expr\StaticCall) {
            return $this->judgeStaticCall($expr, $method, $state, $depth);
        }

        if ($expr instanceof Node\Expr\FuncCall) {
            return $this->judgeFuncCall($expr, $method, $state, $depth);
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->judgeConcatenation($expr, $method, $state, $depth, 'string concatenation');
        }

        if ($expr instanceof Node\Expr\BinaryOp\Coalesce) {
            return $this->judgeParts([$expr->left, $expr->right], $method, $state, $depth, 'null coalescing');
        }

        if ($expr instanceof Node\Expr\Ternary) {
            $branches = array_values(array_filter([$expr->if, $expr->else]));

            return $this->judgeParts($branches, $method, $state, $depth, 'ternary');
        }

        if ($expr instanceof Node\Expr\Cast) {
            return $this->judge($expr->expr, $method, $state, $depth + 1);
        }

        return TaintJudgement::unknown(sprintf('no taint rule covers %s', $expr->getType()));
    }

    /**
     * @param  array<int, Node|null>  $parts
     */
    private function judgeParts(array $parts, MethodShape $method, ?TaintState $state, int $depth, string $context): TaintJudgement
    {
        $judgements = [];

        foreach ($parts as $part) {
            if ($part instanceof Node\Expr) {
                $judgements[] = $this->judge($part, $method, $state, $depth + 1);

                continue;
            }

            if ($part instanceof Node\InterpolatedStringPart) {
                $judgements[] = TaintJudgement::trusted('literal fragment');
            }
        }

        return TaintJudgement::combine($judgements, $context);
    }

    /**
     * Judge a concatenation or an interpolated string POSITIONALLY.
     *
     * Order matters in a URL and nowhere else does an analyser get it so wrong
     * so cheaply. `config('services.crm.base_url').'/v3/contacts/'.$id` is not
     * "an attacker-controlled destination": the scheme, host and port are
     * written by server configuration, the literal `/` closes the authority,
     * and `$id` can only ever land in the path. The taint is real, its reach is
     * not the whole URL, and the judgement says exactly that.
     */
    private function judgeConcatenation(Node\Expr $expr, MethodShape $method, ?TaintState $state, int $depth, string $context): TaintJudgement
    {
        $segments = $this->flatten($expr);
        $judgements = [];

        foreach ($segments as $segment) {
            $judgements[] = $segment instanceof Node\Expr
                ? $this->judge($segment, $method, $state, $depth + 1)
                : TaintJudgement::trusted('literal fragment');
        }

        $combined = TaintJudgement::combine($judgements, $context);

        if (! $combined->carriesTaint()) {
            return $combined;
        }

        $first = null;

        foreach ($judgements as $index => $judgement) {
            if ($judgement->carriesTaint()) {
                $first = $index;

                break;
            }
        }

        // A taint in the leading segment decides the scheme and host itself,
        // so there is nothing to confine.
        if ($first === null || $first === 0) {
            return $combined;
        }

        $origin = $this->fixedOriginBefore(
            array_slice($segments, 0, $first),
            array_slice($judgements, 0, $first),
            $method,
        );

        if ($origin === null) {
            return $combined;
        }

        return $combined->confinedToPath(sprintf(
            '%s, but it is appended after %s, which fixes the scheme, host and port, and after a literal "%s" — so it can only shape the path or query of that fixed destination, not the host it is sent to',
            $judgements[$first]->evidence,
            $origin['label'],
            $origin['separator'],
        ));
    }

    /**
     * Whether the segments BEFORE the first tainted one pin the destination.
     *
     * Three things must hold, all of them read off the analysed file:
     *   1. Every preceding segment is provably server controlled. One unknown
     *      segment and the origin is not proven, so nothing is narrowed.
     *   2. The leading segment establishes an authority — a literal with a
     *      `scheme://` prefix, or a trusted value whose own identifier says it
     *      is a URL base (`config('services.crm.base_url')`).
     *   3. Server-written literal text closes that authority with `/`, `?` or
     *      `#` before the tainted segment begins.
     *
     * @param  array<int, Node>  $segments
     * @param  array<int, TaintJudgement>  $judgements
     * @return array{label: string, separator: string}|null
     */
    private function fixedOriginBefore(array $segments, array $judgements, MethodShape $method): ?array
    {
        foreach ($judgements as $judgement) {
            if (! $judgement->isTrusted()) {
                return null;
            }
        }

        $leading = $segments[0] ?? null;

        if (! $leading instanceof Node\Expr && ! $leading instanceof Node\InterpolatedStringPart) {
            return null;
        }

        $label = null;
        $tail = '';

        $leadingText = $this->literalText($leading);

        if ($leadingText !== null && preg_match(self::SCHEME_PATTERN, $leadingText) === 1) {
            $label = $this->quotedLiteral($leadingText);
            $tail = (string) preg_replace(self::SCHEME_PATTERN, '', $leadingText);
        } elseif ($leading instanceof Node\Expr && $this->establishesAuthority($leading, $method)) {
            $label = $this->sourceText($leading);

            if ($label === null) {
                return null;
            }
        }

        if ($label === null) {
            return null;
        }

        $separator = $this->authorityTerminatorIn($tail);

        if ($separator !== null) {
            return ['label' => $label, 'separator' => $separator];
        }

        foreach (array_slice($segments, 1) as $segment) {
            $text = $this->literalText($segment);

            if ($text === null) {
                continue;
            }

            $separator = $this->authorityTerminatorIn($text);

            if ($separator !== null) {
                return ['label' => $label, 'separator' => $separator];
            }
        }

        return null;
    }

    private function authorityTerminatorIn(string $text): ?string
    {
        foreach (self::AUTHORITY_TERMINATORS as $terminator) {
            if (str_contains($text, $terminator)) {
                return $terminator;
            }
        }

        return null;
    }

    /**
     * Whether a SERVER-CONTROLLED expression carries scheme and host.
     *
     * This gate is load-bearing in the suppressing direction, so it stays
     * narrow. `$scheme = config('app.scheme'); $scheme.'//'.$request->input('h')`
     * puts the client in charge of the HOST, and only the refusal to read
     * `$scheme` as a URL base keeps that a full taint.
     *
     * A single variable hop is followed, because
     * `$base = config('services.crm.base_url')` is the same fact written over
     * two lines.
     */
    private function establishesAuthority(Node\Expr $expr, MethodShape $method, int $depth = 0): bool
    {
        if ($expr instanceof Node\Scalar\String_ && preg_match(self::SCHEME_PATTERN, $expr->value) === 1) {
            return true;
        }

        if ($this->readsAsUrlBase($expr)) {
            return true;
        }

        if ($depth >= 3 || ! $expr instanceof Node\Expr\Variable || ! is_string($expr->name)) {
            return false;
        }

        $assignment = $this->receivers->assignmentsFor($method)->reaching($expr->name, $expr->getStartLine());

        return $assignment !== null && $this->establishesAuthority($assignment['expr'], $method, $depth + 1);
    }

    /**
     * Whether an expression names itself as a URL base.
     */
    private function readsAsUrlBase(Node\Expr $expr): bool
    {
        $rendered = $this->sourceText($expr);

        if ($rendered === null) {
            return false;
        }

        $normalised = strtolower((string) preg_replace('/[^a-z0-9]/i', '', $rendered));

        foreach (self::URL_BASE_WORDS as $word) {
            if (str_contains($normalised, $word)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The literal string a segment contributes, or null when it is computed.
     */
    private function literalText(Node $node): ?string
    {
        if ($node instanceof Node\Scalar\String_) {
            return $node->value;
        }

        if ($node instanceof Node\InterpolatedStringPart) {
            return $node->value;
        }

        return null;
    }

    private function quotedLiteral(string $text): string
    {
        return strlen($text) > self::MAX_RENDERED_LENGTH
            ? sprintf("'%s…'", substr($text, 0, self::MAX_RENDERED_LENGTH))
            : sprintf("'%s'", $text);
    }

    /**
     * Flatten a concatenation or interpolation into its segments, in source
     * order. `$a . "b{$c}" . $d` is five segments, not a tree.
     *
     * @return array<int, Node>
     */
    private function flatten(Node\Expr $expr): array
    {
        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return array_merge($this->flatten($expr->left), $this->flatten($expr->right));
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            $segments = [];

            foreach ($expr->parts as $part) {
                $segments = array_merge(
                    $segments,
                    $part instanceof Node\Expr ? $this->flatten($part) : [$part],
                );
            }

            return $segments;
        }

        return [$expr];
    }

    private function judgeVariable(Node\Expr\Variable $expr, MethodShape $method, ?TaintState $state, int $depth): TaintJudgement
    {
        if (! is_string($expr->name)) {
            return TaintJudgement::unknown('variable variable');
        }

        $name = $expr->name;

        if (in_array($name, self::SUPERGLOBALS, true)) {
            return TaintJudgement::tainted(sprintf('$%s is a superglobal of client-supplied data', $name), '$'.$name);
        }

        $recorded = $state?->at($name, $expr->getStartLine());

        if ($recorded !== null && ! $recorded->isUnknown()) {
            return $recorded;
        }

        $parameter = $method->parameter($name);

        if ($parameter !== null) {
            return $this->judgeParameter($parameter, $method);
        }

        $assignment = $this->receivers->assignmentsFor($method)->reaching($name, $expr->getStartLine());

        if ($assignment === null) {
            return TaintJudgement::unknown(sprintf('$%s has no parameter declaration and no local assignment', $name));
        }

        $judgement = $this->judge($assignment['expr'], $method, $state, $depth + 1);

        return $judgement->withEvidence(sprintf(
            '$%s is assigned on line %d from %s',
            $name,
            $assignment['line'],
            $judgement->evidence,
        ));
    }

    /**
     * A parameter's trust follows its TYPE.
     *
     * A route-model-bound `Room $room` was resolved by the framework from the
     * route key and is not a raw client value. A bare `int $id` on a public
     * controller action IS the raw route segment the client chose.
     */
    public function judgeParameter(ParameterShape $parameter, MethodShape $method): TaintJudgement
    {
        $class = $parameter->classType($method->file());

        if ($class !== null) {
            if ($this->isRequestClass($class)) {
                return TaintJudgement::trusted(sprintf(
                    '$%s is the %s object itself, not a value taken from it',
                    $parameter->name(),
                    TypeNames::shortName($class),
                ));
            }

            if ($this->isEloquentClass($class)) {
                return TaintJudgement::trusted(sprintf(
                    '$%s is a route-model-bound %s resolved by the framework',
                    $parameter->name(),
                    TypeNames::shortName($class),
                ));
            }

            return TaintJudgement::trusted(sprintf(
                '$%s is an injected %s',
                $parameter->name(),
                TypeNames::shortName($class),
            ));
        }

        // Only a scalar or untyped parameter can be a raw route segment. An
        // `array`/`iterable`/`mixed` hint is not routable, so its origin is
        // simply not stated by the signature.
        if (! $parameter->isScalar() && $parameter->isTyped()) {
            return TaintJudgement::unknown(sprintf(
                '$%s is declared %s, which a route segment cannot bind to',
                $parameter->name(),
                implode('|', $parameter->types()),
            ));
        }

        if ($this->isController($method->class()) && $method->isPublic()) {
            return TaintJudgement::tainted(
                sprintf(
                    '$%s is an untyped/scalar parameter of the routed action %s::%s(), so its value is a route segment chosen by the client',
                    $parameter->name(),
                    $method->class()->shortName(),
                    $method->name(),
                ),
                $parameter->variable(),
            );
        }

        return TaintJudgement::unknown(sprintf(
            '$%s is an untyped parameter of a non-routed method',
            $parameter->name(),
        ));
    }

    private function judgeProperty(Node\Expr\PropertyFetch|Node\Expr\NullsafePropertyFetch $expr, MethodShape $method, ?TaintState $state, int $depth): TaintJudgement
    {
        $name = $expr->name instanceof Node\Identifier ? $expr->name->toString() : null;

        if ($name !== null && $this->isRequestExpression($expr->var, $method)) {
            // The receiver is quoted AS WRITTEN. A method that takes
            // `notify(PurchaseRequest $purchaseRequest)` has no `$request` in
            // scope, and a proof that says "$request->callback_url" there names
            // a variable that does not exist.
            $label = $this->accessorLabel(
                $expr->var,
                $this->propertyOperator($expr),
                $name,
                sprintf('the request property %s', $name),
            );

            if (in_array($name, self::NON_INPUT_REQUEST_PROPERTIES, true)) {
                return TaintJudgement::unknown(sprintf('%s is framework state', $label));
            }

            return TaintJudgement::tainted(
                sprintf('%s reads request input through Request::__get()', $label),
                $label,
            );
        }

        $owner = $this->judge($expr->var, $method, $state, $depth + 1);

        if ($owner->isTrusted()) {
            return TaintJudgement::trusted(sprintf(
                'an attribute of a trusted object (%s)',
                $owner->evidence,
            ));
        }

        if ($owner->isTainted()) {
            return TaintJudgement::tainted(sprintf('an attribute of %s', $owner->evidence), $owner->source);
        }

        return $name === null
            ? TaintJudgement::unknown('the object behind a dynamic property fetch is not resolved')
            : TaintJudgement::unknown(sprintf('the object behind %s%s is not resolved', $this->propertyOperator($expr), $name));
    }

    private function judgeMethodCall(Node\Expr\MethodCall|Node\Expr\NullsafeMethodCall $expr, MethodShape $method): TaintJudgement
    {
        if (! $expr->name instanceof Node\Identifier) {
            return TaintJudgement::unknown('dynamic method name');
        }

        // Matching is case-insensitive; the text printed back to a human is the
        // spelling the file actually uses. `getcontent()` is not a method that
        // exists — `getContent()` is.
        $written = $expr->name->toString();
        $name = strtolower($written);
        $operator = $this->methodOperator($expr);

        if ($this->isRequestExpression($expr->var, $method)) {
            return $this->judgeRequestAccessor(
                $name,
                $this->accessorLabel($expr->var, $operator, $written, sprintf('the request accessor %s', $written)),
                $expr,
            );
        }

        if ($this->isAuthFactory($expr->var, $method)) {
            $label = $this->accessorLabel($expr->var, $operator, $written, sprintf('the auth factory accessor %s', $written));

            if (in_array($name, ['user', 'id', 'check', 'guest'], true)) {
                return TaintJudgement::trusted(sprintf('%s() is authentication state, not client input', $label));
            }

            return TaintJudgement::unknown(sprintf('%s() has no taint rule', $label));
        }

        return TaintJudgement::unknown(sprintf('the return value of %s%s() is not modelled', $operator, $written));
    }

    /**
     * @param  string  $name  Lower-cased accessor, for matching
     * @param  string  $label  The accessor AS WRITTEN in the analysed file,
     *                         receiver included, for the text a human reads
     */
    private function judgeRequestAccessor(string $name, string $label, Node\Expr $expr): TaintJudgement
    {
        if (in_array($name, self::TRUSTED_REQUEST_METHODS, true)) {
            return TaintJudgement::trusted(sprintf(
                '%s() returns framework/authentication state, not client input',
                $label,
            ));
        }

        if (in_array($name, self::VALIDATED_REQUEST_METHODS, true)) {
            return TaintJudgement::tainted(
                sprintf('%s() returns client input that passed validation', $label),
                sprintf('%s()', $label),
                true,
            );
        }

        if (in_array($name, self::TAINTED_REQUEST_METHODS, true)) {
            return TaintJudgement::tainted(
                sprintf('%s() reads client-supplied request data', $label),
                sprintf('%s()', $label),
            );
        }

        if ($name === 'route') {
            $hasArgument = $expr instanceof Node\Expr\MethodCall && $expr->args !== [];

            return $hasArgument
                ? TaintJudgement::tainted(sprintf('%s(...) returns a client-chosen route segment', $label), sprintf('%s()', $label))
                : TaintJudgement::unknown(sprintf('%s() returns the Route object', $label));
        }

        return TaintJudgement::unknown(sprintf('%s() has no taint rule', $label));
    }

    /**
     * `$receiver` rendered as the file writes it, joined to a resolved member
     * name — or, when the receiver cannot be rendered, a description that names
     * nothing that was not resolved.
     */
    private function accessorLabel(Node\Expr $receiver, string $operator, string $name, string $fallback): string
    {
        $rendered = $this->sourceText($receiver);

        return $rendered === null ? $fallback : $rendered.$operator.$name;
    }

    private function judgeStaticCall(Node\Expr\StaticCall $expr, MethodShape $method, ?TaintState $state, int $depth): TaintJudgement
    {
        if (! $expr->class instanceof Node\Name || ! $expr->name instanceof Node\Identifier) {
            return TaintJudgement::unknown('dynamic static call');
        }

        $class = $method->file()->resolveName($expr->class);
        $written = $expr->name->toString();
        $name = strtolower($written);

        // The class token as the file writes it — an alias stays the alias, so
        // the reader can find the line the judgement is talking about.
        $label = sprintf('%s::%s', TypeNames::shortName($expr->class->toString()), $written);

        if ($class === 'Illuminate\Support\Facades\Auth') {
            if (in_array($name, ['user', 'id', 'check', 'guest'], true)) {
                return TaintJudgement::trusted(sprintf('%s() is authentication state, not client input', $label));
            }

            return TaintJudgement::unknown(sprintf('%s() has no taint rule', $label));
        }

        if ($class === 'Illuminate\Support\Facades\Request' || TypeNames::shortName($class) === 'Input') {
            return $this->judgeRequestAccessor($name, $label, $expr);
        }

        if ($class === 'Illuminate\Support\Facades\Config') {
            return TaintJudgement::trusted(sprintf('%s() reads server-side configuration', $label));
        }

        if ($class === 'Illuminate\Support\Str' || $class === 'Illuminate\Support\Arr') {
            $arguments = [];

            foreach ($expr->args as $argument) {
                if ($argument instanceof Node\Arg) {
                    $arguments[] = $argument->value;
                }
            }

            return $this->judgeParts($arguments, $method, $state, $depth, sprintf('%s() preserves its input', $label));
        }

        return TaintJudgement::unknown(sprintf('%s() has no taint rule', $label));
    }

    private function judgeFuncCall(Node\Expr\FuncCall $expr, MethodShape $method, ?TaintState $state, int $depth): TaintJudgement
    {
        if (! $expr->name instanceof Node\Name) {
            return TaintJudgement::unknown('dynamic function name');
        }

        $written = TypeNames::shortName($expr->name->toString());
        $name = strtolower($written);

        if ($name === 'request') {
            return $expr->args === []
                ? TaintJudgement::trusted(sprintf('%s() returns the Request object itself, not a value taken from it', $written))
                : TaintJudgement::tainted(sprintf('%s(...) reads client-supplied request data', $written), $written.'()');
        }

        if (in_array($name, self::TAINTED_FUNCTIONS, true)) {
            return TaintJudgement::tainted(sprintf('%s() returns previously submitted client input', $written), $written.'()');
        }

        if (in_array($name, self::TRUSTED_FUNCTIONS, true)) {
            return TaintJudgement::trusted(sprintf('%s() returns server-side state, not client input', $written));
        }

        if (in_array($name, self::TAINT_PRESERVING_FUNCTIONS, true)) {
            $arguments = [];

            foreach ($expr->args as $argument) {
                if ($argument instanceof Node\Arg) {
                    $arguments[] = $argument->value;
                }
            }

            return $this->judgeParts($arguments, $method, $state, $depth, sprintf('%s() preserves the trust of its arguments', $written));
        }

        return TaintJudgement::unknown(sprintf('%s() has no taint rule', $written));
    }

    private function isAuthFactory(Node\Expr $expr, MethodShape $method): bool
    {
        if ($expr instanceof Node\Expr\FuncCall
            && $expr->name instanceof Node\Name
            && strtolower($expr->name->toString()) === 'auth') {
            return true;
        }

        $type = $this->receivers->resolve($expr, $method);

        return $type->is('Illuminate\Contracts\Auth\Factory')
            || $type->is('Illuminate\Support\Facades\Auth');
    }

    /**
     * Render an expression the way the analysed file writes it, or null when it
     * cannot be rendered from resolved nodes alone.
     *
     * THIS IS THE ONLY WAY AN IDENTIFIER MAY REACH FINDING TEXT. Every name it
     * returns was read off a node of the file being analysed — never a template
     * such as `$request`, never a synthesised `{Model}Policy`. When it cannot
     * render something it returns null, and the caller must then describe the
     * value instead of naming it. A missing name is fine; a wrong name is a
     * catastrophe.
     */
    public function sourceText(Node\Expr $expr, int $depth = 0): ?string
    {
        $rendered = $this->renderExpression($expr, $depth);

        if ($rendered === null || $rendered === '' || strlen($rendered) > self::MAX_RENDERED_LENGTH) {
            return null;
        }

        return $rendered;
    }

    private function renderExpression(Node\Expr $expr, int $depth): ?string
    {
        if ($depth > 4) {
            return null;
        }

        if ($expr instanceof Node\Expr\Variable) {
            return is_string($expr->name) ? '$'.$expr->name : null;
        }

        if ($expr instanceof Node\Scalar\String_) {
            return sprintf("'%s'", $expr->value);
        }

        if ($expr instanceof Node\Scalar\Int_) {
            return (string) $expr->value;
        }

        if ($expr instanceof Node\Expr\ConstFetch) {
            return $expr->name->toString();
        }

        if ($expr instanceof Node\Expr\ClassConstFetch) {
            $name = $expr->name instanceof Node\Identifier ? $expr->name->toString() : null;

            return $expr->class instanceof Node\Name && $name !== null
                ? sprintf('%s::%s', TypeNames::shortName($expr->class->toString()), $name)
                : null;
        }

        if ($expr instanceof Node\Expr\PropertyFetch || $expr instanceof Node\Expr\NullsafePropertyFetch) {
            $name = $expr->name instanceof Node\Identifier ? $expr->name->toString() : null;
            $owner = $this->renderExpression($expr->var, $depth + 1);

            return $name === null || $owner === null
                ? null
                : $owner.$this->propertyOperator($expr).$name;
        }

        if ($expr instanceof Node\Expr\StaticPropertyFetch) {
            $name = $expr->name instanceof Node\VarLikeIdentifier ? $expr->name->toString() : null;

            return $expr->class instanceof Node\Name && $name !== null
                ? sprintf('%s::$%s', TypeNames::shortName($expr->class->toString()), $name)
                : null;
        }

        if ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\NullsafeMethodCall) {
            $name = $expr->name instanceof Node\Identifier ? $expr->name->toString() : null;
            $owner = $this->renderExpression($expr->var, $depth + 1);

            return $name === null || $owner === null
                ? null
                : $owner.$this->methodOperator($expr).$name.$this->renderArguments($expr->args, $depth);
        }

        if ($expr instanceof Node\Expr\StaticCall) {
            $name = $expr->name instanceof Node\Identifier ? $expr->name->toString() : null;

            return $expr->class instanceof Node\Name && $name !== null
                ? TypeNames::shortName($expr->class->toString()).'::'.$name.$this->renderArguments($expr->args, $depth)
                : null;
        }

        if ($expr instanceof Node\Expr\FuncCall) {
            return $expr->name instanceof Node\Name
                ? $expr->name->toString().$this->renderArguments($expr->args, $depth)
                : null;
        }

        if ($expr instanceof Node\Expr\ArrayDimFetch) {
            $owner = $this->renderExpression($expr->var, $depth + 1);
            $key = $expr->dim === null ? null : $this->renderExpression($expr->dim, $depth + 1);

            return $owner === null || $key === null ? null : sprintf('%s[%s]', $owner, $key);
        }

        return null;
    }

    /**
     * Arguments are quoted only when every one of them is a scalar literal that
     * is already written in the file; anything computed collapses to `...`.
     *
     * @param  array<int, Node\Arg|Node\VariadicPlaceholder>  $args
     */
    private function renderArguments(array $args, int $depth): string
    {
        if ($args === []) {
            return '()';
        }

        $rendered = [];

        foreach ($args as $argument) {
            if (! $argument instanceof Node\Arg || $argument->unpack) {
                return '(...)';
            }

            $value = $argument->value;

            if (! $value instanceof Node\Scalar\String_ && ! $value instanceof Node\Scalar\Int_) {
                return '(...)';
            }

            $part = $this->renderExpression($value, $depth + 1);

            if ($part === null) {
                return '(...)';
            }

            $rendered[] = $argument->name !== null
                ? $argument->name->toString().': '.$part
                : $part;
        }

        return '('.implode(', ', $rendered).')';
    }

    private function propertyOperator(Node\Expr\PropertyFetch|Node\Expr\NullsafePropertyFetch $expr): string
    {
        return $expr instanceof Node\Expr\NullsafePropertyFetch ? '?->' : '->';
    }

    private function methodOperator(Node\Expr\MethodCall|Node\Expr\NullsafeMethodCall $expr): string
    {
        return $expr instanceof Node\Expr\NullsafeMethodCall ? '?->' : '->';
    }

    /**
     * @param  array<int, string>  $chain
     * @param  array<int, string>  $needles
     */
    private function firstIn(array $chain, array $needles): ?string
    {
        foreach ($chain as $name) {
            if (in_array(strtolower($name), $needles, true)) {
                return $name;
            }
        }

        return null;
    }
}
