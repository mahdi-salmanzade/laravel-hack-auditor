<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Support;

/**
 * Strips secret VALUES out of source before it can reach a cloud AI provider.
 *
 * Two layers, deliberately kept apart:
 *
 *  1. Value-shape detectors (PEM armour, provider key prefixes, JWTs, DSNs,
 *     Bearer headers). Each pattern's character class excludes quotes and
 *     whitespace, so a match can never span from one string literal into the
 *     next — it cannot swallow code, and it is safe to run over the whole text,
 *     which also catches keys pasted into comments and heredocs.
 *  2. Name-bound redaction ("this literal is assigned to something called
 *     password"). This used to be a regex that paired quotes, and it paired a
 *     closing quote with the NEXT opening quote: `"... password = '" . $in . "'"`
 *     lost its injected variable (hiding a SQL injection from the model) and
 *     `['password' => 'required|min:8']` lost its validation rules. It now walks
 *     token_get_all() output so literal boundaries come from the PHP lexer.
 *
 * Every replacement preserves the number of newlines it replaces, so line N of
 * the redacted text is still line N of the file on disk — findings, verification
 * and the deterministic detectors all report real line numbers.
 */
final class SecretRedactor
{
    /**
     * Number of secrets redacted during the most recent redact() call.
     */
    private int $lastRedactionCount = 0;

    /**
     * Identifier fragments that signal a secret-bearing assignment. Compared
     * against the key with `_`, `-` and `.` removed, so `apiKey`, `api_key`
     * and `API-KEY` all match `apikey`.
     *
     * @var list<string>
     */
    private const SECRET_KEYWORDS = [
        'secret',
        'token',
        'password',
        'passwd',
        'passphrase',
        'apikey',
        'accesskey',
        'accesstoken',
        'authtoken',
        'authorization',
        'clientsecret',
        'privatekey',
        'encryptionkey',
        'signingkey',
        'appkey',
        'bearer',
        'credential',
    ];

    /**
     * Trailing key segments that name metadata ABOUT a secret rather than the
     * secret itself (`token_ttl`, `password_field`, `reset_token_route`).
     *
     * @var list<string>
     */
    private const NON_SECRET_KEY_SUFFIXES = [
        'url', 'uri', 'route', 'path', 'field', 'column', 'name', 'label', 'length',
        'ttl', 'lifetime', 'expiry', 'expires', 'expire', 'timeout', 'header', 'type',
        'driver', 'table', 'rule', 'rules', 'prefix', 'param', 'placeholder', 'message',
        'confirmation', 'broker', 'provider', 'guard', 'mode', 'algo', 'algorithm',
    ];

    /**
     * Env-var name segments that mark a .env value as secret. Any non-empty,
     * non-placeholder value is redacted — `DB_PASSWORD=hunter2` is a real
     * password no matter how short it is.
     *
     * @var list<string>
     */
    private const ENV_SECRET_SEGMENTS = [
        'SECRET', 'TOKEN', 'PASSWORD', 'PASSWD', 'PASS', 'PWD', 'KEY', 'APIKEY',
        'CREDENTIAL', 'CREDENTIALS', 'PRIVATE', 'PASSPHRASE', 'SALT',
    ];

    /**
     * Laravel validation rule names and Eloquent cast types. A value made only
     * of these is configuration, not a credential — `'password' => 'hashed'`
     * and `'password' => 'required|confirmed'` must reach the model intact
     * because the access-control detectors and the AI both reason about them.
     *
     * @var list<string>
     */
    private const RULE_AND_CAST_WORDS = [
        'required', 'nullable', 'sometimes', 'string', 'confirmed', 'current_password',
        'min', 'max', 'size', 'between', 'regex', 'not_regex', 'same', 'different',
        'alpha', 'alpha_num', 'alpha_dash', 'ascii', 'numeric', 'integer', 'boolean',
        'email', 'url', 'uuid', 'ulid', 'present', 'filled', 'prohibited', 'bail',
        'exists', 'unique', 'in', 'not_in', 'lowercase', 'uppercase', 'letters',
        'mixed', 'numbers', 'symbols', 'uncompromised', 'password', 'hashed',
        'encrypted', 'array', 'json', 'object', 'collection', 'date', 'datetime',
        'immutable_date', 'immutable_datetime', 'timestamp', 'decimal', 'float',
        'double', 'real', 'int', 'bool', 'hash', 'digits', 'digits_between',
        'starts_with', 'ends_with', 'doesnt_start_with', 'doesnt_end_with',
        'required_with', 'required_without', 'required_if', 'required_unless',
        'exclude', 'dimensions', 'file', 'image', 'mimes', 'mimetypes', 'accepted',
    ];

    /**
     * Functions/methods whose SECOND argument is a value keyed by the FIRST:
     * env('KEY', 'default'), define('KEY', 'value'), config()->set('k', 'v').
     *
     * @var list<string>
     */
    private const KEYED_CALLS = ['env', 'define', 'set', 'putenv'];

    /**
     * Minimum value length below which a quoted literal is treated as a benign
     * placeholder rather than a real secret (e.g. 'abc', 'test').
     */
    private const SECRET_VALUE_FLOOR = 5;

    /**
     * Replace secret values in the given code with detection-friendly markers.
     *
     * The goal is to strip the literal secret VALUE while leaving behind a
     * recognizable placeholder so downstream AI analysis can still flag that a
     * hardcoded secret exists, without ever transmitting the real value.
     */
    public function redact(string $code): string
    {
        $this->lastRedactionCount = 0;

        $code = $this->redactValueShapes($code);

        if ($this->looksLikeDotenv($code)) {
            return $this->redactDotenvLines($code);
        }

        return $this->redactPhpLiterals($code);
    }

    /**
     * Return how many secrets were redacted by the last redact() call.
     */
    public function lastRedactionCount(): int
    {
        return $this->lastRedactionCount;
    }

    /**
     * Redact every secret whose VALUE is recognisable on its own, wherever it
     * sits. PEM blocks keep their line count so nothing below them shifts.
     */
    private function redactValueShapes(string $code): string
    {
        $code = $this->replaceCallback(
            '/-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/s',
            fn (array $m): string => '__REDACTED_PRIVATE_KEY__'.str_repeat("\n", substr_count($m[0], "\n")),
            $code,
        );

        $shapes = [
            '#\b[a-z][a-z0-9+.\-]*://[^\s\'"/@:]*:[^\s\'"/@]+@[^\s\'"]+#i' => '__REDACTED_DSN__',
            '#https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+#' => '__REDACTED_SLACK_WEBHOOK__',
            '/\bBearer\s+(?!__REDACTED)[A-Za-z0-9\-._~+\/]{16,}=*/' => 'Bearer __REDACTED_TOKEN__',
            '/\beyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{10,}/' => '__REDACTED_JWT__',
            '/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}/' => '__REDACTED_STRIPE_KEY__',
            '/\bwhsec_[A-Za-z0-9]{16,}/' => '__REDACTED_STRIPE_KEY__',
            '/\bgh[pousr]_[A-Za-z0-9]{36,}/' => '__REDACTED_GITHUB_TOKEN__',
            '/\bgithub_pat_[A-Za-z0-9_]{22,}/' => '__REDACTED_GITHUB_TOKEN__',
            '/\bxox[abprs]-[A-Za-z0-9\-]{10,}/' => '__REDACTED_SLACK_TOKEN__',
            '/\bAIza[0-9A-Za-z_\-]{35,}/' => '__REDACTED_GOOGLE_API_KEY__',
            '/\bsk-ant-[A-Za-z0-9_\-]{20,}/' => '__REDACTED_AI_API_KEY__',
            '/\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}/' => '__REDACTED_AI_API_KEY__',
            '/\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b/' => '__REDACTED_AWS_KEY__',
        ];

        foreach ($shapes as $pattern => $marker) {
            $code = $this->replace($pattern, $marker, $code);
        }

        return $code;
    }

    /**
     * Whether the text is a dotenv file rather than PHP. PHP (with or without
     * an open tag, since callers also pass fragments) goes to the token pass.
     */
    private function looksLikeDotenv(string $code): bool
    {
        if (str_contains($code, '<?php') || str_contains($code, '<?=')) {
            return false;
        }

        $assignments = 0;

        foreach (explode("\n", $code) as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            if (preg_match('/^(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=/', $line) !== 1) {
                return false;
            }

            $assignments++;
        }

        return $assignments > 0;
    }

    /**
     * Line-based .env redaction: `[export ]NAME=value` where NAME carries a
     * secret segment and value is anything but an obvious placeholder.
     */
    private function redactDotenvLines(string $code): string
    {
        return $this->replaceCallback(
            '/^(\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=[ \t]*)([^\r\n]*)$/m',
            function (array $m): string {
                if (! $this->isSecretEnvName($m[2]) || $this->isEnvPlaceholder($m[3])) {
                    return $m[0];
                }

                return $m[1].'__REDACTED_SECRET__';
            },
            $code,
            countOnlyChanged: true,
        );
    }

    /**
     * Whether an env var name names a secret (DB_PASSWORD, STRIPE_SECRET, APP_KEY).
     */
    private function isSecretEnvName(string $name): bool
    {
        $segments = explode('_', strtoupper($name));

        return array_intersect($segments, self::ENV_SECRET_SEGMENTS) !== []
            || $this->isSecretKeyName($name);
    }

    /**
     * Env values that carry no secret: empty, null, a quoted empty string, a
     * `${VAR}` reference, or an existing marker.
     */
    private function isEnvPlaceholder(string $value): bool
    {
        $value = trim($value);

        if ($value === '' || str_contains($value, '__REDACTED')) {
            return true;
        }

        $unquoted = trim($value, '"\'');

        if ($unquoted === '' || in_array(strtolower($unquoted), ['null', '(null)', 'none', '~'], true)) {
            return true;
        }

        return preg_match('/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/', $unquoted) === 1;
    }

    /**
     * Token-based redaction of string literals bound to a secret-looking name.
     *
     * Fragments without an open tag (tests, `hack:scan --code`) are lexed with
     * a synthetic `<?php ` prefix that is dropped again on output; the prefix
     * has no newline, so line numbers are unaffected.
     */
    private function redactPhpLiterals(string $code): string
    {
        $hasOpenTag = str_contains($code, '<?php') || str_contains($code, '<?=');
        $source = $hasOpenTag ? $code : '<?php '.$code;

        $tokens = $this->normalisedTokens($source);
        $count = count($tokens);

        /** @var array<int, array{end: int, text: string}> $replacements start index => replacement */
        $replacements = [];

        for ($i = 0; $i < $count; $i++) {
            $chain = $this->literalChainAt($tokens, $i);

            if ($chain === null) {
                continue;
            }

            $replacement = $this->replacementForChain($tokens, $i, $chain);

            if ($replacement !== null) {
                $replacements[$i] = ['end' => $chain['end'], 'text' => $replacement];
                $this->lastRedactionCount++;
            }

            $i = $chain['end'];
        }

        if ($replacements === []) {
            return $code;
        }

        $output = '';

        for ($i = $hasOpenTag ? 0 : 1; $i < $count; $i++) {
            if (isset($replacements[$i])) {
                $spanText = '';

                for ($j = $i; $j <= $replacements[$i]['end']; $j++) {
                    $spanText .= $tokens[$j][1];
                }

                $output .= $replacements[$i]['text'].str_repeat("\n", substr_count($spanText, "\n"));
                $i = $replacements[$i]['end'];

                continue;
            }

            $output .= $tokens[$i][1];
        }

        return $output;
    }

    /**
     * Decide what (if anything) replaces a literal chain.
     *
     * @param  list<array{0: int, 1: string}>  $tokens
     * @param  array{end: int, values: list<string>}  $chain
     */
    private function replacementForChain(array $tokens, int $start, array $chain): ?string
    {
        $joined = implode('', $chain['values']);

        if (str_contains($joined, '__REDACTED')) {
            return null;
        }

        // A value-shape secret split across a concatenation chain ("AKIA" . "IOSF...")
        // is invisible to the text-wide pass; re-check the reassembled value.
        if (count($chain['values']) > 1) {
            $probe = new self;
            $reassembled = $probe->redactValueShapes($joined);

            if ($reassembled !== $joined && preg_match('/__REDACTED_[A-Z_]+__/', $reassembled, $marker) === 1) {
                return "'".$marker[0]."'";
            }
        }

        $key = $this->keyForLiteral($tokens, $start);

        if ($key === null || ! $this->isSecretKeyName($key)) {
            return null;
        }

        if (! $this->valueLooksLikeSecret($chain['values'], $key)) {
            return null;
        }

        return "'__REDACTED_SECRET__'";
    }

    /**
     * Find the name a literal is bound to: an array key, an assigned variable
     * or property, a constant, a named argument, a `$cfg['key'] =` target, or
     * the first argument of env()/define()/->set(). Returns null when the
     * literal is not bound to any name (a plain call argument, a SQL string…).
     *
     * @param  list<array{0: int, 1: string}>  $tokens
     */
    private function keyForLiteral(array $tokens, int $start): ?string
    {
        $prev = $this->previousSignificant($tokens, $start);

        if ($prev === null) {
            return null;
        }

        [$id, $text] = $tokens[$prev];

        if ($id === T_DOUBLE_ARROW) {
            $keyIndex = $this->previousSignificant($tokens, $prev);

            return $keyIndex === null ? null : $this->nameOfToken($tokens[$keyIndex]);
        }

        if ($text === '=' || in_array($id, [T_COALESCE_EQUAL, T_CONCAT_EQUAL, T_IS_EQUAL, T_IS_IDENTICAL], true)) {
            $targetIndex = $this->previousSignificant($tokens, $prev);

            if ($targetIndex === null) {
                return null;
            }

            if ($tokens[$targetIndex][1] === ']') {
                $inner = $this->previousSignificant($tokens, $targetIndex);

                return $inner === null ? null : $this->nameOfToken($tokens[$inner]);
            }

            return $this->nameOfToken($tokens[$targetIndex]);
        }

        if ($text === ':') {
            $nameIndex = $this->previousSignificant($tokens, $prev);

            if ($nameIndex === null) {
                return null;
            }

            $before = $this->previousSignificant($tokens, $nameIndex);
            $beforeText = $before === null ? '' : $tokens[$before][1];

            // Named argument `password: '...'` or a JSON-style `{"token": "..."}`
            // pair; a ternary's `? 'a' : 'b'` never has `(`, `,` or `{` there.
            if (in_array($beforeText, ['(', ',', '{'], true)) {
                return $this->nameOfToken($tokens[$nameIndex]);
            }

            return null;
        }

        if ($text === ',') {
            return $this->keyedCallFirstArgument($tokens, $prev);
        }

        return null;
    }

    /**
     * For `env('KEY', <literal>)`-style calls return a name that makes the
     * default secret-looking: the first argument when it names a secret, else
     * the key the whole call is itself bound to (`'secret' => env('AWS', '…')`).
     *
     * @param  list<array{0: int, 1: string}>  $tokens
     */
    private function keyedCallFirstArgument(array $tokens, int $commaIndex): ?string
    {
        $firstArg = $this->previousSignificant($tokens, $commaIndex);

        if ($firstArg === null || $tokens[$firstArg][0] !== T_CONSTANT_ENCAPSED_STRING) {
            return null;
        }

        $paren = $this->previousSignificant($tokens, $firstArg);

        if ($paren === null || $tokens[$paren][1] !== '(') {
            return null;
        }

        $callee = $this->previousSignificant($tokens, $paren);

        if ($callee === null || ! in_array(strtolower($tokens[$callee][1]), self::KEYED_CALLS, true)) {
            return null;
        }

        $firstName = $this->nameOfToken($tokens[$firstArg]);

        if ($firstName !== null && $this->isSecretKeyName($firstName)) {
            return $firstName;
        }

        // env('AUTH_PASSWORD_BROKER', 'users') names metadata about a secret;
        // its default is not one, whatever the outer key is called.
        if ($firstName !== null && $this->mentionsSecretKeyword($firstName)) {
            return null;
        }

        $outer = $this->keyForLiteral($tokens, $callee);

        return $outer !== null && $this->isSecretKeyName($outer) ? $outer : null;
    }

    /**
     * The identifier a key/target token spells, or null when it is not a name.
     *
     * @param  array{0: int, 1: string}  $token
     */
    private function nameOfToken(array $token): ?string
    {
        [$id, $text] = $token;

        return match ($id) {
            T_CONSTANT_ENCAPSED_STRING => $this->literalValue($text),
            T_VARIABLE => ltrim($text, '$'),
            T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED => $text,
            default => null,
        };
    }

    /**
     * Whether a key name is secret-bearing, excluding metadata keys such as
     * `token_ttl` or `password_field` that merely mention a secret.
     */
    private function isSecretKeyName(string $key): bool
    {
        $segments = preg_split('/[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])/', $key) ?: [];
        $segments = array_values(array_filter(array_map('strtolower', $segments), fn (string $s): bool => $s !== ''));

        if ($segments === []) {
            return false;
        }

        $last = $segments[count($segments) - 1];

        if (count($segments) > 1 && in_array($last, self::NON_SECRET_KEY_SUFFIXES, true)) {
            return false;
        }

        return $this->mentionsSecretKeyword($key);
    }

    /**
     * Whether a name contains a secret keyword at all, metadata suffix or not.
     */
    private function mentionsSecretKeyword(string $name): bool
    {
        $normalised = strtolower((string) preg_replace('/[^A-Za-z0-9]/', '', $name));

        foreach (self::SECRET_KEYWORDS as $keyword) {
            if (str_contains($normalised, $keyword)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Decide whether a bound value is substantial enough to be a real secret
     * and not configuration that happens to sit under a secret-ish key.
     *
     * @param  list<string>  $values
     */
    private function valueLooksLikeSecret(array $values, string $key): bool
    {
        $joined = implode('', $values);

        if (count($values) > 1) {
            return mb_strlen($joined) >= self::SECRET_VALUE_FLOOR;
        }

        if (mb_strlen($joined) < self::SECRET_VALUE_FLOOR) {
            return false;
        }

        return ! $this->isBenignValue($joined, $key);
    }

    /**
     * Values that are configuration, references or prose, never credentials:
     * validation rules, cast types, ENV_VAR names or `${ENV_VAR}` references,
     * config/translation paths,
     * the key echoed back as its own value, and human-readable messages.
     */
    private function isBenignValue(string $value, string $key): bool
    {
        $normalise = fn (string $s): string => strtolower((string) preg_replace('/[^a-z0-9]/i', '', $s));

        if ($normalise($value) === $normalise($key)) {
            return true;
        }

        if ($this->isRuleOrCastList($value)) {
            return true;
        }

        if (preg_match('/^\$?\{?[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\}?$/', $value) === 1) {
            return true;
        }

        if (preg_match('/^[a-z0-9_\-]+(?:\.[a-z0-9_\-*]+)+$/', $value) === 1) {
            return true;
        }

        if (str_contains($value, ':attribute')) {
            return true;
        }

        return substr_count(trim($value), ' ') >= 2 && preg_match('/[.!?]$/', trim($value)) === 1;
    }

    /**
     * Whether a value is a `|`-separated list made only of validation rules or
     * cast types (`required|string|min:8`, `hashed`, `encrypted:array`).
     */
    private function isRuleOrCastList(string $value): bool
    {
        foreach (explode('|', $value) as $segment) {
            $name = strtolower(explode(':', trim($segment), 2)[0]);

            if (! in_array($name, self::RULE_AND_CAST_WORDS, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Recognise a maximal literal concatenation chain starting at $i:
     * literal ( '.' literal )*. A literal is a T_CONSTANT_ENCAPSED_STRING or an
     * interpolation-free heredoc/nowdoc. Returns the last token index and the
     * unquoted value of each literal.
     *
     * @param  list<array{0: int, 1: string}>  $tokens
     * @return array{end: int, values: list<string>}|null
     */
    private function literalChainAt(array $tokens, int $i): ?array
    {
        $literal = $this->literalAt($tokens, $i);

        if ($literal === null) {
            return null;
        }

        $values = [$literal['value']];
        $end = $literal['end'];

        while (true) {
            $dot = $this->nextSignificant($tokens, $end);

            if ($dot === null || $tokens[$dot][1] !== '.') {
                break;
            }

            $nextStart = $this->nextSignificant($tokens, $dot);
            $next = $nextStart === null ? null : $this->literalAt($tokens, $nextStart);

            if ($next === null) {
                break;
            }

            $values[] = $next['value'];
            $end = $next['end'];
        }

        return ['end' => $end, 'values' => $values];
    }

    /**
     * @param  list<array{0: int, 1: string}>  $tokens
     * @return array{end: int, value: string}|null
     */
    private function literalAt(array $tokens, int $i): ?array
    {
        if (! isset($tokens[$i])) {
            return null;
        }

        if ($tokens[$i][0] === T_CONSTANT_ENCAPSED_STRING) {
            return ['end' => $i, 'value' => $this->literalValue($tokens[$i][1])];
        }

        if ($tokens[$i][0] !== T_START_HEREDOC) {
            return null;
        }

        $value = '';
        $count = count($tokens);

        for ($j = $i + 1; $j < $count; $j++) {
            if ($tokens[$j][0] === T_END_HEREDOC) {
                return ['end' => $j, 'value' => $value];
            }

            if ($tokens[$j][0] !== T_ENCAPSED_AND_WHITESPACE) {
                return null;
            }

            $value .= $tokens[$j][1];
        }

        return null;
    }

    /**
     * The unquoted body of a single- or double-quoted PHP literal token.
     */
    private function literalValue(string $literal): string
    {
        if (strlen($literal) >= 2 && in_array($literal[0], ["'", '"'], true)) {
            return substr($literal, 1, -1);
        }

        // b'...' binary-prefixed literals.
        if (strlen($literal) >= 3 && in_array($literal[1], ["'", '"'], true)) {
            return substr($literal, 2, -1);
        }

        return $literal;
    }

    /**
     * @param  list<array{0: int, 1: string}>  $tokens
     */
    private function previousSignificant(array $tokens, int $i): ?int
    {
        for ($j = $i - 1; $j >= 0; $j--) {
            if (! in_array($tokens[$j][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                return $j;
            }
        }

        return null;
    }

    /**
     * @param  list<array{0: int, 1: string}>  $tokens
     */
    private function nextSignificant(array $tokens, int $i): ?int
    {
        $count = count($tokens);

        for ($j = $i + 1; $j < $count; $j++) {
            if (! in_array($tokens[$j][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                return $j;
            }
        }

        return null;
    }

    /**
     * token_get_all() with single-character tokens normalised to [0, char] so
     * every entry has the same shape.
     *
     * @return list<array{0: int, 1: string}>
     */
    private function normalisedTokens(string $source): array
    {
        $tokens = [];

        foreach (token_get_all($source) as $token) {
            $tokens[] = is_array($token) ? [$token[0], $token[1]] : [0, $token];
        }

        return $tokens;
    }

    /**
     * Run a regex replacement, tallying redactions into the counter.
     */
    private function replace(string $pattern, string $replacement, string $code): string
    {
        $count = 0;
        $result = preg_replace($pattern, $replacement, $code, -1, $count);

        if ($result === null) {
            return $code;
        }

        $this->lastRedactionCount += $count;

        return $result;
    }

    /**
     * Run a regex callback replacement, tallying redactions into the counter.
     * With $countOnlyChanged, matches the callback returns unchanged are not
     * counted (the dotenv pass matches every assignment line).
     *
     * @param  callable(array<int, string>): string  $callback
     */
    private function replaceCallback(string $pattern, callable $callback, string $code, bool $countOnlyChanged = false): string
    {
        $changed = 0;

        $result = preg_replace_callback($pattern, function (array $m) use ($callback, &$changed): string {
            $replacement = $callback($m);

            if ($replacement !== $m[0]) {
                $changed++;
            }

            return $replacement;
        }, $code, -1, $count);

        if ($result === null) {
            return $code;
        }

        $this->lastRedactionCount += $countOnlyChanged ? $changed : $count;

        return $result;
    }
}
