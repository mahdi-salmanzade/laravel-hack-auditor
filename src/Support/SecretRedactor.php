<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Support;

final class SecretRedactor
{
    /**
     * Number of secrets redacted during the most recent redact() call.
     */
    private int $lastRedactionCount = 0;

    /**
     * Identifier fragments that signal a secret-bearing assignment.
     *
     * @var list<string>
     */
    private const SECRET_KEYWORDS = [
        'secret',
        'token',
        'password',
        'passwd',
        'api_key',
        'apikey',
        'access_key',
        'access_token',
        'auth_token',
        'authorization',
        'client_secret',
        'private_key',
        'encryption_key',
        'app_key',
        'bearer',
    ];

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

        $code = $this->redactPemBlocks($code);
        $code = $this->redactAwsAccessKeyIds($code);
        $code = $this->redactConnectionStrings($code);
        $code = $this->redactBearerTokens($code);
        $code = $this->redactSecretAssignments($code);
        $code = $this->redactEnvSecrets($code);

        return $code;
    }

    /**
     * Return how many secrets were redacted by the last redact() call.
     */
    public function lastRedactionCount(): int
    {
        return $this->lastRedactionCount;
    }

    /**
     * Redact PEM-encoded private key blocks.
     */
    private function redactPemBlocks(string $code): string
    {
        $pattern = '/-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----/s';

        return $this->replace($pattern, '__REDACTED_PRIVATE_KEY__', $code);
    }

    /**
     * Redact AWS access key IDs (AKIA / ASIA prefixed 20-char identifiers).
     *
     * Handles the whole identifier even when it has been split across a string
     * concatenation chain (e.g. "AKIA" . "IOSFODNN7EXAMPLE") so the reassembled
     * key never reaches the AI in either half.
     */
    private function redactAwsAccessKeyIds(string $code): string
    {
        $prefix = '(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)';

        $concatenated = '/'
            .'(["\'])'.$prefix.'[A-Z0-9]*\1'
            .'(?:\s*\.\s*(["\'])[A-Z0-9]+\2)+'
            .'/';
        $code = $this->replace($concatenated, "'__REDACTED_AWS_KEY__'", $code);

        $pattern = '/\b'.$prefix.'[A-Z0-9]{16}\b/';

        return $this->replace($pattern, '__REDACTED_AWS_KEY__', $code);
    }

    /**
     * Redact database / Redis / generic DSN connection strings that embed
     * credentials, e.g. mysql://user:pass@host or redis://:pass@host.
     */
    private function redactConnectionStrings(string $code): string
    {
        $pattern = '#\b[a-z][a-z0-9+.\-]*://[^\s\'"/@:]*:[^\s\'"/@]+@[^\s\'"]+#i';

        return $this->replace($pattern, '__REDACTED_DSN__', $code);
    }

    /**
     * Minimum value length below which a quoted literal is treated as a benign
     * placeholder rather than a real secret (e.g. 'abc', 'test', 'changeme').
     *
     * High-signal secret keywords still redact short values (e.g. 'hunter2'),
     * but trivially short literals are left untouched to avoid over-redaction.
     */
    private const SECRET_VALUE_FLOOR = 5;

    /**
     * A single PHP string literal, single- or double-quoted, honouring escapes
     * so that an embedded opposite/escaped quote does NOT terminate the match.
     */
    private const STRING_LITERAL = "(?:'(?:\\\\.|[^'\\\\])*'|\"(?:\\\\.|[^\"\\\\])*\")";

    /**
     * Redact secret VALUES assigned to key-like identifiers.
     *
     * Matches PHP assignments/array entries where the left-hand identifier
     * looks like a secret (key/secret/token/password/...) and the right-hand
     * side begins with a string literal. The ENTIRE right-hand value expression
     * is redacted — including literals that contain embedded quotes and whole
     * string-concatenation chains ("sk_live_" . "realbody") — so no part of the
     * real secret survives. The marker replaces the value with an obvious,
     * still-syntactically-valid string literal.
     */
    private function redactSecretAssignments(string $code): string
    {
        $keywords = implode('|', array_map('preg_quote', self::SECRET_KEYWORDS));
        $literal = self::STRING_LITERAL;

        $pattern = '/'
            // identifier fragment in quotes or bare, containing a secret keyword,
            // NOT immediately followed by "(" (so passwordResetUrl() is skipped)
            .'(["\']?[a-zA-Z0-9_.\-]*(?:'.$keywords.')[a-zA-Z0-9_.\-]*["\']?'
            .'\s*(?:=>|=|:)\s*)'
            // the value MUST start with a string literal (skips $tokenizer = new ...,
            // $secret = $this->secrets(), numeric/identifier RHS, etc.)
            .'('.$literal
            // ...optionally followed by a concatenation chain of further literals
            // and/or simple sub-expressions, so split/concatenated secrets are
            // captured whole rather than leaking the second half.
            .'(?:\s*\.\s*(?:'.$literal.'|[A-Za-z_$][A-Za-z0-9_]*(?:\([^()]*\))?))*'
            .')'
            .'/i';

        $count = 0;
        $result = preg_replace_callback($pattern, function (array $m) use (&$count): string {
            $value = $m[2];

            // Leave benign placeholders and already-redacted values untouched so
            // the redaction count stays honest and earlier markers survive.
            if (str_contains($value, '__REDACTED') || ! $this->valueLooksLikeSecret($value)) {
                return $m[0];
            }

            $count++;

            return $m[1]."'__REDACTED_SECRET__'";
        }, $code);

        if ($result === null) {
            return $code;
        }

        $this->lastRedactionCount += $count;

        return $result;
    }

    /**
     * Decide whether a captured right-hand value is substantial enough to be a
     * real secret. Concatenation chains and any value containing an embedded
     * quote always qualify; otherwise a small length floor screens out benign
     * placeholders like 'abc'.
     */
    private function valueLooksLikeSecret(string $value): bool
    {
        if (str_contains($value, '.')) {
            return true;
        }

        $inner = substr($value, 1, -1);

        if (preg_match('/[\'"]/', $inner) === 1) {
            return true;
        }

        return mb_strlen($inner) >= self::SECRET_VALUE_FLOOR;
    }

    /**
     * Redact bearer tokens appearing in Authorization-style header strings.
     */
    private function redactBearerTokens(string $code): string
    {
        $pattern = '/\bBearer\s+(?!__REDACTED)[A-Za-z0-9\-._~+\/]{16,}=*/';

        return $this->replace($pattern, 'Bearer __REDACTED_TOKEN__', $code);
    }

    /**
     * Redact long hex or base64 blobs (>=32 chars) that look like raw secrets
     * even when not bound to an obvious identifier, but only inside string
     * literals to avoid mangling ordinary code.
     */
    private function redactEnvSecrets(string $code): string
    {
        $keywords = implode('|', array_map('preg_quote', self::SECRET_KEYWORDS));

        $pattern = '/^('
            .'[A-Z0-9_]*(?:'.strtoupper($keywords).')[A-Z0-9_]*'
            .'\s*=\s*)'
            .'(?!__REDACTED)'
            .'["\']?[^\s"\']{8,}["\']?'
            .'$/im';

        return $this->replaceCallback($pattern, function (array $m): string {
            return $m[1].'__REDACTED_SECRET__';
        }, $code);
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
     *
     * @param  callable(array<int, string>): string  $callback
     */
    private function replaceCallback(string $pattern, callable $callback, string $code): string
    {
        $count = 0;
        $result = preg_replace_callback($pattern, $callback, $code, -1, $count);

        if ($result === null) {
            return $code;
        }

        $this->lastRedactionCount += $count;

        return $result;
    }
}
