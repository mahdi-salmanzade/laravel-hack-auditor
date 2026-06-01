<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\AccessControl;

use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * Flags a sensitive model attribute (password hash, remember token, API
 * secret, private key, SSN, card number, ...) being placed into OUTPUT —
 * a JSON response, a returned array, compact(), or view data.
 *
 * Laravel-specific reasoning: returning `$user->password` or
 * `$user->remember_token` inside response()->json([...]) leaks credential
 * material to any caller. The Eloquent `$hidden` array exists precisely to stop
 * this, so reading a sensitive attribute and serialising it is a
 * sensitive-data-exposure flaw (CWE-200, OWASP A02 Cryptographic Failures).
 *
 * Low-false-positive design: the sensitive `$var->{field}` access must appear
 * inside an OUTPUT context (response()->json, a returned array literal,
 * compact(), ->toArray() exposure, or view(...)->with([...])). This output
 * requirement is the key guard. Hashing/validating INPUT
 * (Hash::make($request->password), Hash::check(..., $user->password)),
 * assignment TO a model field ($user->password = ...), and the field name
 * merely appearing in a `$fillable`/`$hidden`/array-KEY position are NOT
 * flagged. At most one finding is reported per method (at the first exposed
 * sensitive attribute) to avoid multiplying a single leak into several.
 */
final class SensitiveDataExposureDetector implements AccessControlDetector
{
    private MethodScanner $methods;

    public function __construct(?MethodScanner $methods = null)
    {
        $this->methods = $methods ?? new MethodScanner;
    }

    /**
     * Exact sensitive attribute names.
     *
     * @var array<int, string>
     */
    private const SENSITIVE_NAMES = [
        'password',
        'password_hash',
        'remember_token',
        'api_secret',
        'api_key',
        'secret',
        'private_key',
        'ssn',
        'social_security',
        'credit_card',
        'card_number',
        'cvv',
    ];

    public function detect(array $files, AccessControlContext $context): array
    {
        $findings = [];

        foreach ($files as $file) {
            foreach ($this->methods->publicMethods($file->content) as $method) {
                $body = $method['body'];
                $exposure = $this->findSensitiveExposure($body);

                if ($exposure === null) {
                    continue;
                }

                $bodyStart = strpos($file->content, $body, $method['offset']);
                $absoluteOffset = ($bodyStart === false ? $method['offset'] : $bodyStart) + $exposure['offset'];
                $line = $file->lineForOffset($absoluteOffset);

                $findings[] = new Vulnerability(
                    type: VulnerabilityType::SensitiveDataExposure,
                    location: $file->path,
                    line: $line,
                    severity: SeverityLevel::High,
                    description: sprintf(
                        '%s::%s() places a sensitive attribute (%s) into output. Serialising credential material like this leaks it to any caller (Sensitive Data Exposure, CWE-200).',
                        $file->className() ?? 'Class',
                        $method['name'],
                        $exposure['attribute'],
                    ),
                    proof: sprintf(
                        "'%s' is read and emitted in a response/array/view payload; it should be protected by the model's \$hidden array, never serialised.",
                        trim($exposure['snippet']),
                    ),
                    fix: "Remove the sensitive attribute from the output and add it to the model's protected \$hidden array (e.g. protected \$hidden = ['password', 'remember_token']); expose only non-secret fields, or use an API Resource that whitelists safe attributes.",
                );
            }
        }

        return $findings;
    }

    /**
     * Locate the first sensitive exposure that occurs inside an output context,
     * returning the offending snippet, attribute name, and its byte offset
     * within the body.
     *
     * @return array{snippet: string, attribute: string, offset: int}|null
     */
    private function findSensitiveExposure(string $body): ?array
    {
        $outputRegions = $this->outputRegions($body);

        if ($outputRegions === []) {
            return null;
        }

        if (preg_match_all('/\$\w+\s*->\s*(\w+)/', $body, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
            foreach ($matches as $match) {
                $attribute = $match[1][0];
                $offset = (int) $match[0][1];

                if (! $this->isSensitiveAttribute($attribute)) {
                    continue;
                }

                if ($this->isAssignmentTarget($body, $offset)) {
                    continue;
                }

                if (! $this->withinAnyRegion($offset, $outputRegions)) {
                    continue;
                }

                return [
                    'snippet' => trim($match[0][0]),
                    'attribute' => $attribute,
                    'offset' => $offset,
                ];
            }
        }

        return $this->findCompactExposure($body);
    }

    /**
     * Catch the `compact('password', ...)` exposure shape: a compact() argument
     * naming a local variable that was assigned from a sensitive `$x->{field}`
     * read earlier in the method. This is the one output context where the
     * sensitive attribute is referenced by variable name rather than inline.
     *
     * @return array{snippet: string, attribute: string, offset: int}|null
     */
    private function findCompactExposure(string $body): ?array
    {
        if (! preg_match('/\bcompact\s*\(([^)]*)\)/', $body, $compact, PREG_OFFSET_CAPTURE)) {
            return null;
        }

        if (! preg_match_all('/[\'"](\w+)[\'"]/', $compact[1][0], $names)) {
            return null;
        }

        foreach ($names[1] as $name) {
            if (! preg_match('/\$'.preg_quote($name, '/').'\s*=\s*\$\w+\s*->\s*(\w+)/', $body, $assign, PREG_OFFSET_CAPTURE)) {
                continue;
            }

            if (! $this->isSensitiveAttribute($assign[1][0])) {
                continue;
            }

            return [
                'snippet' => trim($assign[0][0]),
                'attribute' => $assign[1][0],
                'offset' => (int) $compact[0][1],
            ];
        }

        return null;
    }

    /**
     * Whether an attribute name is sensitive: an exact match, or a name ending
     * in _secret/_token/_key, or a *_hash that is password/secret related.
     */
    private function isSensitiveAttribute(string $attribute): bool
    {
        $name = strtolower($attribute);

        if (in_array($name, self::SENSITIVE_NAMES, true)) {
            return true;
        }

        if (str_ends_with($name, '_secret') || str_ends_with($name, '_token') || str_ends_with($name, '_key')) {
            return true;
        }

        if (str_ends_with($name, '_hash')) {
            return str_contains($name, 'password') || str_contains($name, 'secret');
        }

        return false;
    }

    /**
     * Whether the `$var->field` at the given offset is the TARGET of an
     * assignment (`$user->password = ...`) rather than a read. Assignment to a
     * sensitive field is setting, not exposing, so it must not be flagged.
     */
    private function isAssignmentTarget(string $body, int $offset): bool
    {
        $rest = substr($body, $offset);

        return (bool) preg_match('/^\$\w+\s*->\s*\w+\s*=(?!=)/', $rest);
    }

    /**
     * Compute the byte ranges of the method body that constitute output
     * contexts: response()->json([...]), a returned array literal, compact(),
     * ->toArray() exposure, or view(...)->with([...]). A sensitive read only
     * counts when it sits inside one of these ranges.
     *
     * @return array<int, array{start: int, end: int}>
     */
    private function outputRegions(string $body): array
    {
        $regions = [];

        $anchors = [
            // response()->json([ ... ]) and return response()->json([ ... ])
            '/response\s*\(\s*\)\s*->\s*json\s*\(/',
            // compact('password', ...)
            '/\bcompact\s*\(/',
            // ->with([ ... ]) view data
            '/->\s*with\s*\(/',
            // ->toArray()  (the exposure is the array immediately handed onward)
            '/->\s*toArray\s*\(/',
            // return [ ... ];  — a returned array literal
            '/\breturn\s*\[/',
            // return response( ... );
            '/\breturn\s+response\s*\(/',
            // view('x', [ ... ])  data array
            '/\bview\s*\(/',
        ];

        foreach ($anchors as $pattern) {
            if (! preg_match_all($pattern, $body, $matches, PREG_OFFSET_CAPTURE)) {
                continue;
            }

            foreach ($matches[0] as $match) {
                $start = (int) $match[1];
                $regions[] = [
                    'start' => $start,
                    'end' => $this->regionEnd($body, $start + strlen($match[0])),
                ];
            }
        }

        return $regions;
    }

    /**
     * Find the end of an output region by balancing brackets/parens from the
     * position just after the anchor's opening delimiter. Falls back to the end
     * of statement (`;`) when balancing does not resolve.
     */
    private function regionEnd(string $body, int $afterAnchor): int
    {
        $length = strlen($body);
        $depth = 1;

        $openChar = $body[$afterAnchor - 1] ?? '(';
        $closeChar = $openChar === '[' ? ']' : ')';

        $pos = $afterAnchor;

        while ($pos < $length && $depth > 0) {
            $char = $body[$pos];

            if ($char === $openChar) {
                $depth++;
            } elseif ($char === $closeChar) {
                $depth--;
            }

            $pos++;
        }

        if ($depth === 0) {
            return $pos;
        }

        $semicolon = strpos($body, ';', $afterAnchor);

        return $semicolon === false ? $length : $semicolon;
    }

    /**
     * Whether an offset falls inside any of the given output regions.
     *
     * @param  array<int, array{start: int, end: int}>  $regions
     */
    private function withinAnyRegion(int $offset, array $regions): bool
    {
        foreach ($regions as $region) {
            if ($offset >= $region['start'] && $offset <= $region['end']) {
                return true;
            }
        }

        return false;
    }
}
