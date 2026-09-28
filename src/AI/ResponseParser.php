<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\AI;

use Illuminate\Support\Facades\Log;
use Mahdi\HackAuditor\Exceptions\InvalidAIResponseException;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;
use Throwable;

final class ResponseParser
{
    /**
     * Whether the most recent parse() had to recover findings from a response
     * that was cut off before its top-level object closed.
     */
    private bool $lastParseTruncated = false;

    /**
     * Why each finding dropped by the most recent parse() was dropped.
     *
     * @var array<int, string>
     */
    private array $lastSkippedFindings = [];

    /**
     * Parse an AI response string into a VulnerabilityReport.
     *
     * Attempts direct JSON decode first, then falls back to extracting JSON
     * from markdown code fences, then to scanning mixed prose for the report
     * object, and finally to salvaging the complete findings out of a
     * response that was truncated at max_tokens.
     *
     * Validation is PER FINDING. One chunk carries up to ten files, and the
     * model routinely gets a single entry slightly wrong — `"line": "42"`,
     * `"fix": null`, a type spelled its own way. Throwing on that entry used
     * to discard every other finding in the chunk, so one cosmetic slip hid
     * real SQL injections in nine unrelated files. Now values are coerced
     * where the intent is unambiguous, and an entry that cannot be salvaged
     * (no usable type or location) is skipped with a logged reason while the
     * rest of the chunk is kept. The response only fails as a whole when no
     * report object can be recovered from it at all.
     *
     * When `$files` (the chunk that was sent) is supplied, each finding's
     * location must name one of those files — it is rewritten to the chunk's
     * canonical path — and its line is clamped to that file's length. A
     * finding that points at a file the model was never shown cannot be
     * acted on and is dropped. Without `$files`, lines are only clamped to 1.
     *
     * @param  array<int, array{path: string, content: string, type?: string}>  $files  The chunk sent to the model, for location/line validation
     *
     * @throws InvalidAIResponseException When no report object can be recovered from the response.
     */
    public function parse(string $response, array $files = []): VulnerabilityReport
    {
        $this->lastParseTruncated = false;
        $this->lastSkippedFindings = [];

        $data = $this->decodeReport($response);

        /** @var array<int|string, mixed> $rawFindings Guaranteed an array by decodeReport(). */
        $rawFindings = $data['vulnerabilities'];

        $vulnerabilities = $this->parseVulnerabilities($rawFindings, $this->indexChunkFiles($files));
        $vulnerabilities = $this->filterSelfContradictions($vulnerabilities);
        $vulnerabilities = $this->filterBrokenTaintTraces($vulnerabilities);
        $overallScore = $this->parseOverallScore($data['overall_score'] ?? null, $vulnerabilities);
        $summary = $this->parseOptionalStringField($data, 'summary');
        $ctfIdea = $this->parseOptionalStringField($data, 'ctf_idea');

        if ($summary === '' && $this->lastParseWasTruncated()) {
            $summary = sprintf(
                'AI response was truncated; %d complete finding(s) were recovered and later files in this chunk may be unanalysed.',
                count($vulnerabilities),
            );
        }

        return new VulnerabilityReport(
            vulnerabilities: $vulnerabilities,
            overallScore: $overallScore,
            summary: $summary,
            ctfIdea: $ctfIdea,
        );
    }

    /**
     * Whether the most recent parse() recovered its findings from a truncated
     * response (typically the model hitting max_tokens mid-array).
     *
     * A truncated chunk is PARTIAL coverage: the findings returned are real,
     * but whatever the model would have written after the cut is missing, so
     * callers should surface the chunk as incompletely analysed rather than
     * treating its score as a clean bill of health.
     */
    public function lastParseWasTruncated(): bool
    {
        return $this->lastParseTruncated;
    }

    /**
     * Reasons for every finding the most recent parse() skipped as unusable.
     *
     * @return array<int, string>
     */
    public function lastSkippedFindings(): array
    {
        return $this->lastSkippedFindings;
    }

    /**
     * Parse an AI response for an exploit-verification request.
     *
     * Reuses the same 3-tier JSON extraction strategy as parse() (direct decode,
     * code-fence extraction, string-aware brace counting). Throws when the
     * response cannot be decoded or the required fields are missing — the
     * VerificationEngine catches this and treats it as a technical failure
     * (returning the original finding unchanged, not downgraded).
     *
     * Guard: when the model sets verified=true but the exploit string is
     * empty, whitespace-only, or a placeholder ("N/A", "TBD", "<...>"), the
     * result is normalized to verified=false — the model must provide
     * substance to keep the finding at its current severity.
     *
     * @return array{verified: bool, exploit: ?string, reasoning: string}
     *
     * @throws InvalidAIResponseException
     */
    public function parseVerification(string $raw): array
    {
        $data = $this->decodeJson($raw, 'verified');

        if (! array_key_exists('verified', $data)) {
            throw InvalidAIResponseException::missingField('verified');
        }

        $verified = $this->coerceBoolean($data['verified']);

        if ($verified === null) {
            throw InvalidAIResponseException::invalidFieldType('verified', 'boolean', get_debug_type($data['verified']));
        }
        $reasoning = $this->coerceString($data['reasoning'] ?? null);
        $exploitRaw = trim($this->coerceExploit($data['exploit'] ?? null));

        if ($verified && ! $this->isSubstantiveExploit($exploitRaw)) {
            return [
                'verified' => false,
                'exploit' => null,
                'reasoning' => $reasoning !== ''
                    ? $reasoning
                    : 'Model claimed verified=true but provided no substantive exploit payload.',
            ];
        }

        return [
            'verified' => $verified,
            'exploit' => $verified ? $exploitRaw : null,
            'reasoning' => $reasoning,
        ];
    }

    /**
     * Flatten a model-supplied exploit into the string the report shows.
     *
     * Models asked for "the exploit" sometimes answer with structure — a
     * {"request": ..., "payload": ...} object or a list of steps. Dropping
     * that as "no exploit" downgraded findings the model had in fact
     * exploited, so structured exploits are kept as pretty-printed JSON and
     * still go through the placeholder check.
     */
    private function coerceExploit(mixed $value): string
    {
        if (is_array($value)) {
            $encoded = json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

            return $value === [] || $encoded === false ? '' : $encoded;
        }

        return $this->coerceString($value);
    }

    /**
     * Determine if an exploit string contains substance or is a placeholder.
     *
     * Rejects empty strings, whitespace, common placeholder/refusal tokens
     * ("N/A", "TBD", "not vulnerable", etc.), a bare URL (a link is not an
     * exploit), and a lone HTML/XML tag template ("<payload>"). The model
     * must provide a payload a human could copy and run.
     */
    private function isSubstantiveExploit(string $exploit): bool
    {
        if ($exploit === '') {
            return false;
        }

        $normalized = strtolower($exploit);

        $placeholders = [
            'n/a',
            'none',
            'tbd',
            'todo',
            'placeholder',
            'not applicable',
            'no exploit',
            'no payload',
            'not vulnerable',
            'safe',
            'patched',
            'no vulnerability',
            'cannot exploit',
        ];

        foreach ($placeholders as $placeholder) {
            if ($normalized === $placeholder) {
                return false;
            }
        }

        if (preg_match('/^\s*https?:\/\/\S+\s*$/i', $exploit) === 1) {
            return false;
        }

        if (preg_match('/^<[^>]+>$/', $exploit) === 1) {
            return false;
        }

        return strlen($exploit) >= 5;
    }

    /**
     * Interpret a model-supplied boolean.
     *
     * `(bool) "false"` is TRUE in PHP, so a model that quoted its verdict
     * ("verified": "false") used to have every unexploitable finding stamped
     * as exploit-verified. Only unambiguous spellings are accepted; anything
     * else is null so the caller can treat it as a technical failure.
     */
    private function coerceBoolean(mixed $value): ?bool
    {
        if (is_bool($value)) {
            return $value;
        }

        if ($value === 0 || $value === 1) {
            return $value === 1;
        }

        if (is_string($value)) {
            return match (strtolower(trim($value))) {
                'true', 'yes', '1' => true,
                'false', 'no', '0' => false,
                default => null,
            };
        }

        return null;
    }

    /**
     * Decode the scan report object, salvaging a truncated response if needed.
     *
     * A bare JSON list of findings (some models drop the wrapper object) is
     * accepted as the vulnerabilities array. A decoded object without a
     * `vulnerabilities` array still fails: treating it as "no findings" would
     * report an unanalysed chunk as clean.
     *
     * @return array<string, mixed>
     *
     * @throws InvalidAIResponseException
     */
    private function decodeReport(string $response): array
    {
        try {
            $data = $this->decodeJson($response, 'vulnerabilities');
        } catch (InvalidAIResponseException $e) {
            $salvaged = $this->salvageTruncatedReport(trim($response));

            if ($salvaged === null) {
                throw $e;
            }

            return $salvaged;
        }

        if ($data !== [] && array_is_list($data)) {
            $data = ['vulnerabilities' => $data];
        }

        if (! array_key_exists('vulnerabilities', $data)) {
            throw InvalidAIResponseException::missingField('vulnerabilities');
        }

        if (! is_array($data['vulnerabilities'])) {
            throw InvalidAIResponseException::invalidFieldType(
                'vulnerabilities',
                'array',
                get_debug_type($data['vulnerabilities']),
            );
        }

        /** @var array<string, mixed> $data */
        return $data;
    }

    /**
     * Decode the JSON response, trying direct decode first, then extracting from code fences.
     *
     * A tier only wins outright when its object carries `$requiredKey`; an
     * array without it is remembered and returned only if no later tier finds
     * a better candidate, so the caller can still report the missing field.
     *
     * @return array<mixed>
     *
     * @throws InvalidAIResponseException
     */
    private function decodeJson(string $response, string $requiredKey): array
    {
        $trimmed = trim($response);
        $fallback = null;

        foreach ([$trimmed, $this->extractJsonFromCodeFences($trimmed)] as $candidate) {
            if ($candidate === null) {
                continue;
            }

            $decoded = json_decode($candidate, true);

            if (! is_array($decoded)) {
                continue;
            }

            if (array_key_exists($requiredKey, $decoded) || array_is_list($decoded)) {
                return $decoded;
            }

            $fallback ??= $decoded;
        }

        // Last resort: find the first { ... } block that looks like valid JSON
        $extracted = $this->extractJsonFromMixedText($trimmed, $requiredKey);

        if ($extracted !== null) {
            $decoded = json_decode($extracted, true);

            if (is_array($decoded)) {
                return $decoded;
            }
        }

        if ($fallback !== null) {
            return $fallback;
        }

        throw InvalidAIResponseException::malformed(
            'Response is not valid JSON and no JSON block could be extracted.',
            $trimmed,
        );
    }

    /**
     * Extract JSON content from markdown code fences (```json ... ``` or ``` ... ```).
     */
    private function extractJsonFromCodeFences(string $response): ?string
    {
        if (preg_match('/```(?:json)?\s*\n?(.*?)\n?\s*```/s', $response, $matches)) {
            return trim($matches[1]);
        }

        return null;
    }

    /**
     * Extract JSON from mixed prose + JSON text.
     *
     * Some models return analysis text before/after the JSON object.
     * Uses string-aware brace counting so that braces inside JSON string
     * values (e.g. PHP code snippets) do not confuse the depth tracker.
     *
     * Every `{` that could open a JSON object is tried in turn. A candidate
     * that never balances — "I looked at the { handler" in leading prose —
     * used to end the search, which threw away a perfectly valid report that
     * followed it; now the scan simply moves on to the next opening brace.
     */
    private function extractJsonFromMixedText(string $response, string $requiredKey): ?string
    {
        $offset = 0;
        $length = strlen($response);

        while ($offset < $length) {
            $start = strpos($response, '{', $offset);

            if ($start === false) {
                return null;
            }

            $offset = $start + 1;

            if (! $this->looksLikeObjectStart($response, $start, $length)) {
                continue;
            }

            $candidate = $this->extractBalancedBlock($response, $start, $length);

            if ($candidate === null) {
                continue;
            }

            $decoded = json_decode($candidate, true);

            if (is_array($decoded) && array_key_exists($requiredKey, $decoded)) {
                return $candidate;
            }

            // A valid object that is not the target: jump past it entirely.
            if (is_array($decoded)) {
                $offset = $start + strlen($candidate);
            }
        }

        return null;
    }

    /**
     * Whether the `{` at `$start` can open a JSON object: the next
     * non-whitespace character must be a key quote or the closing brace.
     *
     * Cheaply rejects the braces of PHP code and prose ("{ handler", "{\n
     * $x = 1;"), which keeps the candidate scan linear-ish on long responses.
     */
    private function looksLikeObjectStart(string $response, int $start, int $length): bool
    {
        for ($i = $start + 1; $i < $length; $i++) {
            $char = $response[$i];

            if ($char === ' ' || $char === "\n" || $char === "\r" || $char === "\t") {
                continue;
            }

            return $char === '"' || $char === '}';
        }

        return false;
    }

    /**
     * Recover the complete findings from a report cut off before it closed.
     *
     * Responses that hit max_tokens stop mid-string, so no tier of JSON
     * decoding can succeed, and the whole chunk used to be discarded even
     * though most of its findings had been written out in full. This walks
     * the text with the same string-aware scanner as extractBalancedBlock(),
     * locates the top-level `"vulnerabilities": [` array, and decodes every
     * element object that closed before the cut. The half-written trailing
     * element is dropped.
     *
     * An object that DID close but still failed to decode (a trailing comma,
     * one badly escaped field) is salvaged the same way, without the truncated
     * flag. Returns null when no vulnerabilities array can be found, or when
     * the response was cut off before a single finding completed — an empty
     * salvage is indistinguishable from "clean" and must not be reported as
     * one.
     *
     * @return array{vulnerabilities: array<int, mixed>}|null
     */
    private function salvageTruncatedReport(string $response): ?array
    {
        $length = strlen($response);
        $offset = 0;

        while (($start = strpos($response, '{', $offset)) !== false) {
            $offset = $start + 1;

            if (! $this->looksLikeObjectStart($response, $start, $length)) {
                continue;
            }

            $salvage = $this->collectVulnerabilityElements($response, $start, $length);

            if ($salvage === null) {
                continue;
            }

            if ($salvage['terminated']) {
                // The object closed, so it was syntactically malformed (a
                // trailing comma, an unescaped quote in one field) rather than
                // truncated. Every element that decodes on its own is complete.
                $this->warn('AI response was malformed JSON; salvaged the findings that decode individually', [
                    'recovered' => count($salvage['items']),
                ]);

                return ['vulnerabilities' => $salvage['items']];
            }

            if ($salvage['items'] === []) {
                // Cut off before a single finding completed: nothing to report.
                return null;
            }

            $this->lastParseTruncated = true;

            $this->warn('AI response was truncated; salvaged the complete findings', [
                'recovered' => count($salvage['items']),
            ]);

            return ['vulnerabilities' => $salvage['items']];
        }

        return null;
    }

    /**
     * Walk one candidate object and collect each complete element of its
     * top-level `vulnerabilities` array.
     *
     * @return array{items: array<int, mixed>, terminated: bool}|null Null when the object has no top-level vulnerabilities array.
     */
    private function collectVulnerabilityElements(string $response, int $start, int $length): ?array
    {
        // Declared wide on purpose: this is a state machine whose flags flip
        // across iterations, and narrowing them to their initial literals
        // makes static analysis conclude the transitions can never happen.
        $depth = 0;
        /** @var bool $inString */
        $inString = false;
        $stringStart = 0;
        /** @var string|null $lastTopLevelString */
        $lastTopLevelString = null;
        /** @var bool $awaitingArray */
        $awaitingArray = false;
        /** @var bool $arrayOpen */
        $arrayOpen = false;
        /** @var bool $found */
        $found = false;
        /** @var int|null $elementStart */
        $elementStart = null;
        $items = [];

        for ($i = $start; $i < $length; $i++) {
            $char = $response[$i];

            if ($inString) {
                if ($char === '\\') {
                    $i++;

                    continue;
                }

                if ($char === '"') {
                    $inString = false;

                    if ($depth === 1) {
                        $lastTopLevelString = substr($response, $stringStart + 1, $i - $stringStart - 1);
                    }
                }

                continue;
            }

            if ($char === ' ' || $char === "\n" || $char === "\r" || $char === "\t") {
                continue;
            }

            if ($char === ':') {
                $awaitingArray = $depth === 1 && $lastTopLevelString === 'vulnerabilities';

                continue;
            }

            $opensArray = $awaitingArray && $char === '[';
            $awaitingArray = false;

            if ($char === '"') {
                $inString = true;
                $stringStart = $i;
            } elseif ($char === '{' || $char === '[') {
                $depth++;

                if ($opensArray && $depth === 2) {
                    $found = true;
                    $arrayOpen = true;
                } elseif ($char === '{' && $arrayOpen && $depth === 3) {
                    $elementStart = $i;
                }
            } elseif ($char === '}' || $char === ']') {
                $depth--;

                if ($char === '}' && $arrayOpen && $depth === 2 && $elementStart !== null) {
                    $decoded = json_decode(substr($response, $elementStart, $i - $elementStart + 1), true);

                    if (is_array($decoded)) {
                        $items[] = $decoded;
                    }

                    $elementStart = null;
                } elseif ($char === ']' && $arrayOpen && $depth === 1) {
                    $arrayOpen = false;
                }

                if ($depth === 0) {
                    return $found ? ['items' => $items, 'terminated' => true] : null;
                }
            }
        }

        return $found ? ['items' => $items, 'terminated' => false] : null;
    }

    /**
     * Extract a balanced { ... } block starting at the given position.
     *
     * Tracks whether the scanner is inside a JSON string literal so that
     * braces within strings (e.g. PHP code in proof/fix fields) do not
     * affect the depth counter. Handles escaped characters within strings.
     */
    private function extractBalancedBlock(string $response, int $start, int $length): ?string
    {
        $depth = 0;
        $inString = false;

        for ($i = $start; $i < $length; $i++) {
            $char = $response[$i];

            if ($inString) {
                if ($char === '\\') {
                    $i++; // skip the escaped character

                    continue;
                }

                if ($char === '"') {
                    $inString = false;
                }

                continue;
            }

            if ($char === '"') {
                $inString = true;
            } elseif ($char === '{') {
                $depth++;
            } elseif ($char === '}') {
                $depth--;

                if ($depth === 0) {
                    return substr($response, $start, $i - $start + 1);
                }
            }
        }

        return null;
    }

    /**
     * Index the chunk's files by normalised path for location validation.
     *
     * @param  array<int, array{path: string, content: string, type?: string}>  $files
     * @return array<string, array{path: string, lines: int}>
     */
    private function indexChunkFiles(array $files): array
    {
        $index = [];

        foreach ($files as $file) {
            $index[$this->normalizePath($file['path'])] = [
                'path' => $file['path'],
                'lines' => max(1, substr_count($file['content'], "\n") + 1),
            ];
        }

        return $index;
    }

    /**
     * Fold a location into a comparable form: forward slashes, no base_path
     * prefix, no leading "./" or "/", lowercased.
     */
    private function normalizePath(string $path): string
    {
        $normalized = str_replace('\\', '/', trim($path));

        foreach ($this->basePathPrefixes() as $prefix) {
            if ($prefix !== '' && str_starts_with(strtolower($normalized), strtolower($prefix).'/')) {
                $normalized = substr($normalized, strlen($prefix) + 1);

                break;
            }
        }

        while (str_starts_with($normalized, './')) {
            $normalized = substr($normalized, 2);
        }

        return strtolower(ltrim($normalized, '/'));
    }

    /**
     * The application base path, when a container is available to supply it.
     *
     * @return array<int, string>
     */
    private function basePathPrefixes(): array
    {
        try {
            return [rtrim(str_replace('\\', '/', base_path()), '/')];
        } catch (Throwable) {
            return [];
        }
    }

    /**
     * Resolve an AI-reported location to one of the chunk's files.
     *
     * Tries an exact normalised match, then a unique path-suffix match in
     * either direction (the model shortened the path, or prefixed an absolute
     * one), then a unique basename match — with or without the ".php" the
     * model sometimes omits. Ambiguity resolves to null rather than a guess.
     *
     * @param  array<string, array{path: string, lines: int}>  $index
     * @return array{path: string, lines: int}|null
     */
    private function resolveChunkFile(string $location, array $index): ?array
    {
        $needle = $this->normalizePath($location);

        if ($needle === '') {
            return null;
        }

        if (isset($index[$needle])) {
            return $index[$needle];
        }

        $suffixMatches = array_filter(
            array_keys($index),
            static fn (string $key): bool => str_ends_with($key, '/'.$needle) || str_ends_with($needle, '/'.$key),
        );

        if (count($suffixMatches) === 1) {
            return $index[array_values($suffixMatches)[0]];
        }

        $needleBase = basename($needle);
        $needleStem = pathinfo($needleBase, PATHINFO_FILENAME);

        $baseMatches = array_filter(
            array_keys($index),
            static fn (string $key): bool => basename($key) === $needleBase
                || (! str_contains($needleBase, '.') && pathinfo(basename($key), PATHINFO_FILENAME) === $needleStem),
        );

        if (count($baseMatches) === 1) {
            return $index[array_values($baseMatches)[0]];
        }

        return null;
    }

    /**
     * Resolve an AI-reported location to a real file inside the application.
     *
     * Absolute paths must sit inside base_path(); relative ones are taken from
     * it. Only the line count is read, to clamp the reported line.
     *
     * @return array{path: string, lines: int}|null
     */
    private function resolveAppFile(string $location): ?array
    {
        // normalizePath() lowercases for matching; a disk lookup must keep case.
        $relative = str_replace('\\', '/', trim($location));

        foreach ($this->basePathPrefixes() as $prefix) {
            if ($prefix !== '' && str_starts_with($relative, $prefix.'/')) {
                $relative = substr($relative, strlen($prefix) + 1);

                break;
            }
        }

        if (str_starts_with($relative, '/') || preg_match('#^[A-Za-z]:/#', $relative) === 1) {
            return null;
        }

        while (str_starts_with($relative, './')) {
            $relative = substr($relative, 2);
        }

        if ($relative === '' || str_contains('/'.$relative.'/', '/../')) {
            return null;
        }

        try {
            $absolute = base_path($relative);
        } catch (Throwable) {
            return null;
        }

        if (! is_file($absolute) || ! is_readable($absolute)) {
            return null;
        }

        $contents = @file_get_contents($absolute);

        if ($contents === false) {
            return null;
        }

        return [
            'path' => $relative,
            'lines' => max(1, substr_count($contents, "\n") + 1),
        ];
    }

    /**
     * Parse the vulnerabilities array, skipping (never throwing on) bad entries.
     *
     * @param  array<int|string, mixed>  $items
     * @param  array<string, array{path: string, lines: int}>  $chunkFiles
     * @return array<int, Vulnerability>
     */
    private function parseVulnerabilities(array $items, array $chunkFiles): array
    {
        $vulnerabilities = [];

        foreach ($items as $index => $item) {
            if (! is_array($item)) {
                $this->skipFinding($index, 'entry is '.get_debug_type($item).', not an object');

                continue;
            }

            $vulnerability = $this->parseVulnerability($item, $index, $chunkFiles);

            if ($vulnerability !== null) {
                $vulnerabilities[] = $vulnerability;
            }
        }

        return $vulnerabilities;
    }

    /**
     * Parse a single vulnerability entry, or null (with a logged reason) when
     * it cannot be turned into an actionable finding.
     *
     * Only TYPE and LOCATION are load-bearing enough to skip on: without them
     * the finding cannot be classified or found. Everything else degrades to
     * a safe default — numeric strings are coerced, a missing proof or fix is
     * empty, an unusable line is 1, an unknown severity falls back to Low
     * (logged by SeverityLevel), and a missing description falls back to the
     * type's own description.
     *
     * @param  array<string, mixed>  $item
     * @param  array<string, array{path: string, lines: int}>  $chunkFiles
     */
    private function parseVulnerability(array $item, int|string $index, array $chunkFiles): ?Vulnerability
    {
        $rawType = $item['type'] ?? null;

        if (! is_string($rawType) || trim($rawType) === '') {
            $this->skipFinding($index, 'type is missing or not a string');

            return null;
        }

        $type = VulnerabilityType::tryFromString($rawType);

        if ($type === null) {
            $this->skipFinding($index, "unknown vulnerability type \"{$rawType}\"");

            return null;
        }

        $location = $item['location'] ?? null;

        if (! is_string($location) || trim($location) === '') {
            $this->skipFinding($index, 'location is missing or not a string');

            return null;
        }

        $line = $this->coerceLine($item['line'] ?? null);

        if ($chunkFiles !== []) {
            // A model often attributes a finding to a related file it was not
            // sent — the model behind a controller, the route file — and those
            // findings can be real. Only a location that exists nowhere in the
            // application is treated as invented.
            $file = $this->resolveChunkFile($location, $chunkFiles) ?? $this->resolveAppFile($location);

            if ($file === null) {
                $this->skipFinding($index, "location \"{$location}\" is neither in this chunk nor a file in the application");

                return null;
            }

            $location = $file['path'];
            $line = min($line, $file['lines']);
        }

        $severity = is_string($item['severity'] ?? null)
            ? SeverityLevel::fromString($item['severity'])
            : SeverityLevel::fromString('');

        $description = $this->coerceString($item['description'] ?? null);

        return new Vulnerability(
            type: $type,
            location: $location,
            line: $line,
            severity: $severity,
            description: $description !== '' ? $description : $type->description(),
            proof: $this->coerceString($item['proof'] ?? null),
            fix: $this->coerceString($item['fix'] ?? null),
            taintTrace: $this->parseOptionalTaintTrace($item),
        );
    }

    /**
     * Coerce a model-supplied line number to a positive integer.
     *
     * Accepts ints, floats and numeric strings ("42", " 42 "), and takes the
     * first number of a range or label ("42-45", "L42"). Anything unusable —
     * null, 0, negative, prose — becomes line 1: the finding still points at
     * the right file, which is more useful than discarding it.
     */
    private function coerceLine(mixed $value): int
    {
        $line = match (true) {
            is_int($value) => $value,
            is_float($value) => (int) $value,
            is_string($value) && is_numeric(trim($value)) => (int) trim($value),
            is_string($value) && preg_match('/\d+/', $value, $match) === 1 => (int) $match[0],
            default => 1,
        };

        return max(1, $line);
    }

    /**
     * Coerce a free-text field to a string: strings pass through, scalars are
     * stringified, null/arrays/objects become empty.
     */
    private function coerceString(mixed $value): string
    {
        if (is_string($value)) {
            return $value;
        }

        if (is_int($value) || is_float($value)) {
            return (string) $value;
        }

        return '';
    }

    /**
     * Record and log why one finding in the response was dropped.
     */
    private function skipFinding(int|string $index, string $reason): void
    {
        $this->lastSkippedFindings[] = "vulnerabilities[{$index}]: {$reason}";

        $this->warn('Skipped unusable AI finding', [
            'index' => $index,
            'reason' => $reason,
        ]);
    }

    /**
     * Log a parser warning without letting logging break parsing.
     *
     * The parser also runs outside a booted app (standalone benchmark, plain
     * unit tests), where the Log facade has no root to resolve.
     *
     * @param  array<string, mixed>  $context
     */
    private function warn(string $message, array $context = []): void
    {
        try {
            Log::warning("[HackAuditor] {$message}", $context);
        } catch (Throwable) {
            // No container bound — nothing to log to.
        }
    }

    /**
     * Parse and clamp the overall score to a 0-100 range.
     *
     * Numeric strings ("40") are accepted. When the score is missing or not a
     * number (including every salvaged, truncated response) it is derived
     * from the parsed findings with the same 100-minus-severity-weights
     * formula the scanner uses, so an unusable score never hides findings
     * behind a default of 100.
     *
     * @param  array<int, Vulnerability>  $vulnerabilities
     */
    private function parseOverallScore(mixed $value, array $vulnerabilities): int
    {
        if (is_string($value) && is_numeric(trim($value))) {
            $value = (float) trim($value);
        }

        if (! is_int($value) && ! is_float($value)) {
            $penalty = 0;

            foreach ($vulnerabilities as $vulnerability) {
                $penalty += $vulnerability->severity->weight();
            }

            return max(0, 100 - $penalty);
        }

        return max(0, min(100, (int) $value));
    }

    /**
     * Parse an optional string field, returning an empty string if missing or null.
     *
     * @param  array<string, mixed>  $data
     */
    private function parseOptionalStringField(array $data, string $field): string
    {
        if (! array_key_exists($field, $data) || $data[$field] === null) {
            return '';
        }

        if (! is_string($data[$field])) {
            return '';
        }

        return $data[$field];
    }

    /**
     * Filter out findings where the description contradicts its own conclusion.
     *
     * Catches cases where the AI analysis concludes a finding is safe but still
     * emits it as a vulnerability (e.g., "this is not actually a vulnerability").
     *
     * @param  array<int, Vulnerability>  $vulnerabilities
     * @return array<int, Vulnerability>
     */
    private function filterSelfContradictions(array $vulnerabilities): array
    {
        return array_values(array_filter(
            $vulnerabilities,
            fn (Vulnerability $v): bool => ! $this->isSelfContradicting($v->description),
        ));
    }

    /**
     * Check if a vulnerability description contradicts its own finding.
     *
     * Uses a two-pass approach: first checks for strong dismissal patterns that
     * always indicate a self-contradiction, then checks for weaker mitigation
     * patterns that can be overridden by adversative "but still vulnerable"
     * counter-phrases (rescue patterns).
     */
    private function isSelfContradicting(string $description): bool
    {
        $lower = strtolower($description);

        // Strong dismissals — always indicate the AI walked back the finding.
        // These are never rescued because they express a clear "not a vuln" conclusion.
        $strongDismissals = [
            // Direct negations
            'this is not a vulnerability',
            'this is not actually a vulnerability',
            'not actually vulnerable',
            'not a real vulnerability',
            'not a real issue',
            'not a security issue',
            'not a security vulnerability',
            'not exploitable',
            'not a concern',
            'no actual vulnerability',
            'no real vulnerability',
            'no vulnerability',
            // Self-corrections mid-description
            'on re-analysis',
            'after self-check',
            'removing this finding',
            'this is by design',
            'by design for',
            'this is actually safe',
            'actually safe',
            'this is expected behavior',
            'this is expected behaviour',
            'this is intentional',
            'working as intended',
            'working as designed',
        ];

        foreach ($strongDismissals as $pattern) {
            if (str_contains($lower, $pattern)) {
                return true;
            }
        }

        // Strong regex dismissals — always indicate the AI walked back the finding.
        $strongRegexPatterns = [
            '/this is not (?:a |an )?[\w\s]{0,30}(?:issue|vulnerability)/i',
            '/on closer inspection[\s\S]{0,80}(?:not|safe|properly|handled)/i',
            '/fields are explicitly (?:specified|listed|enumerated)/i',
            '/properly (?:controlled|protected|validated|handled)/i',
            '/more of a (?:code.?smell|best.?practice|style|hygiene)/i',
            // AI walks back its own finding
            '/\bon re.?analysis[\s\S]{0,40}(?:safe|design|not|no|false|removing)/i',
            '/\bafter (?:self.?check|review|analysis)[\s\S]{0,40}(?:safe|remov|not|no)/i',
            '/\bno (?:actual|real) (?:vulnerability|issue|risk|concern)\b/i',
            '/\bthis is (?:actually |)(?:safe|secure|by design|expected|intentional)\b/i',
            '/\bremoving this (?:finding|issue|vulnerability)\b/i',
        ];

        foreach ($strongRegexPatterns as $regex) {
            if (preg_match($regex, $description)) {
                return true;
            }
        }

        // Weak mitigation patterns — these acknowledge partial safety but the AI
        // may still conclude the code is vulnerable. If a rescue counter-pattern
        // is present (e.g. "but ... is a risk"), the finding is kept.
        $weakDismissals = [
            'already mitigated',
            'already handled',
            'already protected',
            'mitigates direct exploitation',
            'mitigates the risk',
            'prevents direct exploitation',
            'more of a code-smell',
            'more of a code smell',
            'code quality issue rather than',
            'not immediately exploitable',
            'not directly exploitable',
            'not an immediately exploitable',
            'no direct exploitation path',
            'cannot be directly exploited',
            // Type cast safety
            'inputs are cast to',
            'values are cast to int',
            'integer cast prevents',
            'cast provides protection',
        ];

        $weakMatched = false;

        foreach ($weakDismissals as $pattern) {
            if (str_contains($lower, $pattern)) {
                $weakMatched = true;

                break;
            }
        }

        if (! $weakMatched) {
            $weakRegexPatterns = [
                '/\bmitigat(?:es|ed)\b[\s\S]{0,40}\bexploit/i',
                '/\bcast(?:ed|s|ing)?\b[\s\S]{0,30}\b(?:int|integer)\b[\s\S]{0,30}\b(?:safe|prevent|protect|mitigat)/i',
                '/although[\s\S]{0,60}(?:prevents?|mitigat|safe|protected)/i',
                '/however[\s\S]{0,40}(?:the (?:int|integer) cast|casting|not (?:directly|immediately))/i',
            ];

            foreach ($weakRegexPatterns as $regex) {
                if (preg_match($regex, $description)) {
                    $weakMatched = true;

                    break;
                }
            }
        }

        if (! $weakMatched) {
            return false;
        }

        // A weak dismissal matched — check for rescue counter-patterns that
        // indicate the AI still considers this a real vulnerability despite
        // acknowledging partial mitigation.
        return ! $this->hasRescueCounter($lower);
    }

    /**
     * Check if a description contains adversative phrases that override a
     * partial-mitigation dismissal, indicating the finding is still valid.
     *
     * Detects patterns like "mitigates X, but the architecture is still a risk"
     * or "although the cast prevents injection, this is a fragile defense".
     */
    private function hasRescueCounter(string $lower): bool
    {
        $rescuePatterns = [
            // Adversative conjunctions followed by risk assertions
            'but the architecture',
            'but this is still',
            'but still a',
            'but remains',
            'but is a',
            'but the risk',
            'but could be',
            'but it is still',
            'is a sql injection risk',
            'is a security risk',
            'is still a risk',
            'is still vulnerable',
            'still a vulnerability',
            'still exploitable',
            'fragile defense',
            'fragile defence',
            'defense-in-depth failure',
            'defence-in-depth failure',
            'string concatenation is a',
            'building raw sql',
        ];

        foreach ($rescuePatterns as $pattern) {
            if (str_contains($lower, $pattern)) {
                return true;
            }
        }

        $rescueRegexPatterns = [
            // "but ... risk/vulnerability/injection/issue"
            '/\bbut\b[\s\S]{0,80}\b(?:risk|vulnerab|injection|exploit|fragile|unsafe|danger)/i',
            // "however ... still|risk|vulnerable"
            '/\bhowever\b[\s\S]{0,80}\b(?:still|risk|vulnerab|exploit|fragile|unsafe)/i',
            // "although ... fragile|failure|risk|vulnerable"
            '/\balthough\b[\s\S]{0,80}\b(?:fragile|failure|risk|vulnerab|exploit|unsafe)/i',
            // "nonetheless/nevertheless ... risk/vulnerable"
            '/\bnonetheless|nevertheless\b[\s\S]{0,80}\b(?:risk|vulnerab|exploit)/i',
        ];

        foreach ($rescueRegexPatterns as $regex) {
            if (preg_match($regex, $lower)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extract the optional taint_trace field from a vulnerability entry.
     *
     * @param  array<string, mixed>  $item
     */
    private function parseOptionalTaintTrace(array $item): ?string
    {
        if (! array_key_exists('taint_trace', $item) || $item['taint_trace'] === null) {
            return null;
        }

        if (! is_string($item['taint_trace'])) {
            return null;
        }

        $trace = trim($item['taint_trace']);

        return $trace !== '' ? $trace : null;
    }

    /**
     * Filter out findings whose taint trace reveals a non-exploitable data flow.
     *
     * For vulnerability types that require user-controlled input (SQL injection,
     * XSS, open redirect, insecure deserialization), examines the taint_trace
     * field to programmatically detect:
     * - Sources that are not user-controlled (config, env, hardcoded, Auth::id)
     * - Transforms that break the exploitation chain ((int) cast, htmlspecialchars, validated())
     *
     * Findings without a taint_trace or of non-input-dependent types pass through unchanged.
     *
     * @param  array<int, Vulnerability>  $vulnerabilities
     * @return array<int, Vulnerability>
     */
    private function filterBrokenTaintTraces(array $vulnerabilities): array
    {
        return array_values(array_filter(
            $vulnerabilities,
            fn (Vulnerability $v): bool => ! $this->hasBrokenTaintTrace($v),
        ));
    }

    /**
     * Determine if a vulnerability's taint trace reveals a non-exploitable flow.
     */
    private function hasBrokenTaintTrace(Vulnerability $v): bool
    {
        if ($v->taintTrace === null) {
            return false;
        }

        // Only apply taint analysis to input-dependent vulnerability types
        $inputDependentTypes = [
            VulnerabilityType::SqlInjection,
            VulnerabilityType::Xss,
            VulnerabilityType::OpenRedirect,
            VulnerabilityType::InsecureDeserialization,
        ];

        if (! in_array($v->type, $inputDependentTypes, true)) {
            return false;
        }

        $trace = strtolower($v->taintTrace);

        if ($this->hasNonUserControlledSource($trace)) {
            return true;
        }

        return $this->hasChainBreakingTransform($trace, $v->type);
    }

    /**
     * Check if the taint trace SOURCE is non-user-controlled.
     *
     * Parses the SOURCE segment and checks for patterns indicating
     * server-controlled or static data origins.
     */
    private function hasNonUserControlledSource(string $trace): bool
    {
        // Extract the SOURCE segment
        if (! preg_match('/source:\s*(.+?)(?:\s*→|$)/i', $trace, $match)) {
            return false;
        }

        $source = trim($match[1]);

        // Non-user-controlled source patterns
        $safeSourcePatterns = [
            'config(',
            'config::',
            'env(',
            'constant',
            'hardcoded',
            'static array',
            'static string',
            'auth::id()',
            'auth::user()',
            'auth()->id()',
            'auth()->user()',
            '$user->id',
            'database value',
            'admin-set',
            'server-controlled',
            'enum::',
            'enum case',
        ];

        foreach ($safeSourcePatterns as $pattern) {
            if (str_contains($source, $pattern)) {
                return true;
            }
        }

        // Regex patterns for config/env/constant sources
        $safeSourceRegex = [
            '/\bconfig\s*\(/',
            '/\benv\s*\(/',
            '/\b[A-Z_]{2,}(?:\s*constant|\s*enum)?\b/',
            '/\bauth\s*(?:::|->|\(\s*\))/',
        ];

        foreach ($safeSourceRegex as $regex) {
            if (preg_match($regex, $source)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the taint trace TRANSFORMS break the exploitation chain.
     *
     * Examines the TRANSFORMS segment for sanitization or type-casting
     * functions that neutralize the vulnerability type.
     */
    private function hasChainBreakingTransform(string $trace, VulnerabilityType $type): bool
    {
        // Extract the TRANSFORMS segment
        if (! preg_match('/transforms:\s*(.+?)(?:\s*→|$)/i', $trace, $match)) {
            return false;
        }

        $transforms = trim($match[1]);

        if ($transforms === 'none' || $transforms === '') {
            return false;
        }

        // Universal chain breakers — these kill any taint
        $universalBreakers = [
            'validated()',
            '$request->validated()',
            '->validated()',
            '->safe()',
            'safe()->only(',
            'in_array(',
            'in_array',
            'allowlist',
            'whitelist',
        ];

        foreach ($universalBreakers as $pattern) {
            if (str_contains($transforms, $pattern)) {
                return true;
            }
        }

        // Type-specific chain breakers
        return match ($type) {
            VulnerabilityType::SqlInjection => $this->sqlInjectionChainBroken($transforms),
            VulnerabilityType::Xss => $this->xssChainBroken($transforms),
            VulnerabilityType::OpenRedirect => $this->openRedirectChainBroken($transforms),
            VulnerabilityType::InsecureDeserialization => false,
            default => false,
        };
    }

    /**
     * Check if a transform breaks SQL injection exploitation.
     */
    private function sqlInjectionChainBroken(string $transforms): bool
    {
        $breakers = [
            '(int)',
            '(float)',
            '(bool)',
            'intval(',
            'intval',
            'floatval(',
            'floatval',
            'abs(',
            '(int) cast',
            'integer cast',
            'int cast',
            'eloquent parameterization',
            'parameter binding',
            'prepared statement',
        ];

        foreach ($breakers as $pattern) {
            if (str_contains($transforms, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a transform breaks XSS exploitation.
     */
    private function xssChainBroken(string $transforms): bool
    {
        $breakers = [
            'htmlspecialchars(',
            'htmlspecialchars',
            'htmlentities(',
            'htmlentities',
            'e(',
            'strip_tags(',
            'strip_tags',
            '{{ }}',
            'blade {{ }}',
            'blade escaping',
            'escaped output',
            '(int)',
            '(float)',
            '(bool)',
            'intval(',
            'intval',
        ];

        foreach ($breakers as $pattern) {
            if (str_contains($transforms, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a transform breaks open redirect exploitation.
     */
    private function openRedirectChainBroken(string $transforms): bool
    {
        $breakers = [
            'url validation',
            'domain validation',
            'domain allowlist',
            'domain whitelist',
            'parse_url(',
            'parse_url',
            'starts_with(',
            'url::to(',
            'route(',
        ];

        foreach ($breakers as $pattern) {
            if (str_contains($transforms, $pattern)) {
                return true;
            }
        }

        return false;
    }
}
