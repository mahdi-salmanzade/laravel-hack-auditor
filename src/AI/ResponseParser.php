<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\AI;

use Mahdi\HackAuditor\Exceptions\InvalidAIResponseException;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

final class ResponseParser
{
    /**
     * Parse an AI response string into a VulnerabilityReport.
     *
     * Attempts direct JSON decode first, then falls back to extracting JSON
     * from markdown code fences. Validates all fields against expected types
     * and enum values.
     *
     * @throws InvalidAIResponseException When the response cannot be parsed or contains invalid data.
     */
    public function parse(string $response): VulnerabilityReport
    {
        $data = $this->decodeJson($response);

        $this->validateRequiredFields($data);

        $vulnerabilities = $this->parseVulnerabilities($data['vulnerabilities']);
        $vulnerabilities = $this->filterSelfContradictions($vulnerabilities);
        $overallScore = $this->parseOverallScore($data['overall_score']);
        $summary = $this->parseStringField($data, 'summary');
        $ctfIdea = $this->parseOptionalStringField($data, 'ctf_idea');

        return new VulnerabilityReport(
            vulnerabilities: $vulnerabilities,
            overallScore: $overallScore,
            summary: $summary,
            ctfIdea: $ctfIdea,
        );
    }

    /**
     * Decode the JSON response, trying direct decode first, then extracting from code fences.
     *
     * @return array<string, mixed>
     *
     * @throws InvalidAIResponseException
     */
    private function decodeJson(string $response): array
    {
        $trimmed = trim($response);

        $decoded = json_decode($trimmed, true);

        if (is_array($decoded)) {
            return $decoded;
        }

        $extracted = $this->extractJsonFromCodeFences($trimmed);

        if ($extracted !== null) {
            $decoded = json_decode($extracted, true);

            if (is_array($decoded)) {
                return $decoded;
            }
        }

        // Last resort: find the first { ... } block that looks like valid JSON
        $extracted = $this->extractJsonFromMixedText($trimmed);

        if ($extracted !== null) {
            $decoded = json_decode($extracted, true);

            if (is_array($decoded)) {
                return $decoded;
            }
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
     * When the first candidate block does not contain the required keys,
     * subsequent { ... } blocks are tried.
     */
    private function extractJsonFromMixedText(string $response): ?string
    {
        $offset = 0;
        $length = strlen($response);

        while ($offset < $length) {
            $start = strpos($response, '{', $offset);

            if ($start === false) {
                return null;
            }

            $candidate = $this->extractBalancedBlock($response, $start, $length);

            if ($candidate === null) {
                return null;
            }

            $decoded = json_decode($candidate, true);

            if (is_array($decoded) && isset($decoded['vulnerabilities'])) {
                return $candidate;
            }

            // This block was valid JSON but not our target, or invalid JSON -- skip past it
            $offset = $start + strlen($candidate);

            // If it wasn't valid JSON, just skip one character to avoid infinite loop
            if ($decoded === null) {
                $offset = $start + 1;
            }
        }

        return null;
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
     * Validate that all required top-level fields are present.
     *
     * @param  array<string, mixed>  $data
     *
     * @throws InvalidAIResponseException
     */
    private function validateRequiredFields(array $data): void
    {
        $required = ['vulnerabilities', 'overall_score', 'summary'];

        foreach ($required as $field) {
            if (! array_key_exists($field, $data)) {
                throw InvalidAIResponseException::missingField($field);
            }
        }

        if (! is_array($data['vulnerabilities'])) {
            throw InvalidAIResponseException::invalidFieldType(
                'vulnerabilities',
                'array',
                get_debug_type($data['vulnerabilities']),
            );
        }
    }

    /**
     * Parse and validate the vulnerabilities array.
     *
     * @param  array<int, mixed>  $items
     * @return array<int, Vulnerability>
     *
     * @throws InvalidAIResponseException
     */
    private function parseVulnerabilities(array $items): array
    {
        $vulnerabilities = [];

        foreach ($items as $index => $item) {
            if (! is_array($item)) {
                throw InvalidAIResponseException::invalidFieldType(
                    "vulnerabilities[{$index}]",
                    'object',
                    get_debug_type($item),
                );
            }

            $vulnerabilities[] = $this->parseVulnerability($item, $index);
        }

        return $vulnerabilities;
    }

    /**
     * Parse a single vulnerability entry from the AI response.
     *
     * @param  array<string, mixed>  $item
     *
     * @throws InvalidAIResponseException
     */
    private function parseVulnerability(array $item, int $index): Vulnerability
    {
        $requiredFields = ['type', 'location', 'line', 'severity', 'description', 'proof', 'fix'];

        foreach ($requiredFields as $field) {
            if (! array_key_exists($field, $item)) {
                throw InvalidAIResponseException::missingField("vulnerabilities[{$index}].{$field}");
            }
        }

        $type = $this->parseVulnerabilityType($item['type'], $index);
        $severity = $this->parseSeverityLevel($item['severity'], $index);

        if (! is_string($item['location'])) {
            throw InvalidAIResponseException::invalidFieldType(
                "vulnerabilities[{$index}].location",
                'string',
                get_debug_type($item['location']),
            );
        }

        if (! is_int($item['line']) && ! is_float($item['line'])) {
            throw InvalidAIResponseException::invalidFieldType(
                "vulnerabilities[{$index}].line",
                'integer',
                get_debug_type($item['line']),
            );
        }

        if (! is_string($item['description'])) {
            throw InvalidAIResponseException::invalidFieldType(
                "vulnerabilities[{$index}].description",
                'string',
                get_debug_type($item['description']),
            );
        }

        if (! is_string($item['proof'])) {
            throw InvalidAIResponseException::invalidFieldType(
                "vulnerabilities[{$index}].proof",
                'string',
                get_debug_type($item['proof']),
            );
        }

        if (! is_string($item['fix'])) {
            throw InvalidAIResponseException::invalidFieldType(
                "vulnerabilities[{$index}].fix",
                'string',
                get_debug_type($item['fix']),
            );
        }

        return new Vulnerability(
            type: $type,
            location: $item['location'],
            line: (int) $item['line'],
            severity: $severity,
            description: $item['description'],
            proof: $item['proof'],
            fix: $item['fix'],
        );
    }

    /**
     * Parse a vulnerability type string using case-insensitive matching.
     *
     * @throws InvalidAIResponseException
     */
    private function parseVulnerabilityType(mixed $value, int $index): VulnerabilityType
    {
        if (! is_string($value)) {
            throw InvalidAIResponseException::invalidFieldType(
                "vulnerabilities[{$index}].type",
                'string',
                get_debug_type($value),
            );
        }

        try {
            return VulnerabilityType::fromString($value);
        } catch (\ValueError $e) {
            throw InvalidAIResponseException::malformed(
                "Invalid vulnerability type \"{$value}\" at vulnerabilities[{$index}].type.",
            );
        }
    }

    /**
     * Parse a severity level string using case-insensitive matching.
     *
     * @throws InvalidAIResponseException
     */
    private function parseSeverityLevel(mixed $value, int $index): SeverityLevel
    {
        if (! is_string($value)) {
            throw InvalidAIResponseException::invalidFieldType(
                "vulnerabilities[{$index}].severity",
                'string',
                get_debug_type($value),
            );
        }

        return SeverityLevel::fromString($value);
    }

    /**
     * Parse and clamp the overall score to a 0-100 range.
     *
     * @throws InvalidAIResponseException
     */
    private function parseOverallScore(mixed $value): int
    {
        if (! is_int($value) && ! is_float($value)) {
            throw InvalidAIResponseException::invalidFieldType(
                'overall_score',
                'integer',
                get_debug_type($value),
            );
        }

        return max(0, min(100, (int) $value));
    }

    /**
     * Parse a required string field from the response data.
     *
     * @param  array<string, mixed>  $data
     *
     * @throws InvalidAIResponseException
     */
    private function parseStringField(array $data, string $field): string
    {
        if (! is_string($data[$field])) {
            throw InvalidAIResponseException::invalidFieldType(
                $field,
                'string',
                get_debug_type($data[$field]),
            );
        }

        return $data[$field];
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
}
