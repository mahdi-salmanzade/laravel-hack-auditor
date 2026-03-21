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
     */
    private function isSelfContradicting(string $description): bool
    {
        $dismissalPatterns = [
            'this is not a vulnerability',
            'this is not actually a vulnerability',
            'not actually vulnerable',
            'not a real vulnerability',
            'not a real issue',
            'not a security issue',
            'not a security vulnerability',
            'not exploitable',
            'not a concern',
            'already mitigated',
            'already handled',
            'already protected',
        ];

        $lower = strtolower($description);

        foreach ($dismissalPatterns as $pattern) {
            if (str_contains($lower, $pattern)) {
                return true;
            }
        }

        // Regex patterns for more complex contradictions
        $regexPatterns = [
            '/this is not (?:a |an )?[\w\s]{0,30}(?:issue|vulnerability)/i',
            '/on closer inspection[\s\S]{0,80}(?:not|safe|properly|handled)/i',
            '/fields are explicitly (?:specified|listed|enumerated)/i',
            '/properly (?:controlled|protected|validated|handled)/i',
        ];

        foreach ($regexPatterns as $regex) {
            if (preg_match($regex, $description)) {
                return true;
            }
        }

        return false;
    }
}
