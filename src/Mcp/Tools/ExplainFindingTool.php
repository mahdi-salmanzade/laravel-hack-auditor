<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Mcp\Tools;

use Illuminate\Contracts\JsonSchema\JsonSchema;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\ResponseFactory;
use Laravel\Mcp\Server\Attributes\Description;
use Laravel\Mcp\Server\Attributes\Name;
use Laravel\Mcp\Server\Tool;
use Mahdi\HackAuditor\Support\VulnerabilityType;
use ValueError;

#[Name('explain_finding')]
#[Description('Explain a Laravel security vulnerability type returned by scan_path or scan_diff. Pass the finding\'s "type" value (e.g. "sql_injection", "idor", "mass_assignment", "missing_rate_limit") or a common name ("SQL Injection", "IDOR"). Returns a plain-language description, the OWASP Top 10 2021 category, the CWE identifier, and Laravel-specific remediation guidance. Use this to help a developer understand and fix a finding without re-running a scan. Performs no network or AI calls.')]
class ExplainFindingTool extends Tool
{
    /**
     * Define the tool's input schema.
     *
     * @return array<string, mixed>
     */
    public function schema(JsonSchema $schema): array
    {
        return [
            'type' => $schema->string()
                ->description('The vulnerability type identifier from a finding (e.g. "sql_injection", "xss", "idor", "mass_assignment", "missing_rate_limit", "auth_bypass", "ssrf"). Human-readable names like "SQL Injection" are also accepted.')
                ->required(),
        ];
    }

    /**
     * Handle the tool request.
     */
    public function handle(Request $request): Response|ResponseFactory
    {
        $rawType = $request->get('type');

        if (! is_string($rawType) || trim($rawType) === '') {
            return Response::error(
                'You must provide a vulnerability "type", for example "sql_injection", "idor", or "mass_assignment".'
            );
        }

        try {
            $type = VulnerabilityType::fromString($rawType);
        } catch (ValueError) {
            $known = implode(', ', array_map(
                static fn (VulnerabilityType $case): string => $case->value,
                VulnerabilityType::cases(),
            ));

            return Response::error(
                "Unknown vulnerability type \"{$rawType}\". Known types are: {$known}."
            );
        }

        $structured = [
            'type' => $type->value,
            'label' => $type->label(),
            'description' => $type->description(),
            'owasp' => $type->owaspCategory(),
            'cwe' => $type->cweId(),
        ];

        $text = sprintf(
            "%s (%s)\n\n%s\n\nOWASP: %s\nCWE: %s",
            $type->label(),
            $type->value,
            $type->description(),
            $type->owaspCategory(),
            $type->cweId(),
        );

        return Response::make(Response::text($text))
            ->withStructuredContent($structured);
    }
}
