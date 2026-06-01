<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Mcp\Support;

use Laravel\Mcp\Response;
use Laravel\Mcp\ResponseFactory;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;

/**
 * Formats a VulnerabilityReport into an MCP tool response.
 *
 * Produces a human-readable text summary alongside machine-parseable
 * structured content so calling AI agents receive both a readable digest
 * and a typed findings array.
 */
final class FindingFormatter
{
    /**
     * Build an MCP response from a vulnerability report.
     */
    public static function report(VulnerabilityReport $report, string $scope): ResponseFactory
    {
        $findings = array_map(
            static fn (Vulnerability $vulnerability): array => self::finding($vulnerability),
            $report->vulnerabilities,
        );

        $structured = [
            'scope' => $scope,
            'overall_score' => $report->overallScore,
            'summary' => $report->summary,
            'counts' => [
                'critical' => $report->criticalCount(),
                'high' => $report->highCount(),
                'medium' => $report->mediumCount(),
                'low' => $report->lowCount(),
                'total' => $report->totalCount(),
            ],
            'findings' => $findings,
        ];

        return Response::make(Response::text(self::summaryText($report, $scope)))
            ->withStructuredContent($structured);
    }

    /**
     * Reduce a vulnerability to the fields an AI agent needs to act.
     *
     * @return array<string, mixed>
     */
    private static function finding(Vulnerability $vulnerability): array
    {
        return [
            'type' => $vulnerability->type->value,
            'type_label' => $vulnerability->type->label(),
            'severity' => $vulnerability->severity->value,
            'file' => $vulnerability->location,
            'line' => $vulnerability->line,
            'owasp' => $vulnerability->type->owaspCategory(),
            'cwe' => $vulnerability->type->cweId(),
            'description' => $vulnerability->description,
            'proof' => $vulnerability->proof,
            'fix' => $vulnerability->fix,
        ];
    }

    /**
     * Render a concise human-readable digest of the report.
     */
    private static function summaryText(VulnerabilityReport $report, string $scope): string
    {
        $lines = [
            "Security scan of {$scope}",
            "Score: {$report->overallScore}/100",
            sprintf(
                'Findings: %d (critical %d, high %d, medium %d, low %d)',
                $report->totalCount(),
                $report->criticalCount(),
                $report->highCount(),
                $report->mediumCount(),
                $report->lowCount(),
            ),
        ];

        if ($report->summary !== '') {
            $lines[] = '';
            $lines[] = $report->summary;
        }

        foreach ($report->vulnerabilities as $vulnerability) {
            $lines[] = '';
            $lines[] = sprintf(
                '[%s] %s — %s:%d',
                strtoupper($vulnerability->severity->value),
                $vulnerability->type->label(),
                $vulnerability->location,
                $vulnerability->line,
            );
            $lines[] = $vulnerability->description;
            $lines[] = 'Fix: '.$vulnerability->fix;
        }

        return implode("\n", $lines);
    }
}
