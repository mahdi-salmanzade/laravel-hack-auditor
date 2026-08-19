<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Mcp\Support;

use Laravel\Mcp\Response;
use Laravel\Mcp\ResponseFactory;
use Mahdi\HackAuditor\Scanner\ScanCoverage;
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
            $report->confirmedVulnerabilities(),
        );

        $reviewItems = array_map(
            static fn (Vulnerability $vulnerability): array => self::finding($vulnerability),
            $report->reviewItems(),
        );

        $structured = [
            'scope' => $scope,
            // Null rather than a number when coverage cannot support a score.
            // A calling agent that reads "100" for a scan which analysed nothing
            // will confidently tell a human the code is clean.
            'overall_score' => $report->scoreIsMeaningful() ? $report->overallScore : null,
            'score_suppressed' => ! $report->scoreIsMeaningful(),
            'score_suppression_reason' => $report->scoreSuppressionReason(),
            'coverage' => $report->getCoverage()?->toArray(),
            'coverage_statement' => $report->coverageStatement(),
            'summary' => $report->summary,
            'counts' => [
                'critical' => $report->criticalCount(),
                'high' => $report->highCount(),
                'medium' => $report->mediumCount(),
                'low' => $report->lowCount(),
                'total' => $report->totalCount(),
                'review' => $report->reviewCount(),
            ],
            // 'findings' keeps its meaning for existing agents: things the
            // analyzer asserts. Questions are handed over separately and
            // labelled as questions, so an agent cannot "fix" one on a human's
            // behalf believing it was told to.
            'findings' => $findings,
            'review_items' => $reviewItems,
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
            // class says whether this is an assertion or a question; confidence
            // says how much of the evidence chain was actually resolved. An
            // agent that reads severity alone will act on a guess.
            'class' => $vulnerability->findingClass->value,
            'confidence' => $vulnerability->confidence->value,
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
            $report->scoreIsMeaningful()
                ? "Score: {$report->overallScore}/100"
                : 'Score: not available — '.(string) $report->scoreSuppressionReason(),
            sprintf(
                'Confirmed vulnerabilities: %d (critical %d, high %d, medium %d, low %d)',
                $report->totalCount(),
                $report->criticalCount(),
                $report->highCount(),
                $report->mediumCount(),
                $report->lowCount(),
            ),
            sprintf('Needs review: %d (questions, not findings — excluded from the count, the score and the exit code)', $report->reviewCount()),
        ];

        if ($report->totalCount() === 0) {
            $lines[] = 'No confirmed vulnerabilities. '.$report->coverageStatement();
        }

        $coverage = $report->getCoverage();

        if ($coverage !== null && ! $coverage->isComplete()) {
            $lines[] = 'Coverage: '.$coverage->describe();

            foreach ($coverage->skippedByReason() as $reason => $paths) {
                $lines[] = 'Not analyzed ('.ScanCoverage::reasonLabel($reason).'): '.implode(', ', $paths);
            }
        }

        if ($report->summary !== '') {
            $lines[] = '';
            $lines[] = $report->summary;
        }

        $confirmed = $report->confirmedVulnerabilities();

        if ($confirmed !== []) {
            $lines[] = '';
            $lines[] = sprintf('== Confirmed vulnerabilities (%d) ==', count($confirmed));
        }

        foreach ($confirmed as $vulnerability) {
            $lines[] = '';
            $lines[] = sprintf(
                '[%s] %s — %s:%d (confidence: %s)',
                strtoupper($vulnerability->severity->value),
                $vulnerability->type->label(),
                $vulnerability->location,
                $vulnerability->line,
                $vulnerability->confidence->value,
            );
            $lines[] = $vulnerability->description;

            if ($vulnerability->hasFix()) {
                $lines[] = 'Fix: '.$vulnerability->fix;
            }
        }

        $reviewItems = $report->reviewItems();

        if ($reviewItems !== []) {
            $lines[] = '';
            $lines[] = sprintf('== Needs review (%d) ==', count($reviewItems));
            $lines[] = 'These are questions for a human, not findings. No fix is suggested and none should be';
            $lines[] = 'invented: the analyzer could not resolve the evidence that would justify one.';
        }

        foreach ($reviewItems as $item) {
            $lines[] = '';
            $lines[] = sprintf(
                '[REVIEW] %s — %s:%d (impact if real: %s, confidence: %s)',
                $item->type->label(),
                $item->location,
                $item->line,
                strtoupper($item->severity->value),
                $item->confidence->value,
            );
            $lines[] = $item->description;
        }

        return implode("\n", $lines);
    }
}
