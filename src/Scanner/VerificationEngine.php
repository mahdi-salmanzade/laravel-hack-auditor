<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner;

use Illuminate\Support\Facades\Log;
use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\AI\ResponseParser;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\UsageTracker;
use Throwable;

/**
 * Second-pass AI engine that tries to construct a concrete exploit for each
 * HIGH/CRITICAL finding. Findings with a working exploit are retained with a
 * verified flag; findings the model cannot exploit are downgraded one tier.
 * Technical failures (AI throws, malformed JSON) leave the finding untouched.
 */
final class VerificationEngine
{
    public function __construct(
        private readonly AIAdapter $ai,
        private readonly PromptBuilder $prompts,
        private readonly ResponseParser $parser,
    ) {}

    /**
     * Run exploit verification for a single finding.
     *
     * Non-HIGH+ findings short-circuit and are returned unchanged. The usage
     * tracker accumulates verification-bucket tokens per call so the scan
     * command can distinguish pass-1 from pass-2 cost.
     */
    public function verify(Vulnerability $vuln, string $fileContents, UsageTracker $usage): Vulnerability
    {
        if (! $this->isInScope($vuln)) {
            return $vuln;
        }

        try {
            $result = $this->ai->sendWithUsage(
                $this->prompts->verificationSystemPrompt(),
                $this->prompts->buildVerificationPrompt($vuln, $fileContents),
            );
        } catch (Throwable $e) {
            Log::warning('[HackAuditor] Verification AI call failed; leaving finding unchanged', [
                'location' => $vuln->location,
                'line' => $vuln->line,
                'error' => $e->getMessage(),
            ]);

            return $vuln;
        }

        $usage->recordVerification(
            $result['usage']['prompt_tokens'],
            $result['usage']['completion_tokens'],
        );

        try {
            $parsed = $this->parser->parseVerification($result['text']);
        } catch (Throwable $e) {
            Log::warning('[HackAuditor] Verification response unparseable; leaving finding unchanged', [
                'location' => $vuln->location,
                'line' => $vuln->line,
                'error' => $e->getMessage(),
            ]);

            return $vuln;
        }

        if ($parsed['verified'] === true) {
            return $this->markVerified($vuln, $parsed['exploit'] ?? '');
        }

        return $this->markDowngraded($vuln);
    }

    /**
     * Determine whether a finding is eligible for verification.
     *
     * Only Critical and High findings are verified — Medium and Low findings
     * represent defense-in-depth gaps or best-practice violations where
     * "construct an exploit" is not a meaningful prompt.
     */
    private function isInScope(Vulnerability $vuln): bool
    {
        return $vuln->severity === SeverityLevel::Critical
            || $vuln->severity === SeverityLevel::High;
    }

    /**
     * Return a copy of the finding stamped with a successful exploit.
     */
    private function markVerified(Vulnerability $vuln, string $exploit): Vulnerability
    {
        return new Vulnerability(
            type: $vuln->type,
            location: $vuln->location,
            line: $vuln->line,
            severity: $vuln->severity,
            description: $vuln->description,
            proof: $vuln->proof,
            fix: $vuln->fix,
            taintTrace: $vuln->taintTrace,
            exploitVerified: true,
            exploitProof: $exploit,
            originalSeverity: null,
        );
    }

    /**
     * Return a copy of the finding with severity reduced by one tier.
     *
     * Preserves the pre-downgrade severity in originalSeverity so reports can
     * surface the audit trail. Critical becomes High, High becomes Medium.
     */
    private function markDowngraded(Vulnerability $vuln): Vulnerability
    {
        $downgraded = match ($vuln->severity) {
            SeverityLevel::Critical => SeverityLevel::High,
            SeverityLevel::High => SeverityLevel::Medium,
            default => $vuln->severity,
        };

        return new Vulnerability(
            type: $vuln->type,
            location: $vuln->location,
            line: $vuln->line,
            severity: $downgraded,
            description: $vuln->description,
            proof: $vuln->proof,
            fix: $vuln->fix,
            taintTrace: $vuln->taintTrace,
            exploitVerified: false,
            exploitProof: null,
            originalSeverity: $vuln->severity,
        );
    }
}
