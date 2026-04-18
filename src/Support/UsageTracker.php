<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Support;

final class UsageTracker
{
    private int $promptTokens = 0;

    private int $completionTokens = 0;

    private int $requests = 0;

    private int $verificationPromptTokens = 0;

    private int $verificationCompletionTokens = 0;

    private int $verificationRequests = 0;

    private float $startTime;

    private int $tokenLimit;

    private float $inputCostPer1M;

    private float $outputCostPer1M;

    public function __construct(int $tokenLimit = 0)
    {
        $this->tokenLimit = $tokenLimit;
        $this->startTime = microtime(true);
        $this->inputCostPer1M = (float) config('hack-auditor.usage.cost_per_1m_input', 3.00);
        $this->outputCostPer1M = (float) config('hack-auditor.usage.cost_per_1m_output', 15.00);
    }

    /**
     * Create a UsageTracker with cost rates auto-detected from the current AI provider config.
     *
     * Uses AiProviders::detectPricing() to look up real pricing for the configured
     * provider/model instead of using hardcoded default rates.
     */
    public static function forCurrentConfig(int $tokenLimit = 0): self
    {
        $tracker = new self($tokenLimit);

        $pricing = AiProviders::detectPricing();
        $tracker->setCostRates($pricing['input'], $pricing['output']);

        return $tracker;
    }

    /**
     * Set the maximum token budget for the scan.
     */
    public function setTokenLimit(int $limit): void
    {
        $this->tokenLimit = $limit;
    }

    /**
     * Override the default cost rates for input and output tokens.
     */
    public function setCostRates(float $inputPer1M, float $outputPer1M): void
    {
        $this->inputCostPer1M = $inputPer1M;
        $this->outputCostPer1M = $outputPer1M;
    }

    /**
     * Record usage from a single AI response.
     */
    public function record(int $promptTokens, int $completionTokens): void
    {
        $this->promptTokens += $promptTokens;
        $this->completionTokens += $completionTokens;
        $this->requests++;
    }

    /**
     * Record usage from a verification-pass AI response.
     *
     * Tokens are tracked in a separate bucket so pass-1 and verification
     * costs can be distinguished in reports.
     */
    public function recordVerification(int $promptTokens, int $completionTokens): void
    {
        $this->verificationPromptTokens += $promptTokens;
        $this->verificationCompletionTokens += $completionTokens;
        $this->verificationRequests++;
    }

    /**
     * Get the verification-pass prompt (input) tokens.
     */
    public function getVerificationPromptTokens(): int
    {
        return $this->verificationPromptTokens;
    }

    /**
     * Get the verification-pass completion (output) tokens.
     */
    public function getVerificationCompletionTokens(): int
    {
        return $this->verificationCompletionTokens;
    }

    /**
     * Get the number of verification-pass AI requests made.
     */
    public function getVerificationRequests(): int
    {
        return $this->verificationRequests;
    }

    /**
     * Check if we can afford another request of the estimated size.
     */
    public function canAfford(int $estimatedTokens): bool
    {
        if ($this->tokenLimit === 0) {
            return true;
        }

        return ($this->totalTokens() + $estimatedTokens) <= $this->tokenLimit;
    }

    /**
     * Check if additional tokens would exceed the configured limit.
     */
    public function wouldExceedLimit(int $additionalTokens): bool
    {
        return ! $this->canAfford($additionalTokens);
    }

    /**
     * Determine whether a token limit has been configured.
     */
    public function isLimitSet(): bool
    {
        return $this->tokenLimit > 0;
    }

    /**
     * Get the combined total of prompt and completion tokens used (pass-1 + verification).
     */
    public function totalTokens(): int
    {
        return $this->promptTokens
            + $this->completionTokens
            + $this->verificationPromptTokens
            + $this->verificationCompletionTokens;
    }

    /**
     * Get the total number of prompt (input) tokens recorded.
     */
    public function getPromptTokens(): int
    {
        return $this->promptTokens;
    }

    /**
     * Get the total number of completion (output) tokens recorded.
     */
    public function getCompletionTokens(): int
    {
        return $this->completionTokens;
    }

    /**
     * Get the number of AI requests made so far.
     */
    public function getRequests(): int
    {
        return $this->requests;
    }

    /**
     * Get the configured token limit.
     */
    public function getTokenLimit(): int
    {
        return $this->tokenLimit;
    }

    /**
     * Get the number of tokens remaining before hitting the limit.
     *
     * Returns PHP_INT_MAX when no limit is set.
     */
    public function getRemainingTokens(): int
    {
        if ($this->tokenLimit === 0) {
            return PHP_INT_MAX;
        }

        return max(0, $this->tokenLimit - $this->totalTokens());
    }

    /**
     * Get the percentage of the token budget consumed so far.
     *
     * Returns 0.0 when no limit is set.
     */
    public function getUsagePercent(): float
    {
        if ($this->tokenLimit === 0) {
            return 0.0;
        }

        return min(100.0, ($this->totalTokens() / $this->tokenLimit) * 100);
    }

    /**
     * Get the wall-clock seconds elapsed since the tracker was created or last reset.
     */
    public function getElapsedSeconds(): float
    {
        return microtime(true) - $this->startTime;
    }

    /**
     * Estimate the USD cost based on recorded token counts and configured rates.
     *
     * Sums pass-1 and verification buckets so the displayed cost reflects
     * the full scan regardless of whether --verify was used.
     */
    public function estimateCost(): float
    {
        $inputTokens = $this->promptTokens + $this->verificationPromptTokens;
        $outputTokens = $this->completionTokens + $this->verificationCompletionTokens;

        $inputCost = ($inputTokens / 1_000_000) * $this->inputCostPer1M;
        $outputCost = ($outputTokens / 1_000_000) * $this->outputCostPer1M;

        return round($inputCost + $outputCost, 4);
    }

    /**
     * Return the full usage snapshot as an associative array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'prompt_tokens' => $this->promptTokens,
            'completion_tokens' => $this->completionTokens,
            'total_tokens' => $this->totalTokens(),
            'requests' => $this->requests,
            'token_limit' => $this->tokenLimit,
            'remaining_tokens' => $this->tokenLimit > 0 ? $this->getRemainingTokens() : null,
            'usage_percent' => $this->tokenLimit > 0 ? round($this->getUsagePercent(), 1) : null,
            'estimated_cost_usd' => $this->estimateCost(),
            'elapsed_seconds' => round($this->getElapsedSeconds(), 2),
        ];
    }

    /**
     * Reset all counters and restart the elapsed timer.
     */
    public function reset(): void
    {
        $this->promptTokens = 0;
        $this->completionTokens = 0;
        $this->requests = 0;
        $this->verificationPromptTokens = 0;
        $this->verificationCompletionTokens = 0;
        $this->verificationRequests = 0;
        $this->startTime = microtime(true);
    }
}
