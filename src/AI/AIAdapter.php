<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\AI;

use Illuminate\Support\Facades\Log;
use Laravel\Ai\AnonymousAgent;
use RuntimeException;

class AIAdapter
{
    private readonly ?string $provider;

    private readonly ?string $model;

    private readonly float $temperature;

    private readonly int $maxTokens;

    private readonly int $timeout;

    private const int MAX_RETRIES = 5;

    /**
     * Create a new AIAdapter instance, reading configuration from hack-auditor config.
     */
    public function __construct()
    {
        /** @var ?string $provider */
        $provider = config('hack-auditor.ai.provider');

        /** @var ?string $model */
        $model = config('hack-auditor.ai.model');

        /** @var float $temperature */
        $temperature = (float) config('hack-auditor.ai.temperature', 0.3);

        /** @var int $maxTokens */
        $maxTokens = (int) config('hack-auditor.ai.max_tokens', 4096);

        /** @var int $timeout */
        $timeout = (int) config('hack-auditor.ai.timeout', 120);

        $this->provider = $provider;
        $this->model = $model;
        $this->temperature = $temperature;
        $this->maxTokens = $maxTokens;
        $this->timeout = $timeout;
    }

    /**
     * Send a prompt to the AI provider and return the text response.
     *
     * Implements retry logic with exponential backoff (1s, 2s, 4s) for up to
     * 3 attempts. Logs request/response details when app.debug is enabled.
     *
     * @throws RuntimeException When all retry attempts are exhausted.
     */
    public function send(string $systemPrompt, string $userPrompt): string
    {
        $lastException = null;

        for ($attempt = 1; $attempt <= self::MAX_RETRIES; $attempt++) {
            try {
                $this->logRequest($systemPrompt, $userPrompt, $attempt);

                $response = $this->executeRequest($systemPrompt, $userPrompt);

                $this->logResponse($response, $attempt);

                return $response;
            } catch (\Throwable $e) {
                $lastException = $e;

                $this->logRetry($attempt, $e);

                if ($attempt < self::MAX_RETRIES) {
                    $delaySeconds = $this->calculateBackoff($attempt, $e);
                    sleep($delaySeconds);
                }
            }
        }

        throw new RuntimeException(
            'AI request failed after '.self::MAX_RETRIES." attempts: {$lastException?->getMessage()}",
            previous: $lastException,
        );
    }

    /**
     * Alias for send() used by the CTF generator.
     *
     * @throws RuntimeException When all retry attempts are exhausted.
     */
    public function ask(string $systemPrompt, string $userPrompt): string
    {
        return $this->send($systemPrompt, $userPrompt);
    }

    /**
     * Send a prompt and return both the response text and token usage.
     *
     * Same retry logic as send(), but also extracts prompt_tokens and
     * completion_tokens from the AI response's usage object.
     *
     * @return array{text: string, usage: array{prompt_tokens: int, completion_tokens: int}}
     *
     * @throws RuntimeException When all retry attempts are exhausted.
     */
    public function sendWithUsage(string $systemPrompt, string $userPrompt): array
    {
        $lastException = null;

        for ($attempt = 1; $attempt <= self::MAX_RETRIES; $attempt++) {
            try {
                $this->logRequest($systemPrompt, $userPrompt, $attempt);

                $agent = new AnonymousAgent(
                    instructions: $systemPrompt,
                    messages: [],
                    tools: [],
                );

                $response = $agent->prompt(
                    prompt: $userPrompt,
                    provider: $this->provider,
                    model: $this->model,
                    timeout: $this->timeout,
                );

                $text = $response->text;
                $this->logResponse($text, $attempt);

                $promptTokens = 0;
                $completionTokens = 0;

                if (isset($response->usage)) {
                    $promptTokens = $response->usage->promptTokens ?? 0;
                    $completionTokens = $response->usage->completionTokens ?? 0;
                }

                return [
                    'text' => $text,
                    'usage' => [
                        'prompt_tokens' => $promptTokens,
                        'completion_tokens' => $completionTokens,
                    ],
                ];
            } catch (\Throwable $e) {
                $lastException = $e;
                $this->logRetry($attempt, $e);

                if ($attempt < self::MAX_RETRIES) {
                    $delaySeconds = $this->calculateBackoff($attempt, $e);
                    sleep($delaySeconds);
                }
            }
        }

        throw new RuntimeException(
            'AI request failed after '.self::MAX_RETRIES." attempts: {$lastException?->getMessage()}",
            previous: $lastException,
        );
    }

    /**
     * Execute the AI request using the laravel/ai SDK.
     *
     * Uses AnonymousAgent with the Promptable trait to send the system prompt
     * as agent instructions and the user prompt as the prompt message.
     * The response text is extracted from the AgentResponse.
     */
    private function executeRequest(string $systemPrompt, string $userPrompt): string
    {
        $agent = new AnonymousAgent(
            instructions: $systemPrompt,
            messages: [],
            tools: [],
        );

        $response = $agent->prompt(
            prompt: $userPrompt,
            provider: $this->provider,
            model: $this->model,
            timeout: $this->timeout,
        );

        return $response->text;
    }

    /**
     * Log the outgoing request details when debug mode is enabled.
     */
    private function logRequest(string $systemPrompt, string $userPrompt, int $attempt): void
    {
        if (! config('app.debug')) {
            return;
        }

        Log::debug('[HackAuditor] AI request', [
            'attempt' => $attempt,
            'provider' => $this->provider ?? 'default',
            'model' => $this->model ?? 'default',
            'temperature' => $this->temperature,
            'max_tokens' => $this->maxTokens,
            'system_prompt_length' => strlen($systemPrompt),
            'user_prompt_length' => strlen($userPrompt),
        ]);
    }

    /**
     * Log the received response when debug mode is enabled.
     */
    private function logResponse(string $response, int $attempt): void
    {
        if (! config('app.debug')) {
            return;
        }

        Log::debug('[HackAuditor] AI response received', [
            'attempt' => $attempt,
            'response_length' => strlen($response),
            'response_preview' => mb_substr($response, 0, 500),
        ]);
    }

    /**
     * Calculate backoff delay based on attempt number and error type.
     *
     * Rate limit errors get much longer delays (15s, 30s, 60s, 120s)
     * to respect the provider's limits. Other errors use standard
     * exponential backoff (2s, 4s, 8s, 16s).
     */
    private function calculateBackoff(int $attempt, \Throwable $exception): int
    {
        $message = strtolower($exception->getMessage());

        $isRateLimit = str_contains($message, 'rate limit')
            || str_contains($message, 'rate_limit')
            || str_contains($message, 'too many requests')
            || str_contains($message, '429');

        if ($isRateLimit) {
            return min(120, 15 * (int) pow(2, $attempt - 1));
        }

        return (int) pow(2, $attempt);
    }

    /**
     * Log a retry attempt when a request fails.
     */
    private function logRetry(int $attempt, \Throwable $exception): void
    {
        if ($attempt >= self::MAX_RETRIES) {
            Log::error('[HackAuditor] AI request failed on final attempt', [
                'attempt' => $attempt,
                'error' => $exception->getMessage(),
            ]);

            return;
        }

        $delaySeconds = $this->calculateBackoff($attempt, $exception);

        Log::warning('[HackAuditor] AI request failed, retrying', [
            'attempt' => $attempt,
            'next_attempt' => $attempt + 1,
            'delay_seconds' => $delaySeconds,
            'error' => $exception->getMessage(),
        ]);
    }
}
