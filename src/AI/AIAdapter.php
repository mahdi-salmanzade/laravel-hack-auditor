<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\AI;

use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Log;
use Laravel\Ai\Exceptions\InsufficientCreditsException;
use Laravel\Ai\Exceptions\RateLimitedException;
use Mahdi\HackAuditor\Support\AiProviders;
use RuntimeException;

class AIAdapter
{
    private readonly ?string $provider;

    private readonly ?string $model;

    /**
     * Null when the configured model rejects sampling parameters, which omits
     * temperature from the request entirely.
     */
    private readonly ?float $temperature;

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

        // Anthropic removed the sampling parameters from Claude Opus 4.7 onward;
        // sending temperature to Opus 4.7/4.8, Opus 5, Sonnet 5 or Fable 5 returns
        // HTTP 400 and fails the scan. Omit it rather than break those models.
        $this->temperature = AiProviders::supportsSamplingParams($provider, $model)
            ? $temperature
            : null;

        $this->maxTokens = $maxTokens;
        $this->timeout = $timeout;
    }

    /**
     * The temperature that will be transmitted, or null when the configured
     * model rejects sampling parameters.
     */
    public function temperature(): ?float
    {
        return $this->temperature;
    }

    /**
     * Send a prompt to the AI provider and return the text response.
     *
     * @throws RuntimeException When all retry attempts are exhausted, or on the
     *                          first non-retryable error.
     */
    public function send(string $systemPrompt, string $userPrompt): string
    {
        return $this->sendWithUsage($systemPrompt, $userPrompt)['text'];
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
     * Transient failures (rate limits, overloaded or unreachable providers,
     * 5xx) are retried with backoff. Errors that no retry can fix — a rejected
     * API key, an unknown model, a malformed request, exhausted credits — fail
     * on the first attempt: retrying them used to burn 30 seconds per chunk
     * before reporting the same error.
     *
     * @return array{text: string, usage: array{prompt_tokens: int, completion_tokens: int}}
     *
     * @throws RuntimeException When all retry attempts are exhausted, or on the
     *                          first non-retryable error.
     */
    public function sendWithUsage(string $systemPrompt, string $userPrompt): array
    {
        $lastException = null;

        for ($attempt = 1; $attempt <= self::MAX_RETRIES; $attempt++) {
            try {
                $this->logRequest($systemPrompt, $userPrompt, $attempt);

                $response = $this->buildAgent($systemPrompt)->prompt(
                    prompt: $userPrompt,
                    provider: $this->provider,
                    model: $this->model,
                    timeout: $this->timeout,
                );

                $text = $response->text;
                $this->logResponse($text, $attempt);

                return [
                    'text' => $text,
                    'usage' => self::extractUsage($response->usage ?? null),
                ];
            } catch (\Throwable $e) {
                $lastException = $e;

                if (! self::isRetryable($e)) {
                    $this->logRetry(self::MAX_RETRIES, $e);

                    throw new RuntimeException(
                        "AI request failed with a non-retryable error: {$e->getMessage()}",
                        previous: $e,
                    );
                }

                $this->logRetry($attempt, $e);

                if ($attempt < self::MAX_RETRIES) {
                    sleep($this->calculateBackoff($attempt, $e));
                }
            }
        }

        throw new RuntimeException(
            'AI request failed after '.self::MAX_RETRIES." attempts: {$lastException->getMessage()}",
            previous: $lastException,
        );
    }

    /**
     * Read token counts from a laravel/ai usage object, whichever SDK major produced it.
     *
     * laravel/ai 0.x names them promptTokens/completionTokens; 1.x renamed them
     * to inputTokens/outputTokens. Reading only the old names silently recorded
     * every 1.x scan as zero tokens and $0, which also disabled --limit.
     *
     * @return array{prompt_tokens: int, completion_tokens: int}
     */
    public static function extractUsage(?object $usage): array
    {
        if ($usage === null) {
            return ['prompt_tokens' => 0, 'completion_tokens' => 0];
        }

        $read = static function (object $usage, string ...$properties): int {
            foreach ($properties as $property) {
                if (isset($usage->{$property}) && is_numeric($usage->{$property})) {
                    return (int) $usage->{$property};
                }
            }

            return 0;
        };

        return [
            'prompt_tokens' => $read($usage, 'inputTokens', 'promptTokens'),
            'completion_tokens' => $read($usage, 'outputTokens', 'completionTokens'),
        ];
    }

    /**
     * Whether retrying could plausibly change the outcome of a failed request.
     *
     * Walks the exception chain so a provider HTTP error is classified by its
     * status code whichever wrapper laravel/ai put around it. Anything without
     * a status (timeouts, connection resets, unexpected SDK errors) is retried.
     */
    public static function isRetryable(\Throwable $exception): bool
    {
        for ($current = $exception; $current !== null; $current = $current->getPrevious()) {
            if ($current instanceof InsufficientCreditsException) {
                return false;
            }

            if ($current instanceof RequestException) {
                $status = $current->response->status();

                return $status === 408 || $status === 409 || $status === 429 || $status >= 500;
            }
        }

        return true;
    }

    /**
     * Build a scan agent carrying the configured generation options.
     *
     * laravel/ai resolves these from the agent's temperature() / maxTokens()
     * methods, so the configured values reach the provider on every request
     * rather than falling back to its defaults. A null temperature is omitted
     * from the request entirely.
     */
    private function buildAgent(string $systemPrompt): ScannerAgent
    {
        return new ScannerAgent(
            instructions: $systemPrompt,
            temperature: $this->temperature,
            maxTokens: $this->maxTokens,
        );
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

        $isRateLimit = $exception instanceof RateLimitedException
            || str_contains($message, 'rate limit')
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
