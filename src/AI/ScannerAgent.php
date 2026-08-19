<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\AI;

use Laravel\Ai\Contracts\Agent;
use Laravel\Ai\Contracts\Conversational;
use Laravel\Ai\Contracts\HasTools;
use Laravel\Ai\Gateway\TextGenerationOptions;
use Laravel\Ai\Promptable;

/**
 * Agent used for security scans.
 *
 * Generation options are exposed as instance methods. Since laravel/ai 0.6.4,
 * {@see TextGenerationOptions::resolve()} calls an agent's `temperature()` /
 * `maxTokens()` method first and only falls back to a class-level attribute
 * when that method returns null. Carrying the values on the instance replaces
 * the eval()-synthesised subclass this class used against laravel/ai 0.3.x,
 * which existed solely because attribute arguments must be constant
 * expressions and so could not read config.
 *
 * Deliberately no #[Temperature] attribute: because resolve() treats a null
 * method return as "fall back to the attribute", an attribute here would
 * re-introduce a temperature on the models that reject one. Returning null
 * from temperature() is the only way to omit the parameter entirely.
 */
class ScannerAgent implements Agent, Conversational, HasTools
{
    use Promptable;

    /**
     * @param  float|null  $temperature  Null omits the parameter from the request —
     *                                   required for models that reject sampling
     *                                   parameters (Claude Opus 4.7+, Sonnet 5, Fable 5).
     */
    public function __construct(
        public string $instructions,
        public ?float $temperature = null,
        public ?int $maxTokens = null,
        public iterable $messages = [],
        public iterable $tools = [],
    ) {}

    /**
     * Generation temperature, or null to omit it from the request.
     */
    public function temperature(): ?float
    {
        return $this->temperature;
    }

    /**
     * Maximum tokens to generate, or null to use the provider default.
     */
    public function maxTokens(): ?int
    {
        return $this->maxTokens;
    }

    public function instructions(): string
    {
        return $this->instructions;
    }

    public function messages(): iterable
    {
        return $this->messages;
    }

    public function tools(): iterable
    {
        return $this->tools;
    }
}
