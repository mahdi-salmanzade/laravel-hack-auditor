<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\AI;

use Laravel\Ai\Attributes\MaxTokens;
use Laravel\Ai\Attributes\Temperature;
use Laravel\Ai\Contracts\Agent;
use Laravel\Ai\Contracts\Conversational;
use Laravel\Ai\Contracts\HasTools;
use Laravel\Ai\Gateway\TextGenerationOptions;
use Laravel\Ai\Promptable;

/**
 * Agent used for security scans.
 *
 * laravel/ai 0.3.x resolves generation temperature and max tokens exclusively
 * from class-level {@see Temperature} / {@see MaxTokens} attributes via
 * reflection in {@see TextGenerationOptions::forAgent()}.
 * There is no instance-method or runtime hook for these two values, so the
 * configured temperature and max tokens would be silently ignored on a bare
 * AnonymousAgent and the scan would run at the provider's defaults.
 *
 * Because attribute arguments are constant expressions, they cannot read
 * config directly. To make the configured values reach the provider on every
 * scan, {@see self::for()} synthesises (and caches) a concrete subclass per
 * temperature/max-tokens pair whose attributes carry the configured values,
 * which the SDK then reflects and forwards to the provider request.
 */
#[Temperature(0.3)]
#[MaxTokens(4096)]
class ScannerAgent implements Agent, Conversational, HasTools
{
    use Promptable;

    /**
     * @var array<string, class-string<self>>
     */
    private static array $synthesised = [];

    public function __construct(
        public string $instructions,
        public iterable $messages = [],
        public iterable $tools = [],
    ) {}

    /**
     * Build a ScannerAgent whose Temperature / MaxTokens attributes carry the
     * given configured values so they reach the provider on every prompt.
     */
    public static function for(
        string $instructions,
        float $temperature,
        int $maxTokens,
    ): self {
        $class = self::resolveClassFor($temperature, $maxTokens);

        return new $class(instructions: $instructions);
    }

    /**
     * Resolve (synthesising on first use) a ScannerAgent subclass whose
     * class-level attributes encode the given temperature and max tokens.
     *
     * @return class-string<self>
     */
    public static function resolveClassFor(float $temperature, int $maxTokens): string
    {
        $key = $temperature.':'.$maxTokens;

        if (isset(self::$synthesised[$key])) {
            return self::$synthesised[$key];
        }

        $className = 'HackAuditorScannerAgent_'.md5($key);
        $fqcn = __NAMESPACE__.'\\Generated\\'.$className;

        if (! class_exists($fqcn, false)) {
            $temperatureLiteral = var_export($temperature, true);
            $maxTokensLiteral = var_export($maxTokens, true);

            eval(<<<PHP
                namespace Mahdi\\HackAuditor\\AI\\Generated;

                #[\\Laravel\\Ai\\Attributes\\Temperature({$temperatureLiteral})]
                #[\\Laravel\\Ai\\Attributes\\MaxTokens({$maxTokensLiteral})]
                final class {$className} extends \\Mahdi\\HackAuditor\\AI\\ScannerAgent
                {
                }
                PHP);
        }

        return self::$synthesised[$key] = $fqcn;
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
