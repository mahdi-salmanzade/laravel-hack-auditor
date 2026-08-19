<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Support;

final class AiProviders
{
    // Pricing last verified: 19 August 2026 against platform.claude.com/docs/en/about-claude/models/overview.
    // Rates change — override via config if needed.
    //
    // The optional 'sampling' key marks whether a model accepts the temperature /
    // top_p / top_k sampling parameters. Anthropic removed them from Claude Opus 4.7
    // onward: sending temperature to those models returns HTTP 400. Models without
    // the key are assumed to accept sampling. See self::supportsSamplingParams().
    private const PROVIDERS = [
        'anthropic' => [
            'name' => 'Anthropic',
            'env_key' => 'ANTHROPIC_API_KEY',
            'models' => [
                // NOTE: model IDs are dateless from the Claude 4.6 generation onward —
                // each dateless ID is itself a pinned snapshot, not a moving pointer.
                // Only pre-4.6 models carry dated aliases.
                //
                // NOTE: Opus 4.7+ use a new tokenizer that can consume up to ~35% more
                // tokens for the same text than earlier Claude models. Chunking math is
                // unchanged here — this is a heads-up for cost/context estimation only.
                //
                // Order matters: recommendedForScanning() returns the first non-alias
                // 'flagship' entry and defaultModel() the first non-alias 'balanced' one.
                'claude-opus-5' => [
                    'input' => 5.00,
                    'output' => 25.00,
                    'context' => 1_000_000,
                    'tier' => 'flagship',
                    'sampling' => false,
                ],
                'claude-fable-5' => [
                    'input' => 10.00,
                    'output' => 50.00,
                    'context' => 1_000_000,
                    'tier' => 'flagship',
                    'sampling' => false,
                ],
                'claude-opus-4-8' => [
                    'input' => 5.00,
                    'output' => 25.00,
                    'context' => 1_000_000,
                    'tier' => 'flagship',
                    'sampling' => false,
                ],
                'claude-opus-4-7' => [
                    'input' => 5.00,
                    'output' => 25.00,
                    'context' => 1_000_000,
                    'tier' => 'flagship',
                    'sampling' => false,
                ],
                'claude-opus-4-6' => [
                    'input' => 5.00,
                    'output' => 25.00,
                    'context' => 1_000_000,
                    'tier' => 'flagship',
                ],
                'claude-opus-4-5' => [
                    'input' => 5.00,
                    'output' => 25.00,
                    'context' => 200_000,
                    'tier' => 'flagship',
                ],
                'claude-opus-4-5-20251101' => [
                    'input' => 5.00,
                    'output' => 25.00,
                    'context' => 200_000,
                    'tier' => 'flagship',
                    'alias_of' => 'claude-opus-4-5',
                ],
                // Standard rate. Anthropic ran a $2/$10 introductory rate on Claude
                // Sonnet 5 through 2026-08-31; estimates use the post-intro price so
                // they do not under-report once it lapses.
                'claude-sonnet-5' => [
                    'input' => 3.00,
                    'output' => 15.00,
                    'context' => 1_000_000,
                    'tier' => 'balanced',
                    'sampling' => false,
                ],
                'claude-sonnet-4-6' => [
                    'input' => 3.00,
                    'output' => 15.00,
                    'context' => 1_000_000,
                    'tier' => 'balanced',
                ],
                'claude-sonnet-4-5' => [
                    'input' => 3.00,
                    'output' => 15.00,
                    'context' => 200_000,
                    'tier' => 'balanced',
                ],
                'claude-sonnet-4-5-20250929' => [
                    'input' => 3.00,
                    'output' => 15.00,
                    'context' => 200_000,
                    'tier' => 'balanced',
                    'alias_of' => 'claude-sonnet-4-5',
                ],
                'claude-haiku-4-5' => [
                    'input' => 1.00,
                    'output' => 5.00,
                    'context' => 200_000,
                    'tier' => 'fast',
                ],
                'claude-haiku-4-5-20251001' => [
                    'input' => 1.00,
                    'output' => 5.00,
                    'context' => 200_000,
                    'tier' => 'fast',
                    'alias_of' => 'claude-haiku-4-5',
                ],
            ],
        ],

        'openai' => [
            'name' => 'OpenAI',
            'env_key' => 'OPENAI_API_KEY',
            'models' => [
                'gpt-5.5' => [
                    'input' => 5.00,
                    'output' => 30.00,
                    'context' => 400_000,
                    'tier' => 'flagship',
                ],
                'gpt-4o' => [
                    'input' => 2.50,
                    'output' => 10.00,
                    'context' => 128_000,
                    'tier' => 'balanced',
                ],
                'gpt-4o-mini' => [
                    'input' => 0.15,
                    'output' => 0.60,
                    'context' => 128_000,
                    'tier' => 'budget',
                ],
                'gpt-4.1' => [
                    'input' => 2.00,
                    'output' => 8.00,
                    'context' => 1_000_000,
                    'tier' => 'balanced',
                ],
                'gpt-4.1-mini' => [
                    'input' => 0.40,
                    'output' => 1.60,
                    'context' => 1_000_000,
                    'tier' => 'fast',
                ],
                'gpt-4.1-nano' => [
                    'input' => 0.10,
                    'output' => 0.40,
                    'context' => 1_000_000,
                    'tier' => 'budget',
                ],
                'o3' => [
                    'input' => 2.00,
                    'output' => 8.00,
                    'context' => 200_000,
                    'tier' => 'flagship',
                ],
                'o3-mini' => [
                    'input' => 0.50,
                    'output' => 2.00,
                    'context' => 200_000,
                    'tier' => 'fast',
                ],
                'o4-mini' => [
                    'input' => 0.50,
                    'output' => 2.00,
                    'context' => 200_000,
                    'tier' => 'fast',
                ],
            ],
        ],

        'gemini' => [
            'name' => 'Google Gemini',
            'env_key' => 'GEMINI_API_KEY',
            'models' => [
                'gemini-3.5-flash' => [
                    'input' => 1.50,
                    'output' => 9.00,
                    'context' => 1_000_000,
                    'tier' => 'flagship',
                ],
                'gemini-2.5-pro' => [
                    'input' => 1.25,
                    'output' => 10.00,
                    'context' => 1_000_000,
                    'tier' => 'flagship',
                ],
                'gemini-2.5-flash' => [
                    'input' => 0.15,
                    'output' => 0.60,
                    'context' => 1_000_000,
                    'tier' => 'fast',
                ],
                'gemini-2.0-flash' => [
                    'input' => 0.10,
                    'output' => 0.40,
                    'context' => 1_000_000,
                    'tier' => 'fast',
                ],
                'gemini-1.5-pro' => [
                    'input' => 1.25,
                    'output' => 5.00,
                    'context' => 2_000_000,
                    'tier' => 'balanced',
                ],
                'gemini-1.5-flash' => [
                    'input' => 0.075,
                    'output' => 0.30,
                    'context' => 1_000_000,
                    'tier' => 'budget',
                ],
            ],
        ],

        'xai' => [
            'name' => 'xAI',
            'env_key' => 'XAI_API_KEY',
            'models' => [
                'grok-4.3' => [
                    'input' => 1.25,
                    'output' => 2.50,
                    'context' => 256_000,
                    'tier' => 'flagship',
                ],
                'grok-3' => [
                    'input' => 3.00,
                    'output' => 15.00,
                    'context' => 131_000,
                    'tier' => 'balanced',
                ],
                'grok-3-fast' => [
                    'input' => 5.00,
                    'output' => 25.00,
                    'context' => 131_000,
                    'tier' => 'fast',
                ],
            ],
        ],

        'ollama' => [
            'name' => 'Ollama',
            'env_key' => 'OLLAMA_API_KEY',
            'models' => [
                'llama3.1' => [
                    'input' => 0.00,
                    'output' => 0.00,
                    'context' => 128_000,
                    'tier' => 'balanced',
                ],
                'llama3.2' => [
                    'input' => 0.00,
                    'output' => 0.00,
                    'context' => 128_000,
                    'tier' => 'balanced',
                ],
                'codellama' => [
                    'input' => 0.00,
                    'output' => 0.00,
                    'context' => 16_000,
                    'tier' => 'fast',
                ],
                'mistral' => [
                    'input' => 0.00,
                    'output' => 0.00,
                    'context' => 32_000,
                    'tier' => 'balanced',
                ],
                'deepseek-r1' => [
                    'input' => 0.00,
                    'output' => 0.00,
                    'context' => 64_000,
                    'tier' => 'flagship',
                ],
                'qwen2.5-coder' => [
                    'input' => 0.00,
                    'output' => 0.00,
                    'context' => 32_000,
                    'tier' => 'fast',
                ],
            ],
        ],
    ];

    /**
     * Get pricing for a specific provider and model.
     *
     * Returns input/output cost per 1M tokens, or null if not found.
     * Uses fuzzy matching: direct match first, then str_starts_with both ways,
     * then searches across all providers.
     *
     * @return array{input: float, output: float}|null
     */
    public static function pricing(string $provider, string $model): ?array
    {
        $provider = strtolower($provider);

        $modelInfo = self::resolveModel($provider, $model);

        if ($modelInfo !== null) {
            return [
                'input' => $modelInfo['input'],
                'output' => $modelInfo['output'],
            ];
        }

        return null;
    }

    /**
     * Get full model information for a specific provider and model.
     *
     * @return array{input: float, output: float, context: int, tier: string, sampling?: bool, alias_of?: string}|null
     */
    public static function model(string $provider, string $model): ?array
    {
        $provider = strtolower($provider);

        return self::resolveModel($provider, $model);
    }

    /**
     * Determine whether a model accepts the sampling parameters (temperature,
     * top_p, top_k).
     *
     * Anthropic removed these from Claude Opus 4.7 onward — Opus 4.7/4.8,
     * Opus 5, Sonnet 5 and Fable 5 reject a request carrying temperature with
     * HTTP 400 invalid_request_error. Sending a fixed temperature to one of
     * those models fails every scan, so the scanner omits it instead.
     *
     * Defaults to true: an unknown or unpinned model is assumed to accept
     * sampling, preserving the deterministic low-temperature scan everywhere
     * it is still supported.
     */
    public static function supportsSamplingParams(?string $provider, ?string $model): bool
    {
        if ($model === null || $model === '') {
            return true;
        }

        // An empty provider falls through resolveModel() to its cross-provider search.
        $modelInfo = self::resolveModel(strtolower($provider ?? ''), $model);

        if ($modelInfo === null) {
            return true;
        }

        return $modelInfo['sampling'] ?? true;
    }

    /**
     * Auto-detect pricing from the configuration chain.
     *
     * Checks: hack-auditor config -> laravel/ai config -> env key detection -> defaults.
     *
     * @return array{input: float, output: float, provider: string, model: string, source: string}
     */
    public static function detectPricing(): array
    {
        // 1. Check hack-auditor config
        $provider = config('hack-auditor.ai.provider');
        $model = config('hack-auditor.ai.model');

        if ($provider !== null && $model !== null) {
            $pricing = self::pricing((string) $provider, (string) $model);

            if ($pricing !== null) {
                return [
                    'input' => $pricing['input'],
                    'output' => $pricing['output'],
                    'provider' => (string) $provider,
                    'model' => (string) $model,
                    'source' => 'hack-auditor',
                ];
            }
        }

        // 2. Check laravel/ai config
        $aiProvider = config('ai.default_provider') ?? config('ai.provider');
        $aiModel = config('ai.default_model') ?? config('ai.model');

        if ($aiProvider !== null && $aiModel !== null) {
            $pricing = self::pricing((string) $aiProvider, (string) $aiModel);

            if ($pricing !== null) {
                return [
                    'input' => $pricing['input'],
                    'output' => $pricing['output'],
                    'provider' => (string) $aiProvider,
                    'model' => (string) $aiModel,
                    'source' => 'laravel-ai',
                ];
            }
        }

        // 3. Detect from env key
        $envProvider = self::detectProviderFromEnv();

        if ($envProvider !== null) {
            $defaultModel = self::defaultModel($envProvider);

            if ($defaultModel !== null) {
                $pricing = self::pricing($envProvider, $defaultModel);

                if ($pricing !== null) {
                    return [
                        'input' => $pricing['input'],
                        'output' => $pricing['output'],
                        'provider' => $envProvider,
                        'model' => $defaultModel,
                        'source' => 'env-detection',
                    ];
                }
            }
        }

        // 4. Fallback defaults — mirrors defaultModel('anthropic'), the first
        // non-alias 'balanced' entry in the registry.
        return [
            'input' => 3.00,
            'output' => 15.00,
            'provider' => 'anthropic',
            'model' => 'claude-sonnet-5',
            'source' => 'default',
        ];
    }

    /**
     * Detect which AI provider is configured based on environment variables.
     */
    public static function detectProviderFromEnv(): ?string
    {
        foreach (self::PROVIDERS as $key => $provider) {
            if (env($provider['env_key']) !== null && env($provider['env_key']) !== '') {
                return $key;
            }
        }

        return null;
    }

    /**
     * Get the default model for a provider, preferring the balanced tier.
     */
    public static function defaultModel(string $provider): ?string
    {
        $provider = strtolower($provider);

        if (! isset(self::PROVIDERS[$provider])) {
            return null;
        }

        $models = self::PROVIDERS[$provider]['models'];

        // Prefer balanced tier, skip dated aliases
        foreach ($models as $name => $info) {
            if ($info['tier'] === 'balanced' && ! isset($info['alias_of'])) {
                return $name;
            }
        }

        // Fallback to first non-alias model
        foreach ($models as $name => $info) {
            if (! isset($info['alias_of'])) {
                return $name;
            }
        }

        return null;
    }

    /**
     * Get the recommended model for security scanning, preferring flagship or balanced tiers.
     *
     * Skips dated alias models in favor of their canonical names.
     */
    public static function recommendedForScanning(string $provider): ?string
    {
        $provider = strtolower($provider);

        if (! isset(self::PROVIDERS[$provider])) {
            return null;
        }

        $models = self::PROVIDERS[$provider]['models'];

        // Prefer flagship, skip dated aliases
        foreach ($models as $name => $info) {
            if ($info['tier'] === 'flagship' && ! isset($info['alias_of'])) {
                return $name;
            }
        }

        // Fall back to balanced
        foreach ($models as $name => $info) {
            if ($info['tier'] === 'balanced' && ! isset($info['alias_of'])) {
                return $name;
            }
        }

        return null;
    }

    /**
     * Get all models for a given provider.
     *
     * @return array<string, array{input: float, output: float, context: int, tier: string, alias_of?: string}>
     */
    public static function models(string $provider): array
    {
        $provider = strtolower($provider);

        return self::PROVIDERS[$provider]['models'] ?? [];
    }

    /**
     * Get all registered provider keys.
     *
     * @return list<string>
     */
    public static function providers(): array
    {
        return array_keys(self::PROVIDERS);
    }

    /**
     * Get the display name for a provider.
     */
    public static function providerName(string $provider): ?string
    {
        $provider = strtolower($provider);

        return self::PROVIDERS[$provider]['name'] ?? null;
    }

    /**
     * Get the environment variable key used for a provider's API key.
     */
    public static function envKey(string $provider): ?string
    {
        $provider = strtolower($provider);

        return self::PROVIDERS[$provider]['env_key'] ?? null;
    }

    /**
     * Get the context window size (in tokens) for a specific provider and model.
     */
    public static function contextWindow(string $provider, string $model): ?int
    {
        $info = self::model($provider, $model);

        return $info['context'] ?? null;
    }

    /**
     * Check whether a model name is recognized across any provider.
     */
    public static function isKnownModel(string $model): bool
    {
        foreach (self::PROVIDERS as $provider) {
            if (isset($provider['models'][$model])) {
                return true;
            }

            // Fuzzy: check if any model starts with the given name or vice versa
            foreach (array_keys($provider['models']) as $knownModel) {
                if (str_starts_with($knownModel, $model) || str_starts_with($model, $knownModel)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Get the full provider registry.
     *
     * @return array<string, array{name: string, env_key: string, models: array<string, array{input: float, output: float, context: int, tier: string, alias_of?: string}>}>
     */
    public static function registry(): array
    {
        return self::PROVIDERS;
    }

    /**
     * Resolve a model using fuzzy matching.
     *
     * Tries: direct match, str_starts_with both directions, then cross-provider search.
     *
     * @return array{input: float, output: float, context: int, tier: string, sampling?: bool, alias_of?: string}|null
     */
    private static function resolveModel(string $provider, string $model): ?array
    {
        // Direct match within specified provider
        if (isset(self::PROVIDERS[$provider]['models'][$model])) {
            return self::PROVIDERS[$provider]['models'][$model];
        }

        // Fuzzy match within specified provider: str_starts_with both ways
        if (isset(self::PROVIDERS[$provider])) {
            foreach (self::PROVIDERS[$provider]['models'] as $knownModel => $info) {
                if (str_starts_with($knownModel, $model) || str_starts_with($model, $knownModel)) {
                    return $info;
                }
            }
        }

        // Cross-provider search
        foreach (self::PROVIDERS as $providerData) {
            if (isset($providerData['models'][$model])) {
                return $providerData['models'][$model];
            }

            foreach ($providerData['models'] as $knownModel => $info) {
                if (str_starts_with($knownModel, $model) || str_starts_with($model, $knownModel)) {
                    return $info;
                }
            }
        }

        return null;
    }
}
