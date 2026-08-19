<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Support\AiProviders;

it('pricing returns correct rates for anthropic sonnet', function (): void {
    $pricing = AiProviders::pricing('anthropic', 'claude-sonnet-4-6');

    expect($pricing)->not->toBeNull()
        ->and($pricing['input'])->toBe(3.00)
        ->and($pricing['output'])->toBe(15.00);
});

it('pricing returns correct rates for anthropic opus 4.8 flagship', function (): void {
    $pricing = AiProviders::pricing('anthropic', 'claude-opus-4-8');

    expect($pricing)->not->toBeNull()
        ->and($pricing['input'])->toBe(5.00)
        ->and($pricing['output'])->toBe(25.00);
});

it('opus 4.8 is recognized as a known model', function (): void {
    expect(AiProviders::isKnownModel('claude-opus-4-8'))->toBeTrue();
});

it('recommended for scanning returns the opus 5 flagship for anthropic', function (): void {
    expect(AiProviders::recommendedForScanning('anthropic'))->toBe('claude-opus-5');
});

it('prices the current anthropic flagship and balanced models', function (): void {
    expect(AiProviders::pricing('anthropic', 'claude-opus-5'))
        ->toBe(['input' => 5.00, 'output' => 25.00])
        ->and(AiProviders::pricing('anthropic', 'claude-fable-5'))
        ->toBe(['input' => 10.00, 'output' => 50.00])
        ->and(AiProviders::pricing('anthropic', 'claude-sonnet-5'))
        ->toBe(['input' => 3.00, 'output' => 15.00]);
});

it('reports sampling support per model', function (string $model, bool $supported): void {
    expect(AiProviders::supportsSamplingParams('anthropic', $model))->toBe($supported);
})->with([
    // Anthropic removed temperature/top_p/top_k from Opus 4.7 onward.
    ['claude-opus-5', false],
    ['claude-fable-5', false],
    ['claude-opus-4-8', false],
    ['claude-opus-4-7', false],
    ['claude-sonnet-5', false],
    // Still accepted here.
    ['claude-opus-4-6', true],
    ['claude-sonnet-4-6', true],
    ['claude-haiku-4-5', true],
]);

it('assumes sampling support for unknown or unpinned models', function (): void {
    expect(AiProviders::supportsSamplingParams('anthropic', null))->toBeTrue()
        ->and(AiProviders::supportsSamplingParams(null, null))->toBeTrue()
        ->and(AiProviders::supportsSamplingParams('openai', 'gpt-4o'))->toBeTrue()
        ->and(AiProviders::supportsSamplingParams(null, 'some-unreleased-model'))->toBeTrue();
});

it('resolves sampling support without a provider hint', function (): void {
    expect(AiProviders::supportsSamplingParams(null, 'claude-opus-5'))->toBeFalse();
});

it('pricing returns correct rates for openai gpt4o', function (): void {
    $pricing = AiProviders::pricing('openai', 'gpt-4o');

    expect($pricing)->not->toBeNull()
        ->and($pricing['input'])->toBe(2.50)
        ->and($pricing['output'])->toBe(10.00);
});

it('pricing returns correct rates for gemini flash', function (): void {
    $pricing = AiProviders::pricing('gemini', 'gemini-2.5-flash');

    expect($pricing)->not->toBeNull()
        ->and($pricing['input'])->toBe(0.15)
        ->and($pricing['output'])->toBe(0.60);
});

it('pricing returns correct rates for xai grok', function (): void {
    $pricing = AiProviders::pricing('xai', 'grok-3');

    expect($pricing)->not->toBeNull()
        ->and($pricing['input'])->toBe(3.00)
        ->and($pricing['output'])->toBe(15.00);
});

it('pricing returns null for unknown model', function (): void {
    $pricing = AiProviders::pricing('anthropic', 'totally-fake-model');

    expect($pricing)->toBeNull();
});

it('pricing fuzzy matches dated model ids', function (): void {
    $pricing = AiProviders::pricing('anthropic', 'claude-sonnet-4-5-20250514');

    expect($pricing)->not->toBeNull()
        ->and($pricing['input'])->toBe(3.00)
        ->and($pricing['output'])->toBe(15.00);
});

it('pricing fuzzy matches across providers', function (): void {
    $pricing = AiProviders::pricing('unknown', 'gpt-4o');

    expect($pricing)->not->toBeNull()
        ->and($pricing['input'])->toBe(2.50);
});

it('ollama models are free', function (): void {
    $pricing = AiProviders::pricing('ollama', 'llama3.1');

    expect($pricing)->not->toBeNull()
        ->and($pricing['input'])->toBe(0.00)
        ->and($pricing['output'])->toBe(0.00);
});

it('detect provider from env finds anthropic', function (): void {
    $original = getenv('ANTHROPIC_API_KEY');
    putenv('ANTHROPIC_API_KEY=test-key');

    $provider = AiProviders::detectProviderFromEnv();

    expect($provider)->toBe('anthropic');

    putenv($original !== false ? "ANTHROPIC_API_KEY={$original}" : 'ANTHROPIC_API_KEY');
});

it('detect provider from env finds openai', function (): void {
    $original = getenv('OPENAI_API_KEY');
    putenv('OPENAI_API_KEY=test-key');

    $provider = AiProviders::detectProviderFromEnv();

    expect($provider)->toBe('openai');

    putenv($original !== false ? "OPENAI_API_KEY={$original}" : 'OPENAI_API_KEY');
});

it('detect provider from env returns null when no keys', function (): void {
    $keys = [
        'ANTHROPIC_API_KEY' => getenv('ANTHROPIC_API_KEY'),
        'OPENAI_API_KEY' => getenv('OPENAI_API_KEY'),
        'GEMINI_API_KEY' => getenv('GEMINI_API_KEY'),
        'XAI_API_KEY' => getenv('XAI_API_KEY'),
    ];

    foreach ($keys as $key => $value) {
        putenv($key);
    }

    $provider = AiProviders::detectProviderFromEnv();

    expect($provider)->toBeNull();

    foreach ($keys as $key => $value) {
        putenv($value !== false ? "{$key}={$value}" : $key);
    }
});

it('default model returns balanced tier', function (): void {
    $model = AiProviders::defaultModel('anthropic');

    expect($model)->toBeString()->not->toBeEmpty();
});

it('recommended for scanning returns flagship or balanced', function (): void {
    $modelId = AiProviders::recommendedForScanning('anthropic');

    expect($modelId)->toBeString()->not->toBeEmpty();

    $models = AiProviders::models('anthropic');
    $model = $models[$modelId] ?? null;

    expect($model)->not->toBeNull()
        ->and($model['tier'])->toBeIn(['flagship', 'balanced']);
});

it('models returns all models for provider', function (): void {
    $models = AiProviders::models('anthropic');

    expect($models)->toBeArray()->not->toBeEmpty()
        ->and($models)->toHaveKey('claude-sonnet-4-6');
});

it('providers returns all provider keys', function (): void {
    $providers = AiProviders::providers();

    expect($providers)->toContain('anthropic')
        ->and($providers)->toContain('openai')
        ->and($providers)->toContain('gemini')
        ->and($providers)->toContain('xai')
        ->and($providers)->toContain('ollama');
});

it('is known model returns true for valid', function (): void {
    expect(AiProviders::isKnownModel('gpt-4o'))->toBeTrue();
});

it('is known model returns false for unknown', function (): void {
    expect(AiProviders::isKnownModel('fake-model'))->toBeFalse();
});

it('context window returns correct size', function (): void {
    $contextWindow = AiProviders::contextWindow('anthropic', 'claude-opus-4-6');

    expect($contextWindow)->toBe(1000000);
});

it('detect pricing uses hack auditor config first', function (): void {
    config()->set('hack-auditor.ai.provider', 'anthropic');
    config()->set('hack-auditor.ai.model', 'claude-sonnet-4-6');

    $result = AiProviders::detectPricing();

    expect($result)->toBeArray()
        ->and($result['source'])->toContain('hack-auditor');
});

it('detect pricing falls back to defaults', function (): void {
    config()->set('hack-auditor.ai.provider', null);
    config()->set('hack-auditor.ai.model', null);

    $result = AiProviders::detectPricing();

    expect($result)->toBeArray()
        ->and($result['source'])->toContain('default')
        ->and($result['input'])->toBeFloat()
        ->and($result['output'])->toBeFloat();
});

it('registry returns full structure', function (): void {
    $registry = AiProviders::registry();

    expect($registry)->toBeArray()->not->toBeEmpty()
        ->and($registry)->toHaveKey('anthropic')
        ->and($registry['anthropic'])->toHaveKey('models');
});
