<?php

declare(strict_types=1);

use Laravel\Ai\Gateway\TextGenerationOptions;
use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\ScannerAgent;

it('transmits configured temperature and max tokens through TextGenerationOptions', function (): void {
    $agent = new ScannerAgent(
        instructions: 'system prompt',
        temperature: 0.3,
        maxTokens: 4096,
    );

    $options = TextGenerationOptions::forAgent($agent);

    expect($options->temperature)->toBe(0.3)
        ->and($options->maxTokens)->toBe(4096);
});

it('transmits non-default temperature and max tokens overrides', function (): void {
    $agent = new ScannerAgent(
        instructions: 'system prompt',
        temperature: 0.85,
        maxTokens: 16000,
    );

    $options = TextGenerationOptions::forAgent($agent);

    expect($options->temperature)->toBe(0.85)
        ->and($options->maxTokens)->toBe(16000);
});

it('omits temperature entirely when the agent carries none', function (): void {
    $agent = new ScannerAgent(
        instructions: 'system prompt',
        temperature: null,
        maxTokens: 4096,
    );

    $options = TextGenerationOptions::forAgent($agent);

    // A null temperature must survive resolution as null. laravel/ai falls back
    // to a class-level #[Temperature] attribute when the method returns null, so
    // this asserts no such attribute has been reintroduced onto ScannerAgent —
    // one would silently restore a 400 on Claude Opus 4.7+.
    expect($options->temperature)->toBeNull()
        ->and($options->maxTokens)->toBe(4096);
});

it('preserves the supplied instructions on the agent', function (): void {
    $agent = new ScannerAgent(
        instructions: 'audit this code for SQL injection',
        temperature: 0.3,
        maxTokens: 4096,
    );

    expect($agent->instructions())->toBe('audit this code for SQL injection')
        ->and($agent)->toBeInstanceOf(ScannerAgent::class);
});

it('drives ScannerAgent options from hack-auditor config via the adapter', function (): void {
    config()->set('hack-auditor.ai.temperature', 0.15);
    config()->set('hack-auditor.ai.max_tokens', 12000);

    $temperature = (float) config('hack-auditor.ai.temperature');
    $maxTokens = (int) config('hack-auditor.ai.max_tokens');

    $agent = new ScannerAgent(
        instructions: 'system prompt',
        temperature: $temperature,
        maxTokens: $maxTokens,
    );

    $options = TextGenerationOptions::forAgent($agent);

    expect($options->temperature)->toBe(0.15)
        ->and($options->maxTokens)->toBe(12000);
});

it('adapter builds a scan agent whose options carry the configured values', function (): void {
    config()->set('hack-auditor.ai.temperature', 0.42);
    config()->set('hack-auditor.ai.max_tokens', 9000);
    config()->set('hack-auditor.ai.provider', 'anthropic');
    config()->set('hack-auditor.ai.model', 'claude-opus-4-6');

    $adapter = new AIAdapter;

    $method = new ReflectionMethod($adapter, 'buildAgent');
    $agent = $method->invoke($adapter, 'system prompt for scan');

    $options = TextGenerationOptions::forAgent($agent);

    expect($agent)->toBeInstanceOf(ScannerAgent::class)
        ->and($agent->instructions())->toBe('system prompt for scan')
        ->and($options->temperature)->toBe(0.42)
        ->and($options->maxTokens)->toBe(9000);
});

it('drops temperature when the configured model rejects sampling parameters', function (): void {
    config()->set('hack-auditor.ai.temperature', 0.42);
    config()->set('hack-auditor.ai.max_tokens', 9000);
    config()->set('hack-auditor.ai.provider', 'anthropic');
    config()->set('hack-auditor.ai.model', 'claude-opus-5');

    $adapter = new AIAdapter;

    $method = new ReflectionMethod($adapter, 'buildAgent');
    $agent = $method->invoke($adapter, 'system prompt for scan');

    $options = TextGenerationOptions::forAgent($agent);

    // Anthropic returns HTTP 400 if temperature is present on Opus 4.7+.
    expect($adapter->temperature())->toBeNull()
        ->and($options->temperature)->toBeNull()
        ->and($options->maxTokens)->toBe(9000);
});

it('keeps temperature for models that still accept sampling parameters', function (): void {
    config()->set('hack-auditor.ai.temperature', 0.42);
    config()->set('hack-auditor.ai.provider', 'anthropic');
    config()->set('hack-auditor.ai.model', 'claude-sonnet-4-6');

    expect((new AIAdapter)->temperature())->toBe(0.42);
});

it('keeps temperature when no model is pinned', function (): void {
    config()->set('hack-auditor.ai.temperature', 0.3);
    config()->set('hack-auditor.ai.provider', null);
    config()->set('hack-auditor.ai.model', null);

    expect((new AIAdapter)->temperature())->toBe(0.3);
});
