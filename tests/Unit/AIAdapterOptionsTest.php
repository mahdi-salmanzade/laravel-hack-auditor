<?php

declare(strict_types=1);

use Laravel\Ai\Gateway\TextGenerationOptions;
use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\ScannerAgent;

it('transmits configured temperature and max tokens through TextGenerationOptions', function (): void {
    $agent = ScannerAgent::for(
        instructions: 'system prompt',
        temperature: 0.3,
        maxTokens: 4096,
    );

    $options = TextGenerationOptions::forAgent($agent);

    expect($options->temperature)->toBe(0.3)
        ->and($options->maxTokens)->toBe(4096);
});

it('transmits non-default temperature and max tokens overrides', function (): void {
    $agent = ScannerAgent::for(
        instructions: 'system prompt',
        temperature: 0.85,
        maxTokens: 16000,
    );

    $options = TextGenerationOptions::forAgent($agent);

    expect($options->temperature)->toBe(0.85)
        ->and($options->maxTokens)->toBe(16000);
});

it('reuses the same synthesised class for identical option pairs', function (): void {
    $first = ScannerAgent::resolveClassFor(0.4, 2048);
    $second = ScannerAgent::resolveClassFor(0.4, 2048);

    expect($first)->toBe($second);
});

it('produces distinct synthesised classes for different option pairs', function (): void {
    $a = ScannerAgent::resolveClassFor(0.2, 1024);
    $b = ScannerAgent::resolveClassFor(0.9, 8192);

    expect($a)->not->toBe($b);
});

it('preserves the supplied instructions on the synthesised agent', function (): void {
    $agent = ScannerAgent::for(
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

    $agent = ScannerAgent::for(
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

    $adapter = new AIAdapter;

    $method = new ReflectionMethod($adapter, 'buildAgent');
    $agent = $method->invoke($adapter, 'system prompt for scan');

    $options = TextGenerationOptions::forAgent($agent);

    expect($agent)->toBeInstanceOf(ScannerAgent::class)
        ->and($agent->instructions())->toBe('system prompt for scan')
        ->and($options->temperature)->toBe(0.42)
        ->and($options->maxTokens)->toBe(9000);
});
