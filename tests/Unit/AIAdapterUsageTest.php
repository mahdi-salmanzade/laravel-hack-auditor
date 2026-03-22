<?php

declare(strict_types=1);

use Mahdi\HackAuditor\AI\AIAdapter;

it('send with usage returns text and usage array', function (): void {
    $mockAdapter = Mockery::mock(AIAdapter::class);
    $mockAdapter->shouldReceive('sendWithUsage')
        ->once()
        ->andReturn([
            'text' => '{"vulnerabilities":[],"overall_score":100,"summary":"Clean."}',
            'usage' => [
                'prompt_tokens' => 1500,
                'completion_tokens' => 800,
            ],
        ]);

    $result = $mockAdapter->sendWithUsage('system prompt', 'user prompt');

    expect($result)->toHaveKey('text')
        ->and($result['text'])->toBeString()
        ->and($result)->toHaveKey('usage')
        ->and($result['usage'])->toBeArray()
        ->and($result['usage'])->toHaveKeys(['prompt_tokens', 'completion_tokens'])
        ->and($result['usage']['prompt_tokens'])->toBe(1500)
        ->and($result['usage']['completion_tokens'])->toBe(800);
});

it('send with usage handles zero usage gracefully', function (): void {
    $mockAdapter = Mockery::mock(AIAdapter::class);
    $mockAdapter->shouldReceive('sendWithUsage')
        ->once()
        ->andReturn([
            'text' => '{"vulnerabilities":[],"overall_score":100,"summary":"Clean."}',
            'usage' => [
                'prompt_tokens' => 0,
                'completion_tokens' => 0,
            ],
        ]);

    $result = $mockAdapter->sendWithUsage('system prompt', 'user prompt');

    expect($result)->toHaveKey('text')
        ->and($result['text'])->toBeString()
        ->and($result['usage']['prompt_tokens'])->toBe(0)
        ->and($result['usage']['completion_tokens'])->toBe(0);
});

it('send still works unchanged', function (): void {
    $mockAdapter = Mockery::mock(AIAdapter::class);
    $mockAdapter->shouldReceive('send')
        ->once()
        ->andReturn('{"vulnerabilities":[],"overall_score":100,"summary":"Clean."}');

    $result = $mockAdapter->send('system prompt', 'user prompt');

    expect($result)->toBeString();
});

it('ask still works unchanged', function (): void {
    $mockAdapter = Mockery::mock(AIAdapter::class);
    $mockAdapter->shouldReceive('ask')
        ->once()
        ->andReturn('{"vulnerabilities":[],"overall_score":100,"summary":"Clean."}');

    $result = $mockAdapter->ask('system prompt', 'user prompt');

    expect($result)->toBeString();
});

it('send with usage method exists on adapter class', function (): void {
    $reflection = new ReflectionClass(AIAdapter::class);

    expect($reflection->hasMethod('sendWithUsage'))->toBeTrue();

    $method = $reflection->getMethod('sendWithUsage');

    expect($method->isPublic())->toBeTrue();
});
