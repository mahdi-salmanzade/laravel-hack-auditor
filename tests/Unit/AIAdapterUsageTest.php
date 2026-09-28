<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Client\RequestException;
use Laravel\Ai\Exceptions\InsufficientCreditsException;
use Laravel\Ai\Responses\Data\Usage;
use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\ScannerAgent;

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

it('reads token usage from the laravel/ai 1.x usage shape', function (): void {
    $usage = new Usage(1200, 340);

    expect(AIAdapter::extractUsage($usage))->toBe([
        'prompt_tokens' => 1200,
        'completion_tokens' => 340,
    ]);
});

it('reads token usage from the laravel/ai 0.x usage shape', function (): void {
    // 0.x named the fields promptTokens/completionTokens; 1.x renamed them.
    $usage = new class
    {
        public int $promptTokens = 900;

        public int $completionTokens = 120;
    };

    expect(AIAdapter::extractUsage($usage))->toBe([
        'prompt_tokens' => 900,
        'completion_tokens' => 120,
    ]);
});

it('reports zero usage when the response carries none', function (): void {
    expect(AIAdapter::extractUsage(null))->toBe([
        'prompt_tokens' => 0,
        'completion_tokens' => 0,
    ]);
});

it('records real token usage end to end through the SDK', function (): void {
    ScannerAgent::fake(['{"vulnerabilities":[],"overall_score":100,"summary":"ok"}']);

    $result = (new AIAdapter)->sendWithUsage('system', 'user');

    expect($result['text'])->toContain('vulnerabilities')
        ->and($result['usage'])->toHaveKeys(['prompt_tokens', 'completion_tokens']);
});

function providerError(int $status): RequestException
{
    return new RequestException(
        new Illuminate\Http\Client\Response(new Response($status, [], '{"error":{"message":"x"}}')),
    );
}

it('does not retry errors no retry can fix', function (int $status): void {
    expect(AIAdapter::isRetryable(providerError($status)))->toBeFalse()
        ->and(AIAdapter::isRetryable(new RuntimeException('wrapped', previous: providerError($status))))->toBeFalse();
})->with([400, 401, 403, 404, 422]);

it('retries transient provider errors', function (int $status): void {
    expect(AIAdapter::isRetryable(providerError($status)))->toBeTrue();
})->with([408, 409, 429, 500, 502, 503, 529]);

it('does not retry exhausted credits', function (): void {
    $exception = InsufficientCreditsException::forProvider('anthropic', 402, providerError(402));

    expect(AIAdapter::isRetryable($exception))->toBeFalse();
});

it('retries errors that carry no status code', function (): void {
    expect(AIAdapter::isRetryable(new RuntimeException('connection reset')))->toBeTrue();
});

it('fails on the first attempt for a rejected api key instead of retrying', function (): void {
    $calls = 0;

    ScannerAgent::fake(function () use (&$calls): never {
        $calls++;

        throw providerError(401);
    });

    expect(fn () => (new AIAdapter)->send('system', 'user'))
        ->toThrow(RuntimeException::class, 'non-retryable');

    expect($calls)->toBe(1);
});
