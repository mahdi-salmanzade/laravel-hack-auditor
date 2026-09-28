<?php

declare(strict_types=1);

use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\AI\ResponseParser;
use Mahdi\HackAuditor\Scanner\VerificationEngine;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\UsageTracker;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * An engine whose AI adapter answers every verification with `$text`.
 */
function toleranceEngine(string $text): VerificationEngine
{
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('sendWithUsage')->andReturn([
        'text' => $text,
        'usage' => ['prompt_tokens' => 10, 'completion_tokens' => 5],
    ]);

    return new VerificationEngine(ai: $mock, prompts: new PromptBuilder, parser: new ResponseParser);
}

function toleranceHighFinding(): Vulnerability
{
    return new Vulnerability(
        type: VulnerabilityType::SqlInjection,
        location: 'app/Http/Controllers/TestController.php',
        line: 42,
        severity: SeverityLevel::High,
        description: 'Raw SQL interpolation.',
        proof: 'DB::select("... $id")',
        fix: 'Bind it.',
    );
}

it('treats a quoted "false" verdict as not verified rather than verified', function (): void {
    $result = toleranceEngine('{"verified": "false", "exploit": "1 OR 1=1 --", "reasoning": "no"}')
        ->verify(toleranceHighFinding(), '<?php', new UsageTracker);

    expect($result->exploitVerified)->toBeFalse()
        ->and($result->severity)->toBe(SeverityLevel::Medium);
});

it('accepts a quoted "true" verdict with a substantive exploit', function (): void {
    $result = toleranceEngine('{"verified": "true", "exploit": "GET /users?id=1%20OR%201=1", "reasoning": "yes"}')
        ->verify(toleranceHighFinding(), '<?php', new UsageTracker);

    expect($result->exploitVerified)->toBeTrue()
        ->and($result->severity)->toBe(SeverityLevel::High);
});

it('keeps a structured exploit object instead of discarding it as empty', function (): void {
    $result = toleranceEngine('{"verified": true, "exploit": {"request": "GET /users?id=1 OR 1=1"}, "reasoning": "r"}')
        ->verify(toleranceHighFinding(), '<?php', new UsageTracker);

    expect($result->exploitVerified)->toBeTrue()
        ->and($result->exploitProof)->toContain('1 OR 1=1');
});

it('finds the verdict after prose with a stray brace', function (): void {
    $result = toleranceEngine("Looking at the { branch...\n{\"verified\": true, \"exploit\": \"GET /users?id=1 OR 1=1\", \"reasoning\": \"r\"}")
        ->verify(toleranceHighFinding(), '<?php', new UsageTracker);

    expect($result->exploitVerified)->toBeTrue();
});

it('leaves the finding unverified, unchanged, and counted when the verdict is unintelligible', function (string $text): void {
    $engine = toleranceEngine($text);
    $finding = toleranceHighFinding();

    $result = $engine->verify($finding, '<?php', new UsageTracker);

    expect($result)->toBe($finding)
        ->and($result->exploitVerified)->toBeNull()
        ->and($engine->unverifiedCount())->toBe(1);
})->with([
    'not json' => ['I refuse.'],
    'missing verdict' => ['{"exploit": "x", "reasoning": "r"}'],
    'ambiguous verdict' => ['{"verified": "maybe", "exploit": "x"}'],
]);

it('counts an adapter failure as unverified and can be reset', function (): void {
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('sendWithUsage')->andThrow(new RuntimeException('timeout'));
    $engine = new VerificationEngine(ai: $mock, prompts: new PromptBuilder, parser: new ResponseParser);

    $finding = toleranceHighFinding();

    expect($engine->verify($finding, '<?php', new UsageTracker))->toBe($finding)
        ->and($engine->unverifiedCount())->toBe(1);

    $engine->resetUnverifiedCount();

    expect($engine->unverifiedCount())->toBe(0);
});
