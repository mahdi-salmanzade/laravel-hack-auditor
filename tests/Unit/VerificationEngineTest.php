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

function buildFinding(SeverityLevel $severity, VulnerabilityType $type = VulnerabilityType::SqlInjection): Vulnerability
{
    return new Vulnerability(
        type: $type,
        location: 'app/Http/Controllers/TestController.php',
        line: 42,
        severity: $severity,
        description: 'Raw SQL interpolation flagged by pass 1.',
        proof: 'DB::select("SELECT * FROM users WHERE id = $id")',
        fix: 'Use parameter binding.',
        taintTrace: 'SOURCE: $request->input(\'id\') → TRANSFORMS: none → SINK: DB::select()',
    );
}

function buildEngine(AIAdapter $mock): VerificationEngine
{
    return new VerificationEngine(
        ai: $mock,
        prompts: new PromptBuilder,
        parser: new ResponseParser,
    );
}

function aiResponse(bool $verified, string $exploit = '', string $reasoning = ''): array
{
    return [
        'text' => json_encode([
            'verified' => $verified,
            'exploit' => $exploit,
            'reasoning' => $reasoning,
        ], JSON_THROW_ON_ERROR),
        'usage' => [
            'prompt_tokens' => 500,
            'completion_tokens' => 150,
        ],
    ];
}

it('skips Low findings without calling the AI', function (): void {
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldNotReceive('sendWithUsage');

    $usage = new UsageTracker;
    $result = buildEngine($mock)->verify(buildFinding(SeverityLevel::Low), '<?php // file', $usage);

    expect($result->severity)->toBe(SeverityLevel::Low)
        ->and($result->exploitVerified)->toBeNull()
        ->and($result->originalSeverity)->toBeNull()
        ->and($usage->getVerificationRequests())->toBe(0);
});

it('skips Medium findings without calling the AI', function (): void {
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldNotReceive('sendWithUsage');

    $usage = new UsageTracker;
    $result = buildEngine($mock)->verify(buildFinding(SeverityLevel::Medium), '<?php // file', $usage);

    expect($result->severity)->toBe(SeverityLevel::Medium)
        ->and($result->exploitVerified)->toBeNull();
});

it('retains High severity and captures exploit when model verifies', function (): void {
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('sendWithUsage')
        ->once()
        ->andReturn(aiResponse(
            verified: true,
            exploit: 'GET /users?id=1+UNION+SELECT+password+FROM+users--',
            reasoning: 'Direct interpolation, no mitigations.',
        ));

    $usage = new UsageTracker;
    $result = buildEngine($mock)->verify(buildFinding(SeverityLevel::High), '<?php // file', $usage);

    expect($result->severity)->toBe(SeverityLevel::High)
        ->and($result->exploitVerified)->toBeTrue()
        ->and($result->exploitProof)->toContain('UNION+SELECT')
        ->and($result->originalSeverity)->toBeNull()
        ->and($usage->getVerificationRequests())->toBe(1)
        ->and($usage->getVerificationPromptTokens())->toBe(500)
        ->and($usage->getVerificationCompletionTokens())->toBe(150);
});

it('retains Critical severity when model constructs an exploit', function (): void {
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('sendWithUsage')
        ->once()
        ->andReturn(aiResponse(
            verified: true,
            exploit: "POST /admin\nCookie: session=admin",
        ));

    $usage = new UsageTracker;
    $result = buildEngine($mock)->verify(buildFinding(SeverityLevel::Critical), '<?php // file', $usage);

    expect($result->severity)->toBe(SeverityLevel::Critical)
        ->and($result->exploitVerified)->toBeTrue()
        ->and($result->exploitProof)->toBe("POST /admin\nCookie: session=admin")
        ->and($result->originalSeverity)->toBeNull();
});

it('downgrades High to Medium when model cannot exploit', function (): void {
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('sendWithUsage')
        ->once()
        ->andReturn(aiResponse(
            verified: false,
            reasoning: 'Line 20 calls $request->validated() — the input is constrained to an enum.',
        ));

    $usage = new UsageTracker;
    $result = buildEngine($mock)->verify(buildFinding(SeverityLevel::High), '<?php // file', $usage);

    expect($result->severity)->toBe(SeverityLevel::Medium)
        ->and($result->originalSeverity)->toBe(SeverityLevel::High)
        ->and($result->exploitVerified)->toBeFalse()
        ->and($result->exploitProof)->toBeNull();
});

it('downgrades Critical to High when model cannot exploit', function (): void {
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('sendWithUsage')
        ->once()
        ->andReturn(aiResponse(
            verified: false,
            reasoning: 'Middleware filters the parameter before the controller sees it.',
        ));

    $usage = new UsageTracker;
    $result = buildEngine($mock)->verify(buildFinding(SeverityLevel::Critical), '<?php // file', $usage);

    expect($result->severity)->toBe(SeverityLevel::High)
        ->and($result->originalSeverity)->toBe(SeverityLevel::Critical)
        ->and($result->exploitVerified)->toBeFalse();
});

it('treats verified=true with empty exploit as unverified', function (): void {
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('sendWithUsage')
        ->once()
        ->andReturn(aiResponse(verified: true, exploit: '   '));

    $usage = new UsageTracker;
    $result = buildEngine($mock)->verify(buildFinding(SeverityLevel::High), '<?php // file', $usage);

    expect($result->severity)->toBe(SeverityLevel::Medium)
        ->and($result->exploitVerified)->toBeFalse()
        ->and($result->originalSeverity)->toBe(SeverityLevel::High);
});

it('treats verified=true with placeholder exploit as unverified', function (): void {
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('sendWithUsage')
        ->once()
        ->andReturn(aiResponse(verified: true, exploit: 'N/A'));

    $usage = new UsageTracker;
    $result = buildEngine($mock)->verify(buildFinding(SeverityLevel::Critical), '<?php // file', $usage);

    expect($result->severity)->toBe(SeverityLevel::High)
        ->and($result->exploitVerified)->toBeFalse();
});

it('treats verified=true with angle-bracket placeholder as unverified', function (): void {
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('sendWithUsage')
        ->once()
        ->andReturn(aiResponse(verified: true, exploit: '<exploit here>'));

    $usage = new UsageTracker;
    $result = buildEngine($mock)->verify(buildFinding(SeverityLevel::High), '<?php // file', $usage);

    expect($result->severity)->toBe(SeverityLevel::Medium)
        ->and($result->exploitVerified)->toBeFalse();
});

it('returns finding unchanged when AI adapter throws', function (): void {
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('sendWithUsage')
        ->once()
        ->andThrow(new RuntimeException('network exploded'));

    $usage = new UsageTracker;
    $original = buildFinding(SeverityLevel::High);
    $result = buildEngine($mock)->verify($original, '<?php // file', $usage);

    expect($result->severity)->toBe(SeverityLevel::High)
        ->and($result->exploitVerified)->toBeNull()
        ->and($result->originalSeverity)->toBeNull()
        ->and($usage->getVerificationRequests())->toBe(0);
});

it('returns finding unchanged when response JSON is malformed', function (): void {
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('sendWithUsage')
        ->once()
        ->andReturn([
            'text' => 'this is not JSON at all',
            'usage' => ['prompt_tokens' => 200, 'completion_tokens' => 50],
        ]);

    $usage = new UsageTracker;
    $original = buildFinding(SeverityLevel::Critical);
    $result = buildEngine($mock)->verify($original, '<?php // file', $usage);

    expect($result->severity)->toBe(SeverityLevel::Critical)
        ->and($result->exploitVerified)->toBeNull()
        ->and($usage->getVerificationRequests())->toBe(1)
        ->and($usage->getVerificationPromptTokens())->toBe(200);
});

it('returns finding unchanged when verified field is missing', function (): void {
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('sendWithUsage')
        ->once()
        ->andReturn([
            'text' => '{"exploit":"nope","reasoning":"no verified key"}',
            'usage' => ['prompt_tokens' => 100, 'completion_tokens' => 30],
        ]);

    $usage = new UsageTracker;
    $result = buildEngine($mock)->verify(buildFinding(SeverityLevel::High), '<?php // file', $usage);

    expect($result->severity)->toBe(SeverityLevel::High)
        ->and($result->exploitVerified)->toBeNull();
});

it('extracts JSON from markdown fences in verification response', function (): void {
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('sendWithUsage')
        ->once()
        ->andReturn([
            'text' => "```json\n{\"verified\":true,\"exploit\":\"' OR 1=1 --\",\"reasoning\":\"direct\"}\n```",
            'usage' => ['prompt_tokens' => 300, 'completion_tokens' => 80],
        ]);

    $usage = new UsageTracker;
    $result = buildEngine($mock)->verify(buildFinding(SeverityLevel::High), '<?php // file', $usage);

    expect($result->exploitVerified)->toBeTrue()
        ->and($result->exploitProof)->toBe("' OR 1=1 --")
        ->and($result->severity)->toBe(SeverityLevel::High);
});
