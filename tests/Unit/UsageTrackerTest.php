<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Support\UsageTracker;

it('tracks tokens across multiple records', function (): void {
    $tracker = new UsageTracker;
    $tracker->record(100, 50);
    $tracker->record(200, 100);

    expect($tracker->getPromptTokens())->toBe(300)
        ->and($tracker->getCompletionTokens())->toBe(150);
});

it('total tokens is sum of prompt and completion', function (): void {
    $tracker = new UsageTracker;
    $tracker->record(1000, 500);

    expect($tracker->totalTokens())->toBe(1500);
});

it('can afford returns true when no limit', function (): void {
    $tracker = new UsageTracker(0);

    expect($tracker->canAfford(999999))->toBeTrue();
});

it('can afford returns true when under limit', function (): void {
    $tracker = new UsageTracker(10000);
    $tracker->record(3000, 2000);

    expect($tracker->canAfford(4000))->toBeTrue();
});

it('can afford returns false when over limit', function (): void {
    $tracker = new UsageTracker(10000);
    $tracker->record(5000, 4000);

    expect($tracker->canAfford(2000))->toBeFalse();
});

it('would exceed limit is inverse of can afford', function (): void {
    $tracker = new UsageTracker(10000);
    $tracker->record(5000, 4000);

    expect($tracker->wouldExceedLimit(2000))->toBeTrue()
        ->and($tracker->wouldExceedLimit(500))->toBeFalse();
});

it('usage percent calculation', function (): void {
    $tracker = new UsageTracker(10000);
    $tracker->record(3000, 2000);

    expect($tracker->getUsagePercent())->toBe(50.0);
});

it('usage percent is zero when no limit', function (): void {
    $tracker = new UsageTracker(0);
    $tracker->record(5000, 5000);

    expect($tracker->getUsagePercent())->toBe(0.0);
});

it('remaining tokens calculation', function (): void {
    $tracker = new UsageTracker(10000);
    $tracker->record(3000, 2000);

    expect($tracker->getRemainingTokens())->toBe(5000);
});

it('estimate cost calculation', function (): void {
    $tracker = new UsageTracker;
    $tracker->setCostRates(3.00, 15.00);
    $tracker->record(1000000, 100000);

    expect($tracker->estimateCost())->toBe(4.5);
});

it('custom cost rates', function (): void {
    $tracker = new UsageTracker;
    $tracker->setCostRates(10.00, 30.00);
    $tracker->record(1000000, 1000000);

    expect($tracker->estimateCost())->toBe(40.0);
});

it('to array includes all fields', function (): void {
    $tracker = new UsageTracker(10000);
    $tracker->record(3000, 2000);

    $arr = $tracker->toArray();

    expect($arr)->toHaveKeys([
        'prompt_tokens',
        'completion_tokens',
        'total_tokens',
        'requests',
        'token_limit',
        'remaining_tokens',
        'usage_percent',
        'estimated_cost_usd',
        'elapsed_seconds',
    ])
        ->and($arr['prompt_tokens'])->toBe(3000)
        ->and($arr['token_limit'])->toBe(10000)
        ->and($arr['remaining_tokens'])->toBe(5000);
});

it('to array excludes limit fields when unlimited', function (): void {
    $tracker = new UsageTracker(0);
    $tracker->record(1000, 500);

    $arr = $tracker->toArray();

    expect($arr['remaining_tokens'])->toBeNull()
        ->and($arr['usage_percent'])->toBeNull();
});

it('reset clears all counters', function (): void {
    $tracker = new UsageTracker;
    $tracker->record(1000, 500);
    $tracker->reset();

    expect($tracker->totalTokens())->toBe(0)
        ->and($tracker->getRequests())->toBe(0);
});

it('request count increments', function (): void {
    $tracker = new UsageTracker;
    $tracker->record(100, 50);
    $tracker->record(100, 50);
    $tracker->record(100, 50);

    expect($tracker->getRequests())->toBe(3);
});

it('is limit set returns correct value', function (): void {
    $unlimitedTracker = new UsageTracker(0);
    $limitedTracker = new UsageTracker(5000);

    expect($unlimitedTracker->isLimitSet())->toBeFalse()
        ->and($limitedTracker->isLimitSet())->toBeTrue();
});
