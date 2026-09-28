<?php

declare(strict_types=1);

it('defines every context key the ContextCollector reads, with the defaults it uses', function (string $key): void {
    $config = require dirname(__DIR__, 2).'/config/hack-auditor.php';

    expect($config['context'])->toHaveKey($key)
        ->and($config['context'][$key])->toBeTrue();
})->with(['include_rate_limiters', 'include_config', 'include_environment']);

it('does not ship verification keys that nothing reads', function (): void {
    $config = require dirname(__DIR__, 2).'/config/hack-auditor.php';

    expect($config['verification'])->not->toHaveKeys(['min_severity', 'downgrade_on_failure']);
});
