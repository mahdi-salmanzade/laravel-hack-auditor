<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Support\VulnerabilityType;

it('help command runs successfully', function (): void {
    $this->artisan('hack:help')
        ->assertSuccessful();
});

it('help command shows all four commands', function (): void {
    $this->artisan('hack:help')
        ->expectsOutputToContain('hack:demo')
        ->expectsOutputToContain('hack:scan')
        ->expectsOutputToContain('hack:ctf')
        ->expectsOutputToContain('hack:report');
});

it('help command shows quick start section', function (): void {
    $this->artisan('hack:help')
        ->expectsOutputToContain('QUICK START');
});

it('help scan deep dive shows flags table', function (): void {
    $this->artisan('hack:help', ['topic' => 'scan'])
        ->assertSuccessful()
        ->expectsOutputToContain('--path')
        ->expectsOutputToContain('--json')
        ->expectsOutputToContain('--severity')
        ->expectsOutputToContain('--limit');
});

it('help scan deep dive shows workflows', function (): void {
    $result = $this->artisan('hack:help', ['topic' => 'scan']);

    // The output should mention CI/CD, Pipeline, or Workflow concepts
    $result->assertSuccessful();

    $output = $this->artisan('hack:help', ['topic' => 'scan']);
    $passes = false;

    try {
        $output->expectsOutputToContain('CI/CD');
        $passes = true;
    } catch (Throwable) {
    }

    if (! $passes) {
        try {
            $output->expectsOutputToContain('Pipeline');
            $passes = true;
        } catch (Throwable) {
        }
    }

    if (! $passes) {
        $output->expectsOutputToContain('Workflow');
    }
});

it('help demo deep dive works', function (): void {
    $this->artisan('hack:help', ['topic' => 'demo'])
        ->assertSuccessful()
        ->expectsOutputToContain('hack:demo')
        ->expectsOutputToContain('--quick');
});

it('help ctf deep dive shows vulnerability types from enum', function (): void {
    $this->artisan('hack:help', ['topic' => 'ctf'])
        ->assertSuccessful()
        ->expectsOutputToContain('sql_injection')
        ->expectsOutputToContain('xss');
});

it('help ctf types match vulnerability type enum', function (): void {
    $result = $this->artisan('hack:help', ['topic' => 'ctf']);
    $result->assertSuccessful();

    foreach (VulnerabilityType::cases() as $case) {
        $result->expectsOutputToContain($case->value);
    }
});

it('help invalid command shows error', function (): void {
    $this->artisan('hack:help', ['topic' => 'nonexistent'])
        ->expectsOutputToContain('Unknown');
});

it('help shows current provider status', function (): void {
    $result = $this->artisan('hack:help');
    $passes = false;

    try {
        $result->expectsOutputToContain('Provider');
        $passes = true;
    } catch (Throwable) {
    }

    if (! $passes) {
        try {
            $result->expectsOutputToContain('SETUP');
            $passes = true;
        } catch (Throwable) {
        }
    }

    if (! $passes) {
        $result->expectsOutputToContain('Configuration');
    }
});

it('help report deep dive works', function (): void {
    $this->artisan('hack:help', ['topic' => 'report'])
        ->assertSuccessful()
        ->expectsOutputToContain('--latest')
        ->expectsOutputToContain('--id');
});
