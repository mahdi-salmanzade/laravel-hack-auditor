<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Tests;

use Laravel\Ai\AiServiceProvider;
use Mahdi\HackAuditor\HackAuditorServiceProvider;
use Orchestra\Testbench\TestCase as BaseTestCase;

class TestCase extends BaseTestCase
{
    protected function getPackageProviders($app): array
    {
        // laravel/ai is auto-discovered in a real app; register it here so tests
        // can drive the actual SDK (and its fakes) instead of mocking around it.
        return [AiServiceProvider::class, HackAuditorServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
    }
}
