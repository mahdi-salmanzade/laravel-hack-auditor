<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor;

use Illuminate\Support\ServiceProvider;
use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\AI\ResponseParser;
use Mahdi\HackAuditor\Console\HackCTFCommand;
use Mahdi\HackAuditor\Console\HackDemoCommand;
use Mahdi\HackAuditor\Console\HackScanCommand;
use Mahdi\HackAuditor\Contracts\CTFGeneratorInterface;
use Mahdi\HackAuditor\Contracts\ScannerInterface;
use Mahdi\HackAuditor\CTF\CTFGenerator;
use Mahdi\HackAuditor\Scanner\CodeExtractor;
use Mahdi\HackAuditor\Scanner\FileCollector;
use Mahdi\HackAuditor\Scanner\HackScanner;

final class HackAuditorServiceProvider extends ServiceProvider
{
    /**
     * Register package services and bindings into the container.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/hack-auditor.php',
            'hack-auditor',
        );

        $this->app->singleton(FileCollector::class);
        $this->app->singleton(CodeExtractor::class);
        $this->app->singleton(PromptBuilder::class);
        $this->app->singleton(ResponseParser::class);
        $this->app->singleton(AIAdapter::class);

        $this->app->singleton(HackScanner::class, function ($app): HackScanner {
            return new HackScanner(
                fileCollector: $app->make(FileCollector::class),
                codeExtractor: $app->make(CodeExtractor::class),
                promptBuilder: $app->make(PromptBuilder::class),
                responseParser: $app->make(ResponseParser::class),
                aiAdapter: $app->make(AIAdapter::class),
            );
        });

        $this->app->singleton(CTFGenerator::class, function ($app): CTFGenerator {
            return new CTFGenerator(
                ai: $app->make(AIAdapter::class),
                promptBuilder: $app->make(PromptBuilder::class),
            );
        });

        $this->app->singleton(HackAuditorManager::class, function ($app): HackAuditorManager {
            return new HackAuditorManager($app);
        });

        $this->app->bind(ScannerInterface::class, HackScanner::class);
        $this->app->bind(CTFGeneratorInterface::class, CTFGenerator::class);
    }

    /**
     * Bootstrap package services, commands, and publishable assets.
     */
    public function boot(): void
    {
        if (config('hack-auditor.history.enabled', true)) {
            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        }

        if ($this->app->runningInConsole()) {
            $this->commands([
                HackScanCommand::class,
                HackDemoCommand::class,
                HackCTFCommand::class,
            ]);

            $this->publishes([
                __DIR__.'/../config/hack-auditor.php' => config_path('hack-auditor.php'),
            ], 'hack-auditor-config');

            $this->publishes([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'hack-auditor-migrations');

            $this->publishes([
                __DIR__.'/../resources/stubs' => base_path('stubs/hack-auditor'),
            ], 'hack-auditor-stubs');
        }
    }
}
