<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor;

use Illuminate\Support\ServiceProvider;
use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\AI\ResponseParser;
use Mahdi\HackAuditor\Console\HackCTFCommand;
use Mahdi\HackAuditor\Console\HackDemoCommand;
use Mahdi\HackAuditor\Console\HackHelpCommand;
use Mahdi\HackAuditor\Console\HackReportCommand;
use Mahdi\HackAuditor\Console\HackScanCommand;
use Mahdi\HackAuditor\Console\HackUsageCommand;
use Mahdi\HackAuditor\Contracts\CTFGeneratorInterface;
use Mahdi\HackAuditor\Contracts\ScannerInterface;
use Mahdi\HackAuditor\CTF\CTFGenerator;
use Mahdi\HackAuditor\Report\HtmlReportGenerator;
use Mahdi\HackAuditor\Scanner\Baseline;
use Mahdi\HackAuditor\Scanner\CodeExtractor;
use Mahdi\HackAuditor\Scanner\ContextCollector;
use Mahdi\HackAuditor\Scanner\FileCollector;
use Mahdi\HackAuditor\Scanner\HackScanner;
use Mahdi\HackAuditor\Scanner\RouteAnalyzer;
use Mahdi\HackAuditor\Scanner\RuntimeIntrospector;
use Mahdi\HackAuditor\Scanner\VerificationEngine;

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
        $this->app->singleton(RouteAnalyzer::class);
        $this->app->singleton(RuntimeIntrospector::class);
        $this->app->singleton(Baseline::class);
        $this->app->singleton(ContextCollector::class);
        $this->app->singleton(HtmlReportGenerator::class);
        $this->app->singleton(PromptBuilder::class);
        $this->app->singleton(ResponseParser::class);
        $this->app->singleton(AIAdapter::class);

        $this->app->singleton(VerificationEngine::class, function ($app): VerificationEngine {
            return new VerificationEngine(
                ai: $app->make(AIAdapter::class),
                prompts: $app->make(PromptBuilder::class),
                parser: $app->make(ResponseParser::class),
            );
        });

        $this->app->singleton(HackScanner::class, function ($app): HackScanner {
            return new HackScanner(
                fileCollector: $app->make(FileCollector::class),
                codeExtractor: $app->make(CodeExtractor::class),
                promptBuilder: $app->make(PromptBuilder::class),
                responseParser: $app->make(ResponseParser::class),
                aiAdapter: $app->make(AIAdapter::class),
                routeAnalyzer: $app->make(RouteAnalyzer::class),
                runtimeIntrospector: $app->make(RuntimeIntrospector::class),
                contextCollector: $app->make(ContextCollector::class),
                verificationEngine: $app->make(VerificationEngine::class),
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
        if ($this->app->runningInConsole()) {
            $this->commands([
                HackScanCommand::class,
                HackDemoCommand::class,
                HackCTFCommand::class,
                HackReportCommand::class,
                HackHelpCommand::class,
                HackUsageCommand::class,
            ]);

            $this->publishes([
                __DIR__.'/../config/hack-auditor.php' => config_path('hack-auditor.php'),
            ], 'hack-auditor-config');

            $this->publishes([
                __DIR__.'/../resources/stubs' => base_path('stubs/hack-auditor'),
            ], 'hack-auditor-stubs');
        }
    }
}
