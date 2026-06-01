<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Mcp\HackAuditorMcpServer;
use Mahdi\HackAuditor\Mcp\Tools\ExplainFindingTool;
use Mahdi\HackAuditor\Mcp\Tools\ScanDiffTool;
use Mahdi\HackAuditor\Mcp\Tools\ScanPathTool;

it('exposes the three scanner tools on the server', function (): void {
    $property = new ReflectionProperty(HackAuditorMcpServer::class, 'tools');
    $tools = $property->getDefaultValue();

    expect($tools)->toBe([
        ScanPathTool::class,
        ScanDiffTool::class,
        ExplainFindingTool::class,
    ]);
});

it('declares sharp, kebab-case tool names', function (string $tool, string $expectedName): void {
    expect(app($tool)->name())->toBe($expectedName);
})->with([
    'scan_path' => [ScanPathTool::class, 'scan_path'],
    'scan_diff' => [ScanDiffTool::class, 'scan_diff'],
    'explain_finding' => [ExplainFindingTool::class, 'explain_finding'],
]);

it('gives every tool a Laravel-specific description', function (string $tool): void {
    $description = app($tool)->description();

    expect($description)->not->toBe('')
        ->and(strtolower($description))->toContain('laravel');
})->with([
    ScanPathTool::class,
    ScanDiffTool::class,
    ExplainFindingTool::class,
]);

it('defines a path input on scan_path', function (): void {
    $properties = app(ScanPathTool::class)->toArray()['inputSchema']['properties'];

    expect($properties)->toHaveKey('path')
        ->and($properties['path']['description'])->toContain('Laravel');
});

it('defines a base branch input on scan_diff', function (): void {
    $properties = app(ScanDiffTool::class)->toArray()['inputSchema']['properties'];

    expect($properties)->toHaveKey('base')
        ->and($properties['base']['description'])->toContain('branch');
});

it('requires a type input on explain_finding', function (): void {
    $array = app(ExplainFindingTool::class)->toArray();

    expect($array['inputSchema']['properties'])->toHaveKey('type')
        ->and($array['inputSchema']['required'] ?? [])->toContain('type');
});
