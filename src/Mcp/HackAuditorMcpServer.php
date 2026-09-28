<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Mcp;

use Composer\InstalledVersions;
use Laravel\Mcp\Server;
use Laravel\Mcp\Server\Attributes\Instructions;
use Laravel\Mcp\Server\Attributes\Name;
use Laravel\Mcp\Server\Tool;
use Mahdi\HackAuditor\Mcp\Tools\ExplainFindingTool;
use Mahdi\HackAuditor\Mcp\Tools\ScanDiffTool;
use Mahdi\HackAuditor\Mcp\Tools\ScanPathTool;

#[Name('Laravel Hack Auditor')]
#[Instructions(<<<'MARKDOWN'
This server exposes the Laravel Hack Auditor as MCP tools so an AI coding agent
can audit Laravel code for security vulnerabilities.

- Use `scan_path` to audit a specific file or directory.
- Use `scan_diff` to audit only the files changed in the current git branch (PR review).
- Use `explain_finding` to get the OWASP/CWE mapping and remediation for a finding type.

Findings are AI-assisted contextual analysis (routes, middleware, FormRequests,
Eloquent models are considered), not a regex-based SAST replacement. Each finding
includes a type, severity, file, line, description, proof, and suggested fix.
MARKDOWN)]
class HackAuditorMcpServer extends Server
{
    /**
     * The tools registered with this MCP server.
     *
     * @var array<int, class-string<Tool>>
     */
    protected array $tools = [
        ScanPathTool::class,
        ScanDiffTool::class,
        ExplainFindingTool::class,
    ];

    /**
     * Report the installed package version in serverInfo.
     *
     * A #[Version] attribute must be a constant, so it drifted: v2.2.0 still
     * announced itself to MCP clients as 1.0.0.
     */
    protected function boot(): void
    {
        $this->version = self::packageVersion();
    }

    /**
     * The installed version of this package, without a leading "v".
     */
    public static function packageVersion(): string
    {
        $version = InstalledVersions::isInstalled('mahdisphp/laravel-hack-auditor')
            ? InstalledVersions::getPrettyVersion('mahdisphp/laravel-hack-auditor')
            : null;

        return ltrim($version ?? 'dev', 'v');
    }
}
