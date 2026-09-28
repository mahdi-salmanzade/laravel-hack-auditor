<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Mcp\Tools;

use Illuminate\Contracts\JsonSchema\JsonSchema;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\ResponseFactory;
use Laravel\Mcp\Server\Attributes\Description;
use Laravel\Mcp\Server\Attributes\Name;
use Laravel\Mcp\Server\Tool;
use Mahdi\HackAuditor\HackAuditorManager;
use Mahdi\HackAuditor\Mcp\Support\FindingFormatter;

#[Name('scan_diff')]
#[Description('Run an AI-assisted Laravel security audit on ONLY the PHP files changed in the current git branch versus a base branch (default: the configured diff base, else auto-detected main/master). Ideal for pull-request and pre-commit review: it scopes the scan to what the diff touches within the configured scan paths, skipping sensitive files. Returns the same structured findings as scan_path (type, severity, file, line, description, proof, fix). Use this when the user wants to review only their changes or a PR rather than the whole codebase.')]
class ScanDiffTool extends Tool
{
    /**
     * Create a new tool instance.
     */
    public function __construct(private readonly HackAuditorManager $auditor) {}

    /**
     * Define the tool's input schema.
     *
     * @return array<string, mixed>
     */
    public function schema(JsonSchema $schema): array
    {
        return [
            'base' => $schema->string()
                ->description('The git base branch to diff against (e.g. "main", "master", or "develop"). Omit to use the configured diff base, or auto-detect main/master.'),
            'deterministic' => $schema->boolean()
                ->description('Run only the reproducible AST-based access-control engine. No AI request, no API key, no cost — but injection and XSS are not looked for. Default false.'),
        ];
    }

    /**
     * Handle the tool request.
     *
     * This tool used to scan the diff one file at a time and merge the results
     * itself, without coverage: an empty diff — or one where every file failed —
     * came back as a confident 100/100. It now shares the scanner's diff scan,
     * so it gets the same chunking, coverage accounting and score withholding.
     */
    public function handle(Request $request): Response|ResponseFactory
    {
        $base = $request->get('base');

        /** @var ?string $configured */
        $configured = config('hack-auditor.scan.diff_base_branch');

        $baseBranch = match (true) {
            is_string($base) && trim($base) !== '' => trim($base),
            is_string($configured) && $configured !== '' => $configured,
            default => null,
        };

        $report = $this->auditor->scanDiff($baseBranch, deterministic: $request->get('deterministic') === true);

        if ($report->getTargetError() !== null) {
            return Response::error(
                "Unable to compute the git diff: {$report->getTargetError()}"
            );
        }

        $coverage = $report->getCoverage();

        return FindingFormatter::report(
            $report,
            'git diff vs '.($baseBranch ?? 'main/master').' ('.($coverage->filesDiscovered ?? 0).' changed file(s))',
        );
    }
}
