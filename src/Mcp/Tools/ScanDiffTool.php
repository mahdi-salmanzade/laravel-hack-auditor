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
use Mahdi\HackAuditor\Mcp\Support\FindingFormatter;
use Mahdi\HackAuditor\Scanner\GitDiffCollector;
use Mahdi\HackAuditor\Scanner\HackScanner;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Throwable;

#[Name('scan_diff')]
#[Description('Run an AI-assisted Laravel security audit on ONLY the PHP files changed in the current git branch versus a base branch (default: auto-detected main/master). Ideal for pull-request and pre-commit review: it scopes the scan to what the diff touches within the configured scan paths, skipping sensitive files. Returns the same structured findings as scan_path (type, severity, file, line, description, proof, fix). Use this when the user wants to review only their changes or a PR rather than the whole codebase.')]
class ScanDiffTool extends Tool
{
    /**
     * Create a new tool instance.
     */
    public function __construct(
        private readonly GitDiffCollector $diffCollector,
        private readonly HackScanner $scanner,
    ) {}

    /**
     * Define the tool's input schema.
     *
     * @return array<string, mixed>
     */
    public function schema(JsonSchema $schema): array
    {
        return [
            'base' => $schema->string()
                ->description('The git base branch to diff against (e.g. "main", "master", or "develop"). Omit to auto-detect the repository\'s default branch.'),
        ];
    }

    /**
     * Handle the tool request.
     */
    public function handle(Request $request): Response|ResponseFactory
    {
        $base = $request->get('base');
        $baseBranch = is_string($base) && trim($base) !== '' ? trim($base) : 'main';

        try {
            $files = $this->diffCollector->getChangedFiles($baseBranch);
        } catch (Throwable $e) {
            return Response::error(
                "Unable to compute the git diff against \"{$baseBranch}\": {$e->getMessage()}. "
                .'Ensure this command runs inside a git repository.'
            );
        }

        if ($files === []) {
            $empty = new VulnerabilityReport(
                vulnerabilities: [],
                overallScore: 100,
                summary: "No changed PHP files found compared to {$baseBranch}.",
                ctfIdea: '',
            );

            return FindingFormatter::report($empty, "git diff vs {$baseBranch}");
        }

        $reports = [];

        foreach ($files as $filePath) {
            try {
                $reports[] = $this->scanner->scanFile($filePath);
            } catch (Throwable) {
                // Best-effort: skip a file the scanner cannot analyze.
            }
        }

        return FindingFormatter::report(
            $this->mergeReports($reports),
            "git diff vs {$baseBranch} (".count($files).' changed file(s))',
        );
    }

    /**
     * Merge per-file reports into a single report for the diff.
     *
     * @param  array<int, VulnerabilityReport>  $reports
     */
    private function mergeReports(array $reports): VulnerabilityReport
    {
        if ($reports === []) {
            return new VulnerabilityReport(
                vulnerabilities: [],
                overallScore: 100,
                summary: 'No files analyzed.',
                ctfIdea: '',
            );
        }

        /** @var array<int, Vulnerability> $vulnerabilities */
        $vulnerabilities = [];
        $scoreSum = 0;
        $summaries = [];

        foreach ($reports as $report) {
            $vulnerabilities = array_merge($vulnerabilities, $report->vulnerabilities);
            $scoreSum += $report->overallScore;

            if ($report->summary !== '') {
                $summaries[] = $report->summary;
            }
        }

        return new VulnerabilityReport(
            vulnerabilities: $vulnerabilities,
            overallScore: (int) round($scoreSum / count($reports)),
            summary: implode("\n\n", $summaries),
            ctfIdea: '',
        );
    }
}
