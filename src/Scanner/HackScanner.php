<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner;

use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\AI\ResponseParser;
use Mahdi\HackAuditor\Contracts\ScannerInterface;
use SplFileInfo;

final class HackScanner implements ScannerInterface
{
    /**
     * Create a new HackScanner instance with all required dependencies.
     */
    public function __construct(
        private readonly FileCollector $fileCollector,
        private readonly CodeExtractor $codeExtractor,
        private readonly PromptBuilder $promptBuilder,
        private readonly ResponseParser $responseParser,
        private readonly AIAdapter $aiAdapter,
    ) {}

    /**
     * Scan the entire application for security vulnerabilities.
     *
     * Collects files from configured paths, chunks them for batched AI analysis,
     * sends each chunk to the AI provider, parses the responses, and merges all
     * results into a single report with a recalculated weighted average score.
     */
    public function scan(): VulnerabilityReport
    {
        $files = $this->fileCollector->collect();

        if ($files->isEmpty()) {
            return new VulnerabilityReport(
                vulnerabilities: [],
                overallScore: 100,
                summary: 'No files found to scan.',
                ctfIdea: '',
            );
        }

        $chunks = $this->codeExtractor->chunk($files);

        return $this->scanChunks($chunks);
    }

    /**
     * Scan a specific file for security vulnerabilities.
     */
    public function scanFile(string $path): VulnerabilityReport
    {
        $absolutePath = str_starts_with($path, DIRECTORY_SEPARATOR)
            ? $path
            : base_path($path);

        if (! file_exists($absolutePath)) {
            return new VulnerabilityReport(
                vulnerabilities: [],
                overallScore: 100,
                summary: "File not found: {$path}",
                ctfIdea: '',
            );
        }

        $file = new SplFileInfo($absolutePath);
        $extracted = $this->codeExtractor->extract($file);

        return $this->analyzeFiles([$extracted]);
    }

    /**
     * Scan a raw code string for security vulnerabilities.
     */
    public function scanCode(string $code): VulnerabilityReport
    {
        $fileData = [
            'path' => 'inline-code.php',
            'content' => $code,
            'type' => 'other',
        ];

        return $this->analyzeFiles([$fileData]);
    }

    /**
     * Scan multiple chunks of files and merge results into a single report.
     *
     * @param  array<int, array<int, array{path: string, content: string, type: string}>>  $chunks
     */
    private function scanChunks(array $chunks): VulnerabilityReport
    {
        /** @var array<int, VulnerabilityReport> $reports */
        $reports = [];

        foreach ($chunks as $chunk) {
            $reports[] = $this->analyzeFiles($chunk);
        }

        return $this->mergeReports($reports);
    }

    /**
     * Send a batch of files to the AI for security analysis.
     *
     * @param  array<int, array{path: string, content: string, type: string}>  $files
     */
    private function analyzeFiles(array $files): VulnerabilityReport
    {
        $systemPrompt = $this->promptBuilder->systemPrompt();
        $userPrompt = $this->promptBuilder->userPrompt($files);

        $response = $this->aiAdapter->send($systemPrompt, $userPrompt);

        return $this->responseParser->parse($response);
    }

    /**
     * Merge multiple VulnerabilityReports into a single consolidated report.
     *
     * Combines all vulnerabilities, calculates a weighted average overall score
     * based on the number of files in each chunk, concatenates summaries, and
     * picks the most relevant CTF idea.
     *
     * @param  array<int, VulnerabilityReport>  $reports
     */
    private function mergeReports(array $reports): VulnerabilityReport
    {
        if (count($reports) === 0) {
            return new VulnerabilityReport(
                vulnerabilities: [],
                overallScore: 100,
                summary: 'No files analyzed.',
                ctfIdea: '',
            );
        }

        if (count($reports) === 1) {
            return $reports[0];
        }

        $allVulnerabilities = [];
        $scoreSum = 0;
        $summaries = [];
        $ctfIdea = '';
        $lowestScore = 100;

        foreach ($reports as $report) {
            $allVulnerabilities = array_merge($allVulnerabilities, $report->vulnerabilities);
            $scoreSum += $report->overallScore;

            if ($report->summary !== '') {
                $summaries[] = $report->summary;
            }

            if ($report->overallScore < $lowestScore && $report->ctfIdea !== '') {
                $lowestScore = $report->overallScore;
                $ctfIdea = $report->ctfIdea;
            }
        }

        $averageScore = (int) round($scoreSum / count($reports));

        $mergedSummary = implode(' ', $summaries);

        return new VulnerabilityReport(
            vulnerabilities: $allVulnerabilities,
            overallScore: $averageScore,
            summary: $mergedSummary,
            ctfIdea: $ctfIdea,
        );
    }
}
