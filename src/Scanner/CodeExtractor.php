<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner;

use Illuminate\Support\Collection;
use SplFileInfo;

final class CodeExtractor
{
    /**
     * Extract file contents and metadata for AI analysis.
     *
     * Reads the file, determines its type from namespace/class structure,
     * and strips excessive whitespace and multi-line comments while keeping
     * single-line comments and enough context for analysis.
     *
     * @return array{path: string, content: string, type: string}
     */
    public function extract(SplFileInfo $file): array
    {
        $realPath = $file->getRealPath();

        if ($realPath === false) {
            return [
                'path' => $file->getPathname(),
                'content' => '',
                'type' => 'other',
            ];
        }

        $basePath = base_path().DIRECTORY_SEPARATOR;
        $relativePath = str_starts_with($realPath, $basePath)
            ? substr($realPath, strlen($basePath))
            : $realPath;

        $content = (string) file_get_contents($realPath);
        $cleanedContent = $this->cleanContent($content);
        $type = $this->detectType($content, $relativePath);

        return [
            'path' => $relativePath,
            'content' => $cleanedContent,
            'type' => $type,
        ];
    }

    /**
     * Estimate the token count for a string.
     *
     * Uses a rough heuristic of ~4 characters per token, which is conservative
     * enough to avoid blowing context windows.
     */
    public function estimateTokens(string $content): int
    {
        return (int) ceil(strlen($content) / 4);
    }

    /**
     * Group extracted files into chunks for batched AI requests.
     *
     * Uses token-aware chunking: estimates tokens per file and caps each chunk
     * at ~60% of the configured max_tokens to leave room for the system prompt
     * and AI response. Falls back to file-count chunking only as a secondary limit.
     *
     * @param  Collection<int, SplFileInfo>  $files
     * @return array<int, array<int, array{path: string, content: string, type: string}>>
     */
    public function chunk(Collection $files): array
    {
        /** @var int $maxFilesPerChunk */
        $maxFilesPerChunk = config('hack-auditor.scan.chunk_size', 10);

        /** @var int $maxTokens */
        $maxTokens = (int) config('hack-auditor.ai.max_tokens', 4096);

        $tokenBudget = (int) ($maxTokens * 2.5);

        $extracted = $files->map(fn (SplFileInfo $file): array => $this->extract($file));

        $chunks = [];
        $currentChunk = [];
        $currentTokens = 0;

        foreach ($extracted as $file) {
            $fileTokens = $this->estimateTokens($file['content']);

            $wouldExceedTokens = $currentTokens + $fileTokens > $tokenBudget && count($currentChunk) > 0;
            $wouldExceedFiles = count($currentChunk) >= $maxFilesPerChunk;

            if ($wouldExceedTokens || $wouldExceedFiles) {
                $chunks[] = $currentChunk;
                $currentChunk = [];
                $currentTokens = 0;
            }

            $currentChunk[] = $file;
            $currentTokens += $fileTokens;
        }

        if (count($currentChunk) > 0) {
            $chunks[] = $currentChunk;
        }

        return $chunks;
    }

    /**
     * Detect the file type from its namespace, class structure, or path.
     */
    private function detectType(string $content, string $relativePath): string
    {
        if (str_contains($relativePath, 'routes/') || str_contains($relativePath, 'routes\\')) {
            return 'route';
        }

        if (preg_match('/extends\s+Controller\b/', $content)) {
            return 'controller';
        }

        if (preg_match('/extends\s+Model\b/', $content)) {
            return 'model';
        }

        if (preg_match('/extends\s+Middleware\b/', $content)) {
            return 'middleware';
        }

        if (preg_match('/extends\s+FormRequest\b/', $content)) {
            return 'request';
        }

        return 'other';
    }

    /**
     * Clean file content by stripping multi-line comments and collapsing
     * excessive blank lines while preserving single-line comments and code context.
     */
    private function cleanContent(string $content): string
    {
        $content = preg_replace('#/\*(?!/).*?\*/#s', '', $content) ?? $content;

        $content = preg_replace("/\n{3,}/", "\n\n", $content) ?? $content;

        $content = preg_replace("/[ \t]+$/m", '', $content) ?? $content;

        return trim($content);
    }
}
