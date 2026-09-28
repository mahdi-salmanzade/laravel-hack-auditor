<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Support;

use Illuminate\Support\Facades\File;

final class UsageLog
{
    private string $path;

    public function __construct(?string $path = null)
    {
        $this->path = $path ?? storage_path('hack-auditor/usage.json');
    }

    /**
     * Append a usage entry derived from the given tracker and optional metadata.
     *
     * @param  array<string, mixed>  $meta
     */
    public function record(UsageTracker $tracker, array $meta = []): void
    {
        $entries = $this->all();

        $entries[] = [
            'timestamp' => now()->toIso8601String(),
            'prompt_tokens' => $tracker->getPromptTokens(),
            'completion_tokens' => $tracker->getCompletionTokens(),
            'total_tokens' => $tracker->totalTokens(),
            'requests' => $tracker->getRequests(),
            'estimated_cost_usd' => $tracker->estimateCost(),
            'elapsed_seconds' => round($tracker->getElapsedSeconds(), 2),
            'token_limit' => $tracker->getTokenLimit() ?: null,
            'files_scanned' => $meta['files_scanned'] ?? null,
            'files_skipped' => $meta['files_skipped'] ?? 0,
            'coverage_complete' => $meta['coverage_complete'] ?? null,
            'aborted' => $meta['aborted'] ?? false,
            'path' => $meta['path'] ?? null,
            'score' => $meta['score'] ?? null,
            'provider' => $meta['provider'] ?? null,
            'model' => $meta['model'] ?? null,
        ];

        // Encode first: json_encode() returning false used to be written as an
        // empty file, wiping every previously logged scan. Invalid UTF-8 (a
        // --path with Latin-1 bytes) is substituted; any other failure throws
        // before the existing log is touched.
        $json = json_encode(
            $entries,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR,
        );

        $directory = dirname($this->path);

        if (! File::isDirectory($directory)) {
            File::makeDirectory($directory, 0755, true);
        }

        $this->preserveUnreadableLog();

        file_put_contents($this->path, $json, LOCK_EX);
    }

    /**
     * Move an existing log that cannot be decoded out of the way.
     *
     * all() reads a corrupt log as empty, so appending would otherwise
     * overwrite months of spend history with a single entry. The unreadable
     * file is kept next to the log for manual recovery instead.
     */
    private function preserveUnreadableLog(): void
    {
        if (! file_exists($this->path)) {
            return;
        }

        $contents = file_get_contents($this->path);

        if ($contents === false || trim($contents) === '') {
            return;
        }

        if (is_array(json_decode($contents, true))) {
            return;
        }

        @rename($this->path, $this->path.'.corrupt-'.now()->format('YmdHis'));
    }

    /**
     * Return all stored usage entries.
     *
     * @return array<int, array<string, mixed>>
     */
    public function all(): array
    {
        if (! file_exists($this->path)) {
            return [];
        }

        $contents = file_get_contents($this->path);

        if ($contents === false || $contents === '') {
            return [];
        }

        $decoded = json_decode($contents, true);

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * Get the sum of total_tokens across all entries.
     */
    public function totalTokens(): int
    {
        return (int) array_sum(array_column($this->all(), 'total_tokens'));
    }

    /**
     * Get the sum of estimated_cost_usd across all entries.
     */
    public function totalCost(): float
    {
        return (float) array_sum(array_column($this->all(), 'estimated_cost_usd'));
    }

    /**
     * Get the number of recorded scan entries.
     */
    public function scanCount(): int
    {
        return count($this->all());
    }

    /**
     * Filter entries recorded on or after the given date.
     *
     * @return array<int, array<string, mixed>>
     */
    public function since(\DateTimeInterface $since): array
    {
        $threshold = $since->format('c');

        return array_values(array_filter(
            $this->all(),
            fn (array $entry): bool => ($entry['timestamp'] ?? '') >= $threshold,
        ));
    }

    /**
     * Return an aggregated summary of all recorded usage.
     *
     * @return array{total_scans: int, total_tokens: int, total_prompt_tokens: int, total_completion_tokens: int, total_cost_usd: float, total_requests: int}
     */
    public function summary(): array
    {
        $entries = $this->all();

        return [
            'total_scans' => count($entries),
            'total_tokens' => (int) array_sum(array_column($entries, 'total_tokens')),
            'total_prompt_tokens' => (int) array_sum(array_column($entries, 'prompt_tokens')),
            'total_completion_tokens' => (int) array_sum(array_column($entries, 'completion_tokens')),
            'total_cost_usd' => (float) array_sum(array_column($entries, 'estimated_cost_usd')),
            'total_requests' => (int) array_sum(array_column($entries, 'requests')),
        ];
    }

    /**
     * Delete the usage log file.
     */
    public function clear(): void
    {
        if (file_exists($this->path)) {
            unlink($this->path);
        }
    }

    /**
     * Get the filesystem path of the usage log file.
     */
    public function getPath(): string
    {
        return $this->path;
    }
}
