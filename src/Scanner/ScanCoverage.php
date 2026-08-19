<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner;

/**
 * An immutable record of how much of a requested scan actually completed.
 *
 * A security report is only as trustworthy as the set of files behind it.
 * Before this existed, a run could quietly drop a whole chunk of files (token
 * budget exhausted, or an AI response that would not parse) and still print a
 * definitive score, with no way for the reader to learn WHICH files went
 * unexamined. Coverage makes that impossible: every skipped file is named with
 * the reason it was skipped, and the report refuses to present an authoritative
 * score when coverage is partial or empty.
 */
final class ScanCoverage
{
    /**
     * The scan ran out of its configured token budget before reaching the file.
     */
    public const string REASON_TOKEN_LIMIT = 'token_limit';

    /**
     * The AI returned a response that could not be parsed, or the request failed
     * after all retries, so the chunk containing the file produced no findings.
     */
    public const string REASON_AI_FAILURE = 'ai_failure';

    /**
     * The file could not be read from disk.
     */
    public const string REASON_UNREADABLE = 'unreadable';

    /**
     * @param  array<int, array{path: string, reason: string}>  $skipped
     */
    public function __construct(
        public readonly int $filesDiscovered = 0,
        public readonly int $filesAnalyzed = 0,
        public readonly array $skipped = [],
    ) {}

    /**
     * Coverage for a scan that discovered and analysed nothing.
     */
    public static function none(): self
    {
        return new self(filesDiscovered: 0, filesAnalyzed: 0, skipped: []);
    }

    /**
     * Coverage for a run in which every discovered file was analysed.
     */
    public static function complete(int $files): self
    {
        return new self(filesDiscovered: $files, filesAnalyzed: $files, skipped: []);
    }

    /**
     * Number of discovered files that never reached the analyzer.
     */
    public function filesSkipped(): int
    {
        return count($this->skipped);
    }

    /**
     * Whether nothing at all was analysed.
     *
     * An empty scan can never justify a score: there is no evidence either way.
     */
    public function isEmpty(): bool
    {
        return $this->filesAnalyzed === 0;
    }

    /**
     * Whether every discovered file was analysed and nothing was skipped.
     */
    public function isComplete(): bool
    {
        return $this->filesAnalyzed > 0
            && $this->skipped === []
            && $this->filesAnalyzed >= $this->filesDiscovered;
    }

    /**
     * Percentage of discovered files that were actually analysed.
     */
    public function percent(): float
    {
        if ($this->filesDiscovered === 0) {
            return 0.0;
        }

        return round(min(100.0, ($this->filesAnalyzed / $this->filesDiscovered) * 100), 1);
    }

    /**
     * Paths of every file that was not analysed.
     *
     * @return array<int, string>
     */
    public function skippedPaths(): array
    {
        return array_map(
            static fn (array $entry): string => $entry['path'],
            $this->skipped,
        );
    }

    /**
     * Skipped file paths grouped by the reason they were skipped.
     *
     * @return array<string, array<int, string>>
     */
    public function skippedByReason(): array
    {
        $grouped = [];

        foreach ($this->skipped as $entry) {
            $grouped[$entry['reason']][] = $entry['path'];
        }

        return $grouped;
    }

    /**
     * Human-readable explanation for a skip reason code.
     */
    public static function reasonLabel(string $reason): string
    {
        return match ($reason) {
            self::REASON_TOKEN_LIMIT => 'token budget exhausted before this file was reached',
            self::REASON_AI_FAILURE => 'the AI response for this chunk could not be parsed',
            self::REASON_UNREADABLE => 'the file could not be read from disk',
            default => $reason,
        };
    }

    /**
     * A one-line, human-readable statement of coverage.
     */
    public function describe(): string
    {
        if ($this->filesDiscovered === 0) {
            return 'No files were discovered, so nothing was analysed.';
        }

        if ($this->isComplete()) {
            return sprintf('All %d discovered file(s) were analysed.', $this->filesDiscovered);
        }

        return sprintf(
            '%d of %d discovered file(s) were analysed (%s%%); %d file(s) were NOT analysed.',
            $this->filesAnalyzed,
            $this->filesDiscovered,
            $this->percent(),
            $this->filesSkipped(),
        );
    }

    /**
     * Return the coverage record as an associative array for JSON output.
     *
     * @return array{files_discovered: int, files_analyzed: int, files_skipped: int, percent_analyzed: float, complete: bool, skipped_files: array<int, array{path: string, reason: string, reason_label: string}>}
     */
    public function toArray(): array
    {
        return [
            'files_discovered' => $this->filesDiscovered,
            'files_analyzed' => $this->filesAnalyzed,
            'files_skipped' => $this->filesSkipped(),
            'percent_analyzed' => $this->percent(),
            'complete' => $this->isComplete(),
            'skipped_files' => array_map(
                static fn (array $entry): array => [
                    'path' => $entry['path'],
                    'reason' => $entry['reason'],
                    'reason_label' => self::reasonLabel($entry['reason']),
                ],
                $this->skipped,
            ),
        ];
    }
}
