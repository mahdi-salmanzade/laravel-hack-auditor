<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Report;

use Mahdi\HackAuditor\Scanner\ScanCoverage;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\References;
use Mahdi\HackAuditor\Support\SeverityLevel;

/**
 * Renders a report as GitHub-flavoured Markdown — for PR comments, job
 * summaries ($GITHUB_STEP_SUMMARY) and issue trackers.
 *
 * Same honesty rules as every other renderer: the score is printed only when
 * coverage supports it (otherwise the reason it was withheld), confirmed
 * vulnerabilities and review questions are separate sections, and every file
 * that was not analysed is named.
 */
final class MarkdownReportGenerator
{
    /**
     * Render the report as Markdown.
     *
     * @param  array<int, Vulnerability>|null  $confirmed  Confirmed findings to list (defaults to all in the report).
     * @param  array<int, Vulnerability>|null  $reviewItems  Review items to list (defaults to all in the report).
     */
    public function generate(VulnerabilityReport $report, ?array $confirmed = null, ?array $reviewItems = null): string
    {
        $confirmed ??= $report->confirmedVulnerabilities();
        $reviewItems ??= $report->reviewItems();

        $lines = ['# Laravel Hack Auditor — Security Scan', ''];

        $targetError = $report->getTargetError();

        if ($targetError !== null) {
            $lines[] = '> **Scan target could not be analysed:** '.$this->inline($targetError);
            $lines[] = '';
        }

        array_push($lines, ...$this->scoreLines($report));
        array_push($lines, ...$this->coverageLines($report));
        array_push($lines, ...$this->summaryLines($confirmed, $reviewItems));

        if (trim($report->summary) !== '') {
            $lines[] = '## Summary';
            $lines[] = '';
            $lines[] = $this->block($report->summary);
            $lines[] = '';
        }

        array_push($lines, ...$this->confirmedLines($report, $confirmed));
        array_push($lines, ...$this->reviewLines($report, $reviewItems));

        return rtrim(implode("\n", $lines))."\n";
    }

    /**
     * The score line, or the reason it is withheld.
     *
     * @return array<int, string>
     */
    private function scoreLines(VulnerabilityReport $report): array
    {
        if (! $report->scoreIsMeaningful()) {
            return [
                '**Security score:** withheld — '.$this->inline((string) $report->scoreSuppressionReason()),
                '',
            ];
        }

        return [
            "**Security score:** {$report->overallScore}/100",
            '',
        ];
    }

    /**
     * Coverage statement plus every file that was not analysed.
     *
     * @return array<int, string>
     */
    private function coverageLines(VulnerabilityReport $report): array
    {
        $coverage = $report->getCoverage();
        $lines = ['**Coverage:** '.$this->inline($coverage?->describe() ?? 'not recorded for this run.'), ''];

        if ($coverage === null || $coverage->skipped === []) {
            return $lines;
        }

        $lines[] = '<details><summary>Files NOT analysed ('.$coverage->filesSkipped().')</summary>';
        $lines[] = '';

        foreach ($coverage->skippedByReason() as $reason => $paths) {
            $lines[] = '**'.$this->inline(ucfirst(ScanCoverage::reasonLabel($reason))).'**';
            $lines[] = '';

            foreach ($paths as $path) {
                $lines[] = '- '.$this->code($path);
            }

            $lines[] = '';
        }

        $lines[] = '</details>';
        $lines[] = '';

        return $lines;
    }

    /**
     * Count table by severity.
     *
     * @param  array<int, Vulnerability>  $confirmed
     * @param  array<int, Vulnerability>  $reviewItems
     * @return array<int, string>
     */
    private function summaryLines(array $confirmed, array $reviewItems): array
    {
        $lines = ['| Severity | Confirmed |', '|---|---|'];

        foreach (SeverityLevel::cases() as $severity) {
            $count = count(array_filter($confirmed, static fn (Vulnerability $v): bool => $v->severity === $severity));
            $lines[] = '| '.ucfirst($severity->value).' | '.$count.' |';
        }

        $lines[] = '| **Total** | **'.count($confirmed).'** |';
        $lines[] = '';
        $lines[] = sprintf('Plus %d item(s) flagged for human review (not counted, not scored).', count($reviewItems));
        $lines[] = '';

        return $lines;
    }

    /**
     * Confirmed vulnerabilities, one table per severity.
     *
     * @param  array<int, Vulnerability>  $confirmed
     * @return array<int, string>
     */
    private function confirmedLines(VulnerabilityReport $report, array $confirmed): array
    {
        $lines = ['## Confirmed vulnerabilities ('.count($confirmed).')', ''];

        if ($confirmed === []) {
            $lines[] = 'No confirmed vulnerabilities. '.$this->inline($report->coverageStatement());
            $lines[] = '';

            return $lines;
        }

        foreach (SeverityLevel::cases() as $severity) {
            $group = array_values(array_filter($confirmed, static fn (Vulnerability $v): bool => $v->severity === $severity));

            if ($group === []) {
                continue;
            }

            $lines[] = '### '.ucfirst($severity->value).' ('.count($group).')';
            $lines[] = '';
            $lines[] = '| Type | Location | Confidence | CWE | Description |';
            $lines[] = '|---|---|---|---|---|';

            foreach ($group as $finding) {
                $cweUrl = References::cweUrl($finding->type);
                $cwe = $cweUrl !== null ? '['.$finding->type->cweId().']('.$cweUrl.')' : $finding->type->cweId();

                $lines[] = '| '.implode(' | ', [
                    $this->cell($finding->type->label()),
                    $this->code($finding->location.':'.$finding->line),
                    $finding->confidence->value,
                    $cwe,
                    $this->cell($finding->description),
                ]).' |';
            }

            $lines[] = '';
        }

        $withFixes = array_values(array_filter($confirmed, static fn (Vulnerability $v): bool => $v->hasFix()));

        if ($withFixes !== []) {
            $lines[] = '<details><summary>Suggested fixes ('.count($withFixes).')</summary>';
            $lines[] = '';

            foreach ($withFixes as $finding) {
                $lines[] = '**'.$this->inline($finding->type->label()).'** — '.$this->code($finding->location.':'.$finding->line);
                $lines[] = '';
                $lines[] = $this->fence($finding->fix);
                $lines[] = '';
            }

            $lines[] = '</details>';
            $lines[] = '';
        }

        return $lines;
    }

    /**
     * The review section: questions, never fixes.
     *
     * @param  array<int, Vulnerability>  $reviewItems
     * @return array<int, string>
     */
    private function reviewLines(VulnerabilityReport $report, array $reviewItems): array
    {
        $lines = [
            '## Needs review ('.count($reviewItems).')',
            '',
            '_Not vulnerabilities. Security-sensitive code the analyzer could neither clear nor condemn. Excluded from the count, the score and the exit code; no fix is suggested._',
            '',
        ];

        if ($reviewItems === []) {
            $lines[] = 'Nothing was flagged for review.';
            $lines[] = '';

            return $lines;
        }

        $lines[] = '| Type | Location | Impact if real | Confidence | Question |';
        $lines[] = '|---|---|---|---|---|';

        foreach ($reviewItems as $item) {
            $lines[] = '| '.implode(' | ', [
                $this->cell($item->type->label()),
                $this->code($item->location.':'.$item->line),
                $item->severity->value,
                $item->confidence->value,
                $this->cell($item->description),
            ]).' |';
        }

        $lines[] = '';

        return $lines;
    }

    /**
     * Escape text for a single-line table cell.
     */
    private function cell(string $text): string
    {
        $flat = (string) preg_replace('/\s+/', ' ', trim($this->scrub($text)));

        return str_replace('|', '\|', $this->escapeMarkdown($flat));
    }

    /**
     * Escape text for inline prose.
     */
    private function inline(string $text): string
    {
        return $this->escapeMarkdown((string) preg_replace('/\s+/', ' ', trim($this->scrub($text))));
    }

    /**
     * Escape a multi-line paragraph block.
     */
    private function block(string $text): string
    {
        return $this->escapeMarkdown(trim($this->scrub($text)));
    }

    /**
     * Inline code span that cannot be broken out of by backticks in the text.
     */
    private function code(string $text): string
    {
        $flat = str_replace('|', '\|', (string) preg_replace('/\s+/', ' ', trim($this->scrub($text))));

        $fence = str_repeat('`', $this->longestBacktickRun($flat) + 1);

        return $fence.' '.$flat.' '.$fence;
    }

    /**
     * Fenced code block sized so the content cannot close it early.
     */
    private function fence(string $text): string
    {
        $scrubbed = $this->scrub($text);
        $fence = str_repeat('`', max(3, $this->longestBacktickRun($scrubbed) + 1));

        return $fence."\n".rtrim($scrubbed)."\n".$fence;
    }

    /**
     * Length of the longest run of consecutive backticks in the text.
     */
    private function longestBacktickRun(string $text): int
    {
        $longest = 0;

        preg_match_all('/`+/', $text, $matches);

        foreach ($matches[0] as $run) {
            $longest = max($longest, strlen($run));
        }

        return $longest;
    }

    /**
     * Neutralise Markdown and raw HTML in AI-authored text.
     */
    private function escapeMarkdown(string $text): string
    {
        $escaped = htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        return (string) preg_replace('/([\\\\`*_\[\]#!])/', '\\\\$1', $escaped);
    }

    /**
     * Replace invalid UTF-8 and strip control characters other than \n and \t.
     */
    private function scrub(string $text): string
    {
        return (string) preg_replace('/[\x{00}-\x{08}\x{0B}-\x{1F}\x{7F}]/u', '', mb_scrub($text, 'UTF-8'));
    }
}
