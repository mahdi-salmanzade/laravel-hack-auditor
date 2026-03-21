<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Support;

use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;

final class ShareHelper
{
    /**
     * Generate a Twitter/X share intent URL with pre-filled scan results.
     */
    public function twitterUrl(VulnerabilityReport $report): string
    {
        /** @var array<int, string> $hashtags */
        $hashtags = config('hack-auditor.share.default_hashtags', [
            '#LaravelSecurity',
            '#HackAuditor',
            '#CTF',
        ]);

        $hashtagString = implode(' ', $hashtags);

        $criticalLabel = $report->criticalCount() > 0
            ? " | {$report->criticalCount()} Critical"
            : '';

        $tweet = implode("\n", [
            "\xF0\x9F\x94\x93 AI Security Scan Results: Score {$report->overallScore}/100 | Found {$report->totalCount()} vulnerabilities{$criticalLabel}",
            '',
            'php artisan hack:scan',
            '',
            'mahdisphp/laravel-hack-auditor',
            $hashtagString,
        ]);

        return 'https://twitter.com/intent/tweet?text='.rawurlencode($tweet);
    }

    /**
     * Generate a markdown summary suitable for README badges and reports.
     */
    public function markdownSummary(VulnerabilityReport $report): string
    {
        $scoreColor = match (true) {
            $report->overallScore >= 80 => 'brightgreen',
            $report->overallScore >= 60 => 'yellow',
            $report->overallScore >= 40 => 'orange',
            default => 'red',
        };

        $badge = "![Security Score](https://img.shields.io/badge/security%20score-{$report->overallScore}%2F100-{$scoreColor})";

        $lines = [
            $badge,
            '',
            '## Vulnerability Summary',
            '',
            '| Severity | Count |',
            '|----------|-------|',
            "| \xF0\x9F\x94\xB4 Critical | {$report->criticalCount()} |",
            "| \xF0\x9F\x9F\xA0 High | {$report->highCount()} |",
            "| \xF0\x9F\x9F\xA1 Medium | {$report->mediumCount()} |",
            "| \xF0\x9F\x9F\xA2 Low | {$report->lowCount()} |",
            "| **Total** | **{$report->totalCount()}** |",
            '',
            $report->summary,
        ];

        return implode("\n", $lines);
    }

    /**
     * Generate a punchy tweet using AI based on actual scan results.
     *
     * Falls back to a template-based tweet if AI is unavailable.
     */
    public function generateTweet(VulnerabilityReport $report, AIAdapter $ai, PromptBuilder $promptBuilder): string
    {
        if (! config('hack-auditor.share.ai_tweets', true)) {
            return $this->templateTweet($report);
        }

        $topFinding = '';

        if (count($report->vulnerabilities) > 0) {
            $topFinding = $report->vulnerabilities[0]->description;
        }

        try {
            $systemPrompt = $promptBuilder->tweetSystemPrompt();
            $userPrompt = $promptBuilder->tweetUserPrompt(
                $report->overallScore,
                $report->totalCount(),
                $report->criticalCount(),
                $report->highCount(),
                $topFinding,
            );

            $tweet = trim($ai->send($systemPrompt, $userPrompt));

            // Strip quotes if AI wraps the tweet in them
            $tweet = trim($tweet, '"\'');

            if (mb_strlen($tweet) > 280) {
                $tweet = mb_substr($tweet, 0, 277).'...';
            }

            return $tweet;
        } catch (\Throwable) {
            return $this->templateTweet($report);
        }
    }

    /**
     * Generate a template-based fallback tweet without AI.
     */
    public function templateTweet(VulnerabilityReport $report): string
    {
        $critical = $report->criticalCount() > 0
            ? " ({$report->criticalCount()} critical)"
            : '';

        return "Just scanned my Laravel app with hack-auditor. Score: {$report->overallScore}/100. Found {$report->totalCount()} vulnerabilities{$critical}. Time to fix some things.";
    }

    /**
     * Generate styled console output for the sharing prompt with box drawing characters.
     */
    public function consoleShareBlock(VulnerabilityReport $report): string
    {
        $score = str_pad((string) $report->overallScore, 3, ' ', STR_PAD_LEFT);
        $total = (string) $report->totalCount();
        $critical = (string) $report->criticalCount();
        $high = (string) $report->highCount();
        $medium = (string) $report->mediumCount();
        $low = (string) $report->lowCount();

        $innerWidth = 44;
        $hr = str_repeat("\xE2\x94\x80", $innerWidth);

        $lines = [
            "\xE2\x94\x8C{$hr}\xE2\x94\x90",
            "\xE2\x94\x82".$this->centerText("\xF0\x9F\x94\x93 Hack Auditor Scan Results", $innerWidth)."\xE2\x94\x82",
            "\xE2\x94\x9C{$hr}\xE2\x94\xA4",
            "\xE2\x94\x82".$this->padRight("  Security Score: {$score}/100", $innerWidth)."\xE2\x94\x82",
            "\xE2\x94\x82".$this->padRight("  Vulnerabilities Found: {$total}", $innerWidth)."\xE2\x94\x82",
            "\xE2\x94\x9C{$hr}\xE2\x94\xA4",
            "\xE2\x94\x82".$this->padRight("  \xF0\x9F\x94\xB4 Critical: {$critical}", $innerWidth)."\xE2\x94\x82",
            "\xE2\x94\x82".$this->padRight("  \xF0\x9F\x9F\xA0 High:     {$high}", $innerWidth)."\xE2\x94\x82",
            "\xE2\x94\x82".$this->padRight("  \xF0\x9F\x9F\xA1 Medium:   {$medium}", $innerWidth)."\xE2\x94\x82",
            "\xE2\x94\x82".$this->padRight("  \xF0\x9F\x9F\xA2 Low:      {$low}", $innerWidth)."\xE2\x94\x82",
            "\xE2\x94\x9C{$hr}\xE2\x94\xA4",
            "\xE2\x94\x82".$this->centerText('Share your results!', $innerWidth)."\xE2\x94\x82",
            "\xE2\x94\x82".$this->centerText('php artisan hack:share', $innerWidth)."\xE2\x94\x82",
            "\xE2\x94\x94{$hr}\xE2\x94\x98",
        ];

        return implode("\n", $lines);
    }

    /**
     * Center text within a fixed-width field, accounting for multibyte characters.
     */
    private function centerText(string $text, int $width): string
    {
        $visibleLength = $this->visibleLength($text);
        $padding = max(0, $width - $visibleLength);
        $leftPad = (int) floor($padding / 2);
        $rightPad = (int) ceil($padding / 2);

        return str_repeat(' ', $leftPad).$text.str_repeat(' ', $rightPad);
    }

    /**
     * Pad text to the right within a fixed-width field, accounting for multibyte characters.
     */
    private function padRight(string $text, int $width): string
    {
        $visibleLength = $this->visibleLength($text);
        $padding = max(0, $width - $visibleLength);

        return $text.str_repeat(' ', $padding);
    }

    /**
     * Calculate the visible character length, accounting for emoji widths.
     *
     * Emoji characters typically occupy 2 terminal columns but mb_strlen
     * counts them as 1. This method estimates the visible width for
     * terminal alignment purposes.
     */
    private function visibleLength(string $text): int
    {
        $emojiCount = preg_match_all('/[\x{1F000}-\x{1FFFF}]/u', $text);

        return mb_strlen($text, 'UTF-8') + ($emojiCount ?: 0);
    }
}
