<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Report;

use Illuminate\Support\Facades\File;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;

class HtmlReportGenerator
{
    /**
     * Severity sort order: Critical first, Low last.
     *
     * @var array<string, int>
     */
    private const array SEVERITY_ORDER = [
        'critical' => 0,
        'high' => 1,
        'medium' => 2,
        'low' => 3,
    ];

    /**
     * Circumference of the SVG score ring (2 * PI * 54).
     */
    private const float RING_CIRCUMFERENCE = 339.292;

    /**
     * Generate a self-contained HTML security report from a VulnerabilityReport.
     *
     * @param  array{scanned_at?: string, duration?: string, paths_scanned?: array<int, string>, provider?: string, model?: string, total_files?: int}  $meta
     */
    public function generate(VulnerabilityReport $report, array $meta = []): string
    {
        $scannedAt = $meta['scanned_at'] ?? now()->format('Y-m-d H:i:s');
        $duration = $meta['duration'] ?? 'N/A';
        $totalFiles = $meta['total_files'] ?? $this->countUniqueFiles($report);
        $provider = $this->resolveProvider($meta);

        $score = $report->overallScore;
        $scoreColor = $this->scoreColor($score, $report->criticalCount());
        $strokeOffset = self::RING_CIRCUMFERENCE * (1 - $score / 100);

        $findingsHtml = $this->buildFindingsHtml($report);
        $usageHtml = $this->buildUsageHtml($report);

        $stub = File::get($this->stubPath());

        $replacements = [
            '{{SCORE}}' => (string) $score,
            '{{SCORE_COLOR}}' => $scoreColor,
            '{{STROKE_OFFSET}}' => number_format($strokeOffset, 3, '.', ''),
            '{{CRITICAL_COUNT}}' => (string) $report->criticalCount(),
            '{{HIGH_COUNT}}' => (string) $report->highCount(),
            '{{MEDIUM_COUNT}}' => (string) $report->mediumCount(),
            '{{LOW_COUNT}}' => (string) $report->lowCount(),
            '{{TOTAL_COUNT}}' => (string) $report->totalCount(),
            '{{SCANNED_AT}}' => $this->escape($scannedAt),
            '{{DURATION}}' => $this->escape($duration),
            '{{TOTAL_FILES}}' => (string) $totalFiles,
            '{{PROVIDER}}' => $this->escape($provider),
            '{{SUMMARY}}' => $this->buildSummaryHtml($report->summary),
            '{{FINDINGS}}' => $findingsHtml,
            '{{USAGE_SECTION}}' => $usageHtml,
        ];

        return str_replace(
            array_keys($replacements),
            array_values($replacements),
            $stub,
        );
    }

    /**
     * Determine the score color based on overall score and critical finding count.
     */
    private function scoreColor(int $score, int $criticalCount): string
    {
        if ($criticalCount >= 3) {
            return '#ef4444';
        }

        if ($criticalCount >= 1 && $score < 70) {
            return $score < 50 ? '#ef4444' : '#f97316';
        }

        return match (true) {
            $score < 40 => '#ef4444',
            $score < 60 => '#f97316',
            $score < 80 => '#eab308',
            default => '#22c55e',
        };
    }

    /**
     * Build the summary HTML, splitting on double-newlines into paragraphs.
     *
     * When there are more than 2 paragraphs, the summary is collapsible.
     */
    private function buildSummaryHtml(string $summary): string
    {
        $paragraphs = array_filter(
            array_map('trim', explode("\n\n", $summary)),
            fn (string $p): bool => $p !== '',
        );

        if ($paragraphs === []) {
            return '<p>'.$this->escape($summary).'</p>';
        }

        $html = implode("\n", array_map(
            fn (string $p): string => '<p>'.$this->escape($p).'</p>',
            $paragraphs,
        ));

        if (count($paragraphs) > 2) {
            return '<div class="summary-collapsed" id="summaryContent">'.$html.'</div>'
                .'<button class="summary-toggle" onclick="toggleSummary()">Read full summary</button>';
        }

        return $html;
    }

    /**
     * Build the token usage section HTML when usage data is available.
     *
     * Returns an empty string when no usage data is present, so the
     * {{USAGE_SECTION}} placeholder is cleanly removed from the stub.
     */
    private function buildUsageHtml(VulnerabilityReport $report): string
    {
        if (! $report->hasUsageData()) {
            return '';
        }

        $tracker = $report->getUsageTracker();
        $promptTokens = number_format($tracker->getPromptTokens());
        $completionTokens = number_format($tracker->getCompletionTokens());
        $totalTokens = number_format($tracker->totalTokens());
        $requests = (string) $tracker->getRequests();
        $cost = sprintf('$%.4f', $tracker->estimateCost());
        $duration = sprintf('%.1fs', $tracker->getElapsedSeconds());
        $filesSkipped = $report->getFilesSkipped();

        $cards = <<<HTML
            <div class="meta-card">
                <div class="meta-label">Token Usage</div>
                <div class="meta-value mono">{$totalTokens}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Prompt / Completion</div>
                <div class="meta-value mono">{$promptTokens} / {$completionTokens}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">AI Requests</div>
                <div class="meta-value">{$requests}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Estimated Cost</div>
                <div class="meta-value mono">{$cost}</div>
            </div>
        HTML;

        if ($tracker->isLimitSet()) {
            $limit = number_format($tracker->getTokenLimit());
            $percent = sprintf('%.1f%%', $tracker->getUsagePercent());
            $cards .= <<<HTML

                <div class="meta-card">
                    <div class="meta-label">Budget Used</div>
                    <div class="meta-value mono">{$percent} of {$limit}</div>
                </div>
            HTML;
        }

        if ($filesSkipped > 0) {
            $cards .= <<<HTML

                <div class="meta-card">
                    <div class="meta-label">Files Skipped</div>
                    <div class="meta-value" style="color:var(--high)">{$filesSkipped}</div>
                </div>
            HTML;
        }

        return <<<HTML

            <!-- Token Usage -->
            <div style="margin-top:8px;margin-bottom:4px;font-size:12px;font-weight:600;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-dim)">Token Usage</div>
            <div class="meta-grid">
                {$cards}
            </div>
        HTML;
    }

    /**
     * Build the HTML for all finding cards, sorted by severity (Critical first).
     *
     * Inserts severity group dividers when the severity level changes.
     */
    private function buildFindingsHtml(VulnerabilityReport $report): string
    {
        $vulnerabilities = $report->vulnerabilities;

        usort($vulnerabilities, function (Vulnerability $a, Vulnerability $b): int {
            $orderA = self::SEVERITY_ORDER[$a->severity->value] ?? 99;
            $orderB = self::SEVERITY_ORDER[$b->severity->value] ?? 99;

            return $orderA <=> $orderB;
        });

        if ($vulnerabilities === []) {
            return '<div class="no-findings">No vulnerabilities found.</div>';
        }

        // Group vulnerabilities by severity to build counts and dividers.
        $grouped = [];

        foreach ($vulnerabilities as $vulnerability) {
            $grouped[$vulnerability->severity->value][] = $vulnerability;
        }

        $cards = [];

        $previousSeverity = null;

        foreach ($vulnerabilities as $vulnerability) {
            $currentSeverity = $vulnerability->severity->value;

            if ($currentSeverity !== $previousSeverity) {
                $count = count($grouped[$currentSeverity]);
                $label = strtoupper($vulnerability->severity->name);
                $cards[] = <<<HTML
                <div class="severity-divider severity-{$currentSeverity}">
                  <span>{$label} ({$count})</span>
                </div>
                HTML;
                $previousSeverity = $currentSeverity;
            }

            $cards[] = $this->buildFindingCard($vulnerability);
        }

        return implode("\n", $cards);
    }

    /**
     * Build a single finding card HTML block for a vulnerability.
     */
    private function buildFindingCard(Vulnerability $vulnerability): string
    {
        $severityValue = $this->escape($vulnerability->severity->value);
        $severityName = $this->escape(strtoupper($vulnerability->severity->name));
        $typeLabel = $this->escape($vulnerability->type->label());
        $location = $this->escape($vulnerability->location);
        $line = (string) $vulnerability->line;
        $fullOwasp = $this->escape($vulnerability->type->owaspCategory());
        $shortOwasp = $this->escape($this->truncateOwasp($vulnerability->type->owaspCategory()));
        $description = $this->escape($vulnerability->description);
        $proof = $this->escape($vulnerability->proof);
        $fix = $this->escape($vulnerability->fix);

        return <<<HTML
        <div class="finding-card severity-{$severityValue}" data-expanded="false">
          <div class="finding-header" onclick="toggleCard(this)">
            <div class="finding-row-top">
              <span class="severity-badge {$severityValue}">{$severityName}</span>
              <span class="finding-type">{$typeLabel}</span>
              <span class="toggle-icon">&#9654;</span>
            </div>
            <div class="finding-row-bottom">
              <span class="finding-location">{$location}:{$line}</span>
              <span class="owasp-tag" title="{$fullOwasp}">{$shortOwasp}</span>
            </div>
          </div>
          <div class="finding-body">
            <p class="finding-description">{$description}</p>
            <div class="code-section">
              <div class="code-label vulnerable-label">Vulnerable Code</div>
              <div class="code-block vulnerable-code"><button class="copy-btn" onclick="copyCode(this)">Copy</button><pre><code>{$proof}</code></pre></div>
            </div>
            <div class="code-section">
              <div class="code-label fix-label">Recommended Fix</div>
              <div class="code-block fix-code"><button class="copy-btn" onclick="copyCode(this)">Copy</button><pre><code>{$fix}</code></pre></div>
            </div>
          </div>
        </div>
        HTML;
    }

    /**
     * Truncate an OWASP category string to just the code (e.g. "A07:2021").
     */
    private function truncateOwasp(string $owasp): string
    {
        if (preg_match('/^(A\d{2}:\d{4})/', $owasp, $matches)) {
            return $matches[1];
        }

        return $owasp;
    }

    /**
     * Resolve the provider display string from meta or config fallback.
     *
     * @param  array{provider?: string, model?: string}  $meta
     */
    private function resolveProvider(array $meta): string
    {
        /** @var ?string $configProvider */
        $configProvider = config('hack-auditor.ai.provider');

        /** @var ?string $configModel */
        $configModel = config('hack-auditor.ai.model');

        $provider = $meta['provider'] ?? $configProvider ?? 'default';
        $model = $meta['model'] ?? $configModel ?? 'default';

        return $provider.' / '.$model;
    }

    /**
     * Count unique file locations across all vulnerabilities in the report.
     */
    private function countUniqueFiles(VulnerabilityReport $report): int
    {
        $files = array_unique(
            array_map(
                fn (Vulnerability $v): string => $v->location,
                $report->vulnerabilities,
            ),
        );

        return count($files);
    }

    /**
     * Return the absolute path to the report HTML stub.
     */
    private function stubPath(): string
    {
        return dirname(__DIR__, 2).'/resources/stubs/report.stub';
    }

    /**
     * HTML-escape a string for safe embedding in HTML output.
     */
    private function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
    }
}
