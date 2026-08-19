<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Report;

use Illuminate\Support\Facades\File;
use Mahdi\HackAuditor\Scanner\ScanCoverage;
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

        $scoreIsMeaningful = $report->scoreIsMeaningful();
        $score = $report->overallScore;

        // A penalty-only score over an empty or partial scan is not evidence.
        // Withhold the number rather than publish a figure the coverage cannot
        // support — an empty ring reads as "unknown", not "perfect".
        $scoreLabel = $scoreIsMeaningful ? (string) $score : 'n/a';
        $scoreColor = $scoreIsMeaningful
            ? $this->scoreColor($score, $report->criticalCount())
            : '#94a3b8';
        $strokeOffset = $scoreIsMeaningful
            ? self::RING_CIRCUMFERENCE * (1 - $score / 100)
            : self::RING_CIRCUMFERENCE;

        $findingsHtml = $this->buildFindingsHtml($report);
        $usageHtml = $this->buildUsageHtml($report);

        $stub = File::get($this->stubPath());

        $replacements = [
            '{{SCORE}}' => $scoreLabel,
            '{{SCORE_COLOR}}' => $scoreColor,
            '{{STROKE_OFFSET}}' => number_format($strokeOffset, 3, '.', ''),
            '{{CRITICAL_COUNT}}' => (string) $report->criticalCount(),
            '{{HIGH_COUNT}}' => (string) $report->highCount(),
            '{{MEDIUM_COUNT}}' => (string) $report->mediumCount(),
            '{{LOW_COUNT}}' => (string) $report->lowCount(),
            '{{TOTAL_COUNT}}' => (string) $report->totalCount(),
            '{{REVIEW_COUNT}}' => (string) $report->reviewCount(),
            '{{SCANNED_AT}}' => $this->escape($scannedAt),
            '{{DURATION}}' => $this->escape($duration),
            '{{TOTAL_FILES}}' => (string) $totalFiles,
            '{{PROVIDER}}' => $this->escape($provider),
            '{{SUMMARY}}' => $this->buildCoverageHtml($report).$this->buildSummaryHtml($report->summary),
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
     * Build the coverage banner shown above the summary.
     *
     * Returns an empty string for a complete scan. When files went unanalysed
     * the banner names every one of them, so a reader can never mistake a
     * partial report for a full audit.
     */
    private function buildCoverageHtml(VulnerabilityReport $report): string
    {
        $coverage = $report->getCoverage();

        if ($coverage === null || $coverage->isComplete()) {
            return '';
        }

        $html = '<p><strong>Incomplete scan — '.$this->escape($coverage->describe()).'</strong></p>';

        $reason = $report->scoreSuppressionReason();

        if ($reason !== null) {
            $html .= '<p>'.$this->escape($reason).'</p>';
        }

        foreach ($coverage->skippedByReason() as $skipReason => $paths) {
            $html .= '<p>'.$this->escape(ucfirst(ScanCoverage::reasonLabel($skipReason))).':</p><ul>';

            foreach ($paths as $path) {
                $html .= '<li><code>'.$this->escape($path).'</code></li>';
            }

            $html .= '</ul>';
        }

        return $html;
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
     * Build the findings body: confirmed vulnerabilities first, then the
     * questions the analyzer wants a human to answer.
     *
     * The two sections are visually distinct and worded differently on purpose.
     * The first makes claims; the second asks. Merging them into one list is
     * what let unproven findings be read — and acted on — as vulnerabilities.
     */
    private function buildFindingsHtml(VulnerabilityReport $report): string
    {
        return $this->buildConfirmedSection($report)
            ."\n"
            .$this->buildReviewSection($report);
    }

    /**
     * Build the "Confirmed vulnerabilities" section.
     *
     * When it is empty the section states what was analysed rather than
     * implying the code is clean: a zero here measures coverage, not safety.
     */
    private function buildConfirmedSection(VulnerabilityReport $report): string
    {
        $vulnerabilities = $this->sortedBySeverity($report->confirmedVulnerabilities());
        $count = count($vulnerabilities);

        $heading = <<<HTML
        <div class="class-heading" style="margin:8px 0 4px;font-size:13px;font-weight:700;letter-spacing:0.04em;text-transform:uppercase;color:#ef4444">Confirmed vulnerabilities ({$count})</div>
        <div class="class-note" style="margin-bottom:14px;font-size:12px;line-height:1.6;opacity:0.75">Asserted findings — a source, a sink and an unguarded path between them were resolved in the analysed code.</div>
        HTML;

        if ($count === 0) {
            $statement = $this->escape($report->coverageStatement());

            return $heading."\n"
                .'<div class="no-findings">No vulnerabilities found. '
                .'<span style="display:block;margin-top:6px;font-size:12px;opacity:0.75">'.$statement.'</span>'
                .'</div>';
        }

        // Group vulnerabilities by severity to build counts and dividers.
        $grouped = [];

        foreach ($vulnerabilities as $vulnerability) {
            $grouped[$vulnerability->severity->value][] = $vulnerability;
        }

        $cards = [$heading];

        $previousSeverity = null;

        foreach ($vulnerabilities as $vulnerability) {
            $currentSeverity = $vulnerability->severity->value;

            if ($currentSeverity !== $previousSeverity) {
                $severityCount = count($grouped[$currentSeverity]);
                $label = strtoupper($vulnerability->severity->name);
                $cards[] = <<<HTML
                <div class="severity-divider severity-{$currentSeverity}">
                  <span>{$label} ({$severityCount})</span>
                </div>
                HTML;
                $previousSeverity = $currentSeverity;
            }

            $cards[] = $this->buildFindingCard($vulnerability);
        }

        return implode("\n", $cards);
    }

    /**
     * Build the "Needs review" section.
     *
     * Review items render as questions with no fix block at all — the fix
     * string is already empty by construction, and printing an empty
     * "Recommended Fix" panel would invite someone to fill it in.
     */
    private function buildReviewSection(VulnerabilityReport $report): string
    {
        $items = $this->sortedBySeverity($report->reviewItems());
        $count = count($items);

        $html = <<<HTML
        <div class="class-heading" style="margin:28px 0 4px;padding-top:20px;border-top:1px dashed rgba(148,163,184,0.4);font-size:13px;font-weight:700;letter-spacing:0.04em;text-transform:uppercase;color:#eab308">Needs review ({$count})</div>
        <div class="class-note" style="margin-bottom:14px;font-size:12px;line-height:1.6;opacity:0.75">Not vulnerabilities. Security-sensitive code the analyzer could neither clear nor condemn, so it asks instead of asserting. These are excluded from the counts, the score and the exit code, and no fix is suggested for them.</div>
        HTML;

        if ($items === []) {
            return $html."\n".'<div class="no-findings">Nothing was flagged for review.</div>';
        }

        foreach ($items as $item) {
            $html .= "\n".$this->buildReviewCard($item);
        }

        return $html;
    }

    /**
     * Render one review item as a question card.
     */
    private function buildReviewCard(Vulnerability $item): string
    {
        $typeLabel = $this->escape($item->type->label());
        $location = $this->escape($item->location);
        $line = (string) $item->line;
        $severity = $this->escape(strtoupper($item->severity->name));
        $confidence = $this->escape($item->confidence->value);
        $description = $this->escape($item->description);
        $proof = $this->escape($item->proof);

        $proofBlock = $proof === '' ? '' : <<<HTML
        <div class="code-section">
          <div class="code-label">Code in question</div>
          <div class="code-block"><button class="copy-btn" onclick="copyCode(this)">Copy</button><pre><code>{$proof}</code></pre></div>
        </div>
        HTML;

        return <<<HTML
        <div class="finding-card review-card" data-expanded="false" style="border-left:3px dashed #eab308">
          <div class="finding-header" onclick="toggleCard(this)">
            <div class="finding-row-top">
              <span class="severity-badge" style="background:#eab308;color:#1c1917">REVIEW</span>
              <span class="finding-type">{$typeLabel}</span>
              <span class="toggle-icon">&#9654;</span>
            </div>
            <div class="finding-row-bottom">
              <span class="finding-location">{$location}:{$line}</span>
              <span class="owasp-tag" title="Impact if this turns out to be real">if real: {$severity}</span>
              <span class="owasp-tag" title="How much of the evidence chain was resolved">confidence: {$confidence}</span>
            </div>
          </div>
          <div class="finding-body">
            <p class="finding-description">{$description}</p>
            {$proofBlock}
            <p class="finding-description" style="opacity:0.75;font-size:12px">No fix is suggested: the analyzer did not resolve the evidence that would justify one. A human decides whether this is a problem.</p>
          </div>
        </div>
        HTML;
    }

    /**
     * Sort findings by severity, Critical first.
     *
     * @param  array<int, Vulnerability>  $findings
     * @return array<int, Vulnerability>
     */
    private function sortedBySeverity(array $findings): array
    {
        usort($findings, function (Vulnerability $a, Vulnerability $b): int {
            $orderA = self::SEVERITY_ORDER[$a->severity->value] ?? 99;
            $orderB = self::SEVERITY_ORDER[$b->severity->value] ?? 99;

            return $orderA <=> $orderB;
        });

        return $findings;
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
        $verificationBadge = $this->buildVerificationBadge($vulnerability);
        $exploitBlock = $this->buildExploitBlock($vulnerability);
        $fixBlock = $this->buildFixBlock($vulnerability);

        return <<<HTML
        <div class="finding-card severity-{$severityValue}" data-expanded="false">
          <div class="finding-header" onclick="toggleCard(this)">
            <div class="finding-row-top">
              <span class="severity-badge {$severityValue}">{$severityName}</span>
              <span class="finding-type">{$typeLabel}</span>
              {$verificationBadge}
              <span class="toggle-icon">&#9654;</span>
            </div>
            <div class="finding-row-bottom">
              <span class="finding-location">{$location}:{$line}</span>
              <span class="owasp-tag" title="{$fullOwasp}">{$shortOwasp}</span>
            </div>
          </div>
          <div class="finding-body">
            <p class="finding-description">{$description}</p>
            {$exploitBlock}
            <div class="code-section">
              <div class="code-label vulnerable-label">Vulnerable Code</div>
              <div class="code-block vulnerable-code"><button class="copy-btn" onclick="copyCode(this)">Copy</button><pre><code>{$proof}</code></pre></div>
            </div>
            {$fixBlock}
          </div>
        </div>
        HTML;
    }

    /**
     * Render the recommended-fix panel, or nothing when there is no fix.
     *
     * An empty "Recommended Fix" code block is an invitation to invent one.
     * Findings that could not justify a fix say so in words instead.
     */
    private function buildFixBlock(Vulnerability $vulnerability): string
    {
        if (! $vulnerability->hasFix()) {
            return '<p class="finding-description" style="opacity:0.75;font-size:12px">'
                .'No fix is suggested for this finding: the analyzer could not resolve every identifier a fix would have to name.'
                .'</p>';
        }

        $fix = $this->escape($vulnerability->fix);

        return <<<HTML
        <div class="code-section">
          <div class="code-label fix-label">Recommended Fix</div>
          <div class="code-block fix-code"><button class="copy-btn" onclick="copyCode(this)">Copy</button><pre><code>{$fix}</code></pre></div>
        </div>
        HTML;
    }

    /**
     * Build the inline verification badge shown in the finding header.
     *
     * Returns a green check badge for findings with a confirmed exploit,
     * a subtle downgrade badge (with original severity in the tooltip) for
     * findings the model could not exploit, or an empty string when
     * verification was not attempted.
     */
    private function buildVerificationBadge(Vulnerability $vulnerability): string
    {
        if ($vulnerability->exploitVerified === true) {
            return '<span class="verification-badge verified" style="margin-left:8px;padding:2px 8px;border-radius:4px;font-size:11px;background:#16a34a;color:#fff;" title="Exploit verified by a second AI pass">&#10003; Verified</span>';
        }

        if ($vulnerability->exploitVerified === false && $vulnerability->originalSeverity !== null) {
            $original = $this->escape(strtoupper($vulnerability->originalSeverity->name));
            $tooltip = "Downgraded from {$original} — the model could not construct a working exploit";

            return '<span class="verification-badge downgraded" style="margin-left:8px;padding:2px 8px;border-radius:4px;font-size:11px;background:#4b5563;color:#e5e7eb;" title="'.$this->escape($tooltip).'">&#9661; Downgraded from '.$original.'</span>';
        }

        return '';
    }

    /**
     * Render the verified exploit payload inside the expanded card body.
     *
     * Treats the payload as untrusted (HTML-escaped, never interpreted).
     * Returns an empty string when no exploit proof is attached.
     */
    private function buildExploitBlock(Vulnerability $vulnerability): string
    {
        if ($vulnerability->exploitVerified !== true || $vulnerability->exploitProof === null) {
            return '';
        }

        $exploit = $this->escape($vulnerability->exploitProof);

        return <<<HTML
        <div class="code-section">
          <div class="code-label vulnerable-label">Verified Exploit</div>
          <div class="code-block vulnerable-code"><button class="copy-btn" onclick="copyCode(this)">Copy</button><pre><code>{$exploit}</code></pre></div>
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
