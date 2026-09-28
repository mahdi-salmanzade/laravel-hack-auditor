<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner;

use Mahdi\HackAuditor\Support\Fingerprint;

/**
 * A set of accepted findings that should not fail a build again.
 *
 * Entries are matched by FINGERPRINT (type, relative file and the normalised
 * content of the flagged source line — see Fingerprint). The original format
 * matched on md5(description), and the AI rewords descriptions between runs,
 * so an accepted finding kept coming back as "new" and teams stopped trusting
 * the baseline. Files written in the old format (no 'fingerprint' key) are
 * still honoured through the legacy file + type + description-hash match.
 */
class Baseline
{
    /**
     * The loaded baseline entries. Shape is not trusted: the file is
     * hand-editable and may be from an older version.
     *
     * @var array<int, mixed>
     */
    private array $entries = [];

    /**
     * Load baseline from a JSON file.
     *
     * If the file does not exist, the baseline is initialized with empty entries.
     */
    public function load(?string $path = null): self
    {
        $path = $this->resolvePath($path);

        if (! file_exists($path)) {
            $this->entries = [];

            return $this;
        }

        $decoded = json_decode((string) file_get_contents($path), true);

        $this->entries = is_array($decoded) ? array_values($decoded) : [];

        return $this;
    }

    /**
     * Check if a vulnerability is in the baseline.
     *
     * Pass the fingerprint the owning report assigned (VulnerabilityReport::
     * fingerprintOf) so duplicates within a file are matched one-to-one; it
     * is computed standalone when omitted. Malformed entries never match and
     * never throw.
     */
    public function contains(Vulnerability $vuln, ?string $fingerprint = null): bool
    {
        $fingerprint ??= $vuln->fingerprint();
        $legacyHash = null;

        foreach ($this->entries as $entry) {
            if (! is_array($entry)) {
                continue;
            }

            if (is_string($entry['fingerprint'] ?? null)) {
                if (hash_equals($entry['fingerprint'], $fingerprint)) {
                    return true;
                }

                continue;
            }

            // Legacy entry (no fingerprint): file + type + md5(description).
            $legacyHash ??= md5($vuln->description);

            if (
                is_string($entry['file'] ?? null)
                && is_string($entry['type'] ?? null)
                && is_string($entry['hash'] ?? null)
                && Fingerprint::normalisePath($entry['file']) === Fingerprint::normalisePath($vuln->location)
                && $entry['type'] === $vuln->type->value
                && $entry['hash'] === $legacyHash
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Save all findings from a report as the new baseline.
     *
     * The legacy 'hash' is still written so an older version of the package
     * reading this file keeps working.
     */
    public function save(VulnerabilityReport $report, ?string $path = null): void
    {
        $path = $this->resolvePath($path);

        $entries = array_map(
            fn (Vulnerability $vuln): array => [
                'fingerprint' => $report->fingerprintOf($vuln),
                'file' => Fingerprint::normalisePath($vuln->location),
                'line' => $vuln->line,
                'type' => $vuln->type->value,
                'hash' => md5($vuln->description),
            ],
            $report->vulnerabilities,
        );

        file_put_contents(
            $path,
            json_encode($entries, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
        );
    }

    /**
     * Filter a report to exclude baselined findings. Returns new findings only.
     *
     * Pass the owning report so each finding is matched by the fingerprint the
     * report assigned it; without one, findings are fingerprinted standalone.
     *
     * @param  array<int, Vulnerability>  $vulnerabilities
     * @return array{new: array<int, Vulnerability>, suppressed: int}
     */
    public function filter(array $vulnerabilities, ?VulnerabilityReport $report = null): array
    {
        $new = [];
        $suppressed = 0;

        foreach ($vulnerabilities as $vuln) {
            if ($this->contains($vuln, $report?->fingerprintOf($vuln))) {
                $suppressed++;
            } else {
                $new[] = $vuln;
            }
        }

        return [
            'new' => $new,
            'suppressed' => $suppressed,
        ];
    }

    /**
     * Check if a baseline file exists.
     */
    public function exists(?string $path = null): bool
    {
        return file_exists($this->resolvePath($path));
    }

    /**
     * Resolve the baseline file path from the given path or config.
     */
    public function resolvePath(?string $path = null): string
    {
        if ($path !== null) {
            return $path;
        }

        $resolved = config('hack-auditor.scan.baseline_path', base_path('hack-auditor-baseline.json'));

        return is_string($resolved) && $resolved !== '' ? $resolved : base_path('hack-auditor-baseline.json');
    }
}
