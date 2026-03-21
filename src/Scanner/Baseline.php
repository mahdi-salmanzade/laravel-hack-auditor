<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner;

class Baseline
{
    /**
     * The loaded baseline entries.
     *
     * @var array<int, array{file: string, line: int, type: string, hash: string}>
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

        $contents = (string) file_get_contents($path);

        /** @var array<int, array{file: string, line: int, type: string, hash: string}> $decoded */
        $decoded = json_decode($contents, true);

        $this->entries = is_array($decoded) ? $decoded : [];

        return $this;
    }

    /**
     * Check if a vulnerability is in the baseline (matches by file + type + hash).
     *
     * The hash is md5 of the description, so line number changes don't break matching.
     */
    public function contains(Vulnerability $vuln): bool
    {
        $hash = md5($vuln->description);

        foreach ($this->entries as $entry) {
            if (
                $entry['file'] === $vuln->location
                && $entry['type'] === $vuln->type->value
                && $entry['hash'] === $hash
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Save all findings from a report as the new baseline.
     */
    public function save(VulnerabilityReport $report, ?string $path = null): void
    {
        $path = $this->resolvePath($path);

        $entries = array_map(
            fn (Vulnerability $vuln): array => [
                'file' => $vuln->location,
                'line' => $vuln->line,
                'type' => $vuln->type->value,
                'hash' => md5($vuln->description),
            ],
            $report->vulnerabilities,
        );

        file_put_contents(
            $path,
            (string) json_encode($entries, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE),
        );
    }

    /**
     * Filter a report to exclude baselined findings. Returns new findings only.
     *
     * @param  array<int, Vulnerability>  $vulnerabilities
     * @return array{new: array<int, Vulnerability>, suppressed: int}
     */
    public function filter(array $vulnerabilities): array
    {
        $new = [];
        $suppressed = 0;

        foreach ($vulnerabilities as $vuln) {
            if ($this->contains($vuln)) {
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
    private function resolvePath(?string $path): string
    {
        if ($path !== null) {
            return $path;
        }

        /** @var string $resolved */
        $resolved = config('hack-auditor.scan.baseline_path', base_path('hack-auditor-baseline.json'));

        return $resolved;
    }
}
