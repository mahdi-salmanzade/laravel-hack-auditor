<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\AccessControl;

use Mahdi\HackAuditor\Scanner\Php\SemanticWorkspace;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * Orchestrates the deterministic access-control detectors and reconciles their
 * findings with the AI-produced findings.
 *
 * This is the OWASP-#1 (Broken Access Control / IDOR) detection moat: pure
 * static/contextual analysis that does not depend on an AI model and is fully
 * reproducible. Alongside the access-control detectors it also runs two further
 * reproducible detectors that close known AI-variance false-negatives — SSRF
 * (CWE-918, OWASP A10) and Sensitive Data Exposure (CWE-200, OWASP A02) — and
 * de-duplicates across both its own output and the AI findings so the report
 * never double-reports the same issue at the same file+line+type.
 */
final class AccessControlAnalyzer
{
    /**
     * Vulnerability types that describe the SAME class of access-control flaw
     * (OWASP A01 Broken Access Control) and must therefore collapse together
     * when reported at the same file+line, so the same underlying bug is never
     * double-reported or double-penalized. Deliberately narrow: CSRF and Open
     * Redirect also map to A01 but are distinct flaws and are NOT included.
     *
     * @var array<int, VulnerabilityType>
     */
    private const ACCESS_CONTROL_SYNONYMS = [
        VulnerabilityType::Idor,
        VulnerabilityType::AuthBypass,
    ];

    /**
     * Maximum line distance at which two same-file, same-type findings are
     * treated as the same issue and collapsed. Covers the common gap between a
     * method signature and the vulnerable statement a few lines into its body.
     */
    private const LINE_PROXIMITY = 5;

    /**
     * @var array<int, AccessControlDetector>
     */
    private array $detectors;

    /**
     * @param  array<int, AccessControlDetector>|null  $detectors
     */
    public function __construct(?array $detectors = null)
    {
        // ONE semantic layer for the whole run. Each detector used to build its
        // own — parsing the entire file set, then indexing it, five times over —
        // and each of those layers retained every ParsedFile it had produced.
        // That exhausted PHP's default 128M memory_limit part-way through a
        // 750-file application and killed the process outright: a fatal, not a
        // catchable Throwable, so the parser's own graceful-degradation path
        // never ran and the scan produced nothing at all.
        //
        // The shared workspace indexes the file set once and hands the same
        // context to every detector. Combined with the streaming SemanticContext
        // and the bounded parser cache, peak memory is now set by how many files
        // are open at once, not by how large the application is.
        $workspace = new SemanticWorkspace;

        $this->detectors = $detectors ?? [
            new SensitiveFillableDetector($workspace),
            new UnauthorizedModelFetchDetector($workspace),
            new PolicyRouteMismatchDetector($workspace),
            new SsrfDetector($workspace),
            new SensitiveDataExposureDetector($workspace),
        ];
    }

    /**
     * Run every detector over the given files and return deduplicated findings.
     *
     * @param  array<int, array{path: string, content: string, type: string}>  $files
     * @return array<int, Vulnerability>
     */
    public function analyze(array $files, AccessControlContext $context): array
    {
        $sourceFiles = array_map(
            static fn (array $file): SourceFile => SourceFile::fromArray($file),
            $files,
        );

        $found = [];

        foreach ($this->detectors as $detector) {
            foreach ($detector->detect($sourceFiles, $context) as $vulnerability) {
                $found[] = $vulnerability;
            }
        }

        return $this->dedupe($found);
    }

    /**
     * Merge deterministic access-control findings with an existing finding list
     * (typically the AI findings) and de-duplicate across the ENTIRE combined
     * list, keeping the FIRST occurrence of each fingerprint.
     *
     * Deduping the whole list — rather than only the deterministic findings
     * against the existing ones — collapses (a) two AI findings of the same
     * type at the same place (e.g. the same IDOR reported at two nearby lines)
     * and (b) an AI finding and a deterministic finding for the same flaw whose
     * `location` strings differ only in path format (basename vs absolute vs
     * relative). Existing findings are visited before deterministic ones, so an
     * AI finding always wins the "first occurrence" tie and is the one kept.
     *
     * @param  array<int, Vulnerability>  $existing  AI/other findings (visited first; win ties)
     * @param  array<int, Vulnerability>  $deterministic  Access-control findings to merge in
     * @return array<int, Vulnerability>
     */
    public function merge(array $existing, array $deterministic): array
    {
        return $this->dedupe([...$existing, ...$deterministic]);
    }

    /**
     * Remove duplicate findings within a list by fingerprint, keeping the first
     * occurrence. Used both for a single detector pass and for the combined
     * AI-plus-deterministic list in merge().
     *
     * @param  array<int, Vulnerability>  $findings
     * @return array<int, Vulnerability>
     */
    private function dedupe(array $findings): array
    {
        $kept = [];

        foreach ($findings as $vulnerability) {
            foreach ($kept as $existing) {
                if ($this->isSameIssue($vulnerability, $existing)) {
                    continue 2;
                }
            }

            $kept[] = $vulnerability;
        }

        return array_values($kept);
    }

    /**
     * Decide whether two findings describe the SAME underlying issue and should
     * collapse into one.
     *
     * Two findings are the same issue when they share a file, a type, and sit
     * within LINE_PROXIMITY lines of each other:
     *
     * - Location is compared by lowercased BASENAME, not the full path, so the
     *   same file collapses whether one source reported a basename, a relative
     *   path, or an absolute path.
     * - Lines are compared by PROXIMITY (absolute distance) rather than by a fixed
     *   bucket. A fixed floor(line/3) bucket put adjacent lines on opposite sides
     *   of a boundary (e.g. line 14 in bucket 4 but line 15 in bucket 5), so the
     *   same vulnerability reported a couple of lines apart by the AI and the
     *   deterministic detector failed to collapse. Proximity has no such seams.
     * - Access-control SYNONYMS (Idor and AuthBypass, both OWASP A01) share a
     *   single type token so the same flaw is never reported or penalized twice.
     *
     * Residual risk: two genuinely different files that share a basename AND have
     * a same-type finding within LINE_PROXIMITY lines would collapse. This is
     * rare, and the alternative (path-sensitive matching) misses the far more
     * common case of the same file referenced by differently-formatted paths.
     */
    private function isSameIssue(Vulnerability $a, Vulnerability $b): bool
    {
        return $this->basename($a->location) === $this->basename($b->location)
            && $this->typeToken($a->type) === $this->typeToken($b->type)
            && abs($a->line - $b->line) <= self::LINE_PROXIMITY;
    }

    /**
     * Lowercased file basename used for path-format-tolerant location matching.
     */
    private function basename(string $location): string
    {
        return strtolower(basename(str_replace('\\', '/', $location)));
    }

    /**
     * Map a vulnerability type to a dedupe token. Access-control synonyms share
     * one token so they merge; every other type keeps its own backing value.
     */
    private function typeToken(VulnerabilityType $type): string
    {
        if (in_array($type, self::ACCESS_CONTROL_SYNONYMS, true)) {
            return 'access_control';
        }

        return $type->value;
    }
}
