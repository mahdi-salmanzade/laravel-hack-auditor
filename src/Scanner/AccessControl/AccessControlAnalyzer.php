<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\AccessControl;

use Mahdi\HackAuditor\Scanner\Php\SemanticWorkspace;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\VulnerabilityType;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use Throwable;

/**
 * Orchestrates the deterministic access-control detectors and reconciles their
 * findings with the AI-produced findings.
 *
 * This is the OWASP-#1 (Broken Access Control / IDOR) detection moat: pure
 * static/contextual analysis that does not depend on an AI model and is fully
 * reproducible. Alongside the access-control detectors it also runs two further
 * reproducible detectors that close known AI-variance false-negatives — SSRF
 * (CWE-918, OWASP A10) and Sensitive Data Exposure (CWE-200, OWASP A02) — and
 * reconciles its output with the AI findings so the report never
 * double-reports the same issue (see merge() for the exact rules).
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
     * Maximum line distance at which an AI finding and a deterministic finding
     * of the same file and type are treated as the same issue and collapsed. Covers the common gap between a
     * method signature and the vulnerable statement a few lines into its body.
     */
    private const LINE_PROXIMITY = 5;

    /**
     * Maximum line distance at which two findings from the SAME source may be
     * one issue reported twice — and then only with identical evidence.
     */
    private const SAME_SOURCE_PROXIMITY = 2;

    /**
     * @var array<int, AccessControlDetector>
     */
    private array $detectors;

    /**
     * Cached, normalised application base path; false until first resolved.
     */
    private string|false|null $basePath = false;

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

        return $this->collapseSameMethodAccessControl($this->dedupe($found), $sourceFiles);
    }

    /**
     * Keep one access-control finding per method.
     *
     * Two detectors can reach the same missing check from different ends: the
     * policy/route-mismatch detector reports a policy that exists but is never
     * applied (at the method signature), and the unauthorized-fetch detector
     * reports the unguarded record write it enables (at the statement, lines
     * later). Both are true and both describe ONE fix, so reporting both
     * double-counts a single bug in the score and in the build gate. Within a
     * method the AuthBypass finding is kept — it names the policy that already
     * exists, which is the better remedy — and same-method Idor findings are
     * dropped. Method bounds come from the AST, never from line proximity.
     *
     * @param  array<int, Vulnerability>  $findings
     * @param  array<int, SourceFile>  $sourceFiles
     * @return array<int, Vulnerability>
     */
    private function collapseSameMethodAccessControl(array $findings, array $sourceFiles): array
    {
        $bypassSpans = [];

        foreach ($findings as $finding) {
            if ($finding->type !== VulnerabilityType::AuthBypass) {
                continue;
            }

            $span = $this->methodSpanAt($finding->location, $finding->line, $sourceFiles);

            if ($span !== null) {
                $bypassSpans[] = ['location' => $finding->location, 'span' => $span];
            }
        }

        if ($bypassSpans === []) {
            return $findings;
        }

        return array_values(array_filter($findings, function (Vulnerability $finding) use ($bypassSpans): bool {
            if ($finding->type !== VulnerabilityType::Idor) {
                return true;
            }

            foreach ($bypassSpans as $bypass) {
                if ($this->isSameFile($finding->location, $bypass['location'])
                    && $finding->line >= $bypass['span'][0]
                    && $finding->line <= $bypass['span'][1]) {
                    return false;
                }
            }

            return true;
        }));
    }

    /**
     * The [start, end] lines of the class method containing a line, or null.
     *
     * @param  array<int, SourceFile>  $sourceFiles
     * @return array{0: int, 1: int}|null
     */
    private function methodSpanAt(string $location, int $line, array $sourceFiles): ?array
    {
        foreach ($sourceFiles as $file) {
            if (! $this->isSameFile($file->path, $location)) {
                continue;
            }

            try {
                $ast = (new ParserFactory)->createForNewestSupportedVersion()->parse($file->content) ?? [];
            } catch (Throwable) {
                return null;
            }

            foreach ((new NodeFinder)->findInstanceOf($ast, ClassMethod::class) as $method) {
                if ($line >= $method->getStartLine() && $line <= $method->getEndLine()) {
                    return [$method->getStartLine(), $method->getEndLine()];
                }
            }

            return null;
        }

        return null;
    }

    /**
     * Merge deterministic access-control findings with an existing finding list
     * (typically the AI findings), collapsing only what is genuinely the same
     * issue.
     *
     * Two different rules apply, because the two kinds of overlap have
     * different causes:
     *
     * - ACROSS sources (an AI finding vs a deterministic finding), the same
     *   flaw is routinely reported a few lines apart — the AI at the vulnerable
     *   statement, the detector at the method signature — and with differently
     *   formatted paths. These collapse on same file + same type token + line
     *   PROXIMITY. This is the v1.7 dedup fix that took benchmark precision
     *   from ≈0.73 to ≈0.89, and it is kept as-is for the cross-source case.
     * - WITHIN one source, two findings at different lines are two claims.
     *   Proximity used to apply here too, so two separate SQL injections four
     *   lines apart in one method became one, and an IDOR at line 20 swallowed
     *   the auth bypass at line 24. Within a source only EXACT duplicates
     *   (same file, same type token, same line) collapse.
     *
     * Existing findings are visited before deterministic ones, so an AI
     * finding always wins a cross-source tie and is the one kept.
     *
     * @param  array<int, Vulnerability>  $existing  AI/other findings (visited first; win ties)
     * @param  array<int, Vulnerability>  $deterministic  Access-control findings to merge in
     * @return array<int, Vulnerability>
     */
    public function merge(array $existing, array $deterministic): array
    {
        $kept = $this->dedupe($existing);

        foreach ($this->dedupe($deterministic) as $candidate) {
            foreach ($kept as $existingFinding) {
                if ($this->isSameIssueAcrossSources($candidate, $existingFinding)) {
                    continue 2;
                }
            }

            $kept[] = $candidate;
        }

        return array_values($kept);
    }

    /**
     * Remove exact duplicates from a single-source list, keeping the first
     * occurrence. Used for one detector pass and for each side of merge().
     *
     * @param  array<int, Vulnerability>  $findings
     * @return array<int, Vulnerability>
     */
    private function dedupe(array $findings): array
    {
        $kept = [];

        foreach ($findings as $vulnerability) {
            foreach ($kept as $existing) {
                if ($this->isExactDuplicate($vulnerability, $existing)) {
                    continue 2;
                }
            }

            $kept[] = $vulnerability;
        }

        return array_values($kept);
    }

    /**
     * Whether two findings from the SAME source are one finding emitted twice.
     *
     * Same file and type token, and either the same line, or lines within
     * SAME_SOURCE_PROXIMITY carrying the same evidence (identical proof or
     * description once whitespace is normalised). The evidence condition is
     * what separates a model reporting one issue twice at adjacent lines —
     * which it does — from two genuine injections a few lines apart, which
     * proximity alone used to merge into one, losing a real finding.
     *
     * Access-control SYNONYMS (Idor and AuthBypass, both OWASP A01) share a
     * token, so the same flaw labelled both ways at one line still collapses.
     */
    private function isExactDuplicate(Vulnerability $a, Vulnerability $b): bool
    {
        if ($this->typeToken($a->type) !== $this->typeToken($b->type)
            || ! $this->isSameFile($a->location, $b->location)) {
            return false;
        }

        if ($a->line === $b->line) {
            return true;
        }

        if (abs($a->line - $b->line) > self::SAME_SOURCE_PROXIMITY) {
            return false;
        }

        $normalise = static fn (string $text): string => strtolower(trim((string) preg_replace('/\s+/', ' ', $text)));

        $sameProof = $normalise($a->proof) !== '' && $normalise($a->proof) === $normalise($b->proof);
        $sameDescription = $normalise($a->description) !== '' && $normalise($a->description) === $normalise($b->description);

        return $sameProof || $sameDescription;
    }

    /**
     * Decide whether an AI finding and a deterministic finding describe the
     * SAME underlying issue and should collapse into one.
     *
     * - Same file, by normalised path (see isSameFile()).
     * - Same type token: access-control SYNONYMS (Idor and AuthBypass) share
     *   one, so the same flaw is never reported or penalized twice.
     * - Lines within LINE_PROXIMITY. A fixed floor(line/3) bucket used to put
     *   adjacent lines on opposite sides of a boundary (line 14 in bucket 4,
     *   line 15 in bucket 5); proximity has no such seams.
     */
    private function isSameIssueAcrossSources(Vulnerability $a, Vulnerability $b): bool
    {
        return abs($a->line - $b->line) <= self::LINE_PROXIMITY
            && $this->typeToken($a->type) === $this->typeToken($b->type)
            && $this->isSameFile($a->location, $b->location);
    }

    /**
     * Whether two locations name the same file.
     *
     * Paths are normalised first (backslashes, the application base path, and
     * a leading "./" or "/" are stripped; case is folded). They then match
     * when equal, or when one is a path-segment suffix of the other — the
     * same file referenced relative by one source and absolute by the other.
     *
     * The BASENAME is only trusted when one side IS a bare basename (the AI
     * sometimes reports just "UserController.php"). Comparing basenames of
     * two full paths merged Api/UserController.php with
     * Admin/UserController.php, which are different controllers with
     * different bugs.
     */
    private function isSameFile(string $a, string $b): bool
    {
        $left = $this->normalizePath($a);
        $right = $this->normalizePath($b);

        if ($left === $right) {
            return true;
        }

        if (str_ends_with($left, '/'.$right) || str_ends_with($right, '/'.$left)) {
            return true;
        }

        return false;
    }

    /**
     * Fold a location into a comparable relative path.
     */
    private function normalizePath(string $location): string
    {
        $path = str_replace('\\', '/', trim($location));
        $base = $this->basePath();

        if ($base !== null && str_starts_with(strtolower($path), strtolower($base).'/')) {
            $path = substr($path, strlen($base) + 1);
        }

        while (str_starts_with($path, './')) {
            $path = substr($path, 2);
        }

        return strtolower(ltrim($path, '/'));
    }

    /**
     * The application base path with forward slashes and no trailing slash,
     * or null when no container is bound (pure unit usage).
     */
    private function basePath(): ?string
    {
        if ($this->basePath === false) {
            try {
                $this->basePath = rtrim(str_replace('\\', '/', base_path()), '/');
            } catch (Throwable) {
                $this->basePath = null;
            }
        }

        return $this->basePath;
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
