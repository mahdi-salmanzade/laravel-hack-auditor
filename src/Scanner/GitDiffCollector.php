<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner;

use RuntimeException;

class GitDiffCollector
{
    /**
     * The ref the most recent diff was actually computed against.
     */
    private ?string $resolvedBase = null;

    /**
     * Get PHP files that changed compared to the base branch.
     *
     * Runs a git diff against the given base branch and returns only PHP files
     * within configured scan paths that are not matched by sensitive patterns.
     * Useful in CI to scan only what a PR touches.
     *
     * Three failure modes used to be reported as "no changed files" — a green
     * CI check on a PR nobody looked at — and now throw instead:
     *
     *  - the base ref does not exist locally or on origin (typically a shallow
     *    `actions/checkout` without `fetch-depth: 0`);
     *  - an explicitly requested base could not be resolved, in which case the
     *    collector used to diff against `main`/`master` instead — a different
     *    comparison from the one asked for, reported as if it were the same;
     *  - the Laravel app lives in a subdirectory of the repository, where git
     *    reports repo-root paths (`backend/app/...`) that never matched the
     *    configured scan paths. The diff now runs from base_path() with
     *    `--relative`, so paths are app-relative wherever the app lives.
     *
     * @param  string|null  $baseBranch  The base to diff against. Null auto-detects
     *                                   `main`, then `master`; an explicit branch is
     *                                   used exactly, with no fallback.
     * @param  string|null  $restrictTo  Optional app-relative file or directory the
     *                                   result is narrowed to (`--path` with `--diff`).
     * @return array<int, string> Absolute file paths
     *
     * @throws RuntimeException If not inside a git repository, or the base cannot be resolved.
     */
    public function getChangedFiles(?string $baseBranch = null, ?string $restrictTo = null): array
    {
        $this->ensureGitRepository();

        $candidates = $baseBranch !== null && trim($baseBranch) !== ''
            ? [trim($baseBranch)]
            : ['main', 'master'];

        $files = null;

        foreach ($candidates as $candidate) {
            $files = $this->diffAgainstBranch($candidate);

            if ($files !== null) {
                break;
            }
        }

        if ($files === null) {
            $tried = implode(', ', array_map(
                static fn (string $candidate): string => "{$candidate}, origin/{$candidate}",
                $candidates,
            ));

            throw new RuntimeException(
                "Could not resolve the diff base (tried {$tried}). In CI this usually means a shallow "
                .'checkout: set `fetch-depth: 0` on actions/checkout, or fetch the base branch before scanning.'
            );
        }

        $basePath = base_path();

        /** @var array<int, string> $scanPaths */
        $scanPaths = config('hack-auditor.scan.paths', [
            'app/Http/Controllers',
            'app/Models',
            'app/Http/Requests',
            'app/Http/Middleware',
            'routes',
        ]);

        /** @var array<int, string> $sensitivePatterns */
        $sensitivePatterns = config('hack-auditor.scan.sensitive_patterns', [
            '.env*',
            '*.key',
            '*.pem',
            'storage/logs/*',
        ]);

        $restriction = $this->normaliseRestriction($restrictTo);

        $absolutePaths = [];

        foreach ($files as $relativePath) {
            $relativePath = str_replace('\\', '/', trim($relativePath));

            if ($relativePath === '') {
                continue;
            }

            if (! $this->isWithinScanPaths($relativePath, $scanPaths)) {
                continue;
            }

            if ($restriction !== null && ! $this->isWithinScanPaths($relativePath, [$restriction])) {
                continue;
            }

            if ($this->matchesSensitivePattern($relativePath, $sensitivePatterns)) {
                continue;
            }

            $absolutePath = $basePath.DIRECTORY_SEPARATOR.$relativePath;

            if (is_file($absolutePath)) {
                $absolutePaths[] = $absolutePath;
            }
        }

        sort($absolutePaths);

        return array_values($absolutePaths);
    }

    /**
     * The ref the most recent getChangedFiles() call diffed against, e.g. `origin/main`.
     */
    public function resolvedBase(): ?string
    {
        return $this->resolvedBase;
    }

    /**
     * Ensure base_path() is inside a git work tree.
     *
     * @throws RuntimeException If not inside a git work tree.
     */
    private function ensureGitRepository(): void
    {
        exec($this->git('rev-parse --is-inside-work-tree').' 2>/dev/null', $output, $exitCode);

        if ($exitCode !== 0) {
            throw new RuntimeException('Not a git repository');
        }
    }

    /**
     * Run git diff against the given branch and return app-relative paths, or null on failure.
     *
     * @return array<int, string>|null
     */
    private function diffAgainstBranch(string $branch): ?array
    {
        // Try local branch first, then origin/ remote ref (needed in CI
        // where GitHub Actions only checks out the PR branch locally).
        $refs = [$branch, "origin/{$branch}"];

        foreach ($refs as $ref) {
            $output = [];

            exec(
                $this->git(sprintf('rev-parse --verify --quiet %s', escapeshellarg($ref.'^{commit}'))).' 2>/dev/null',
                $output,
                $exitCode,
            );

            if ($exitCode !== 0) {
                continue;
            }

            $output = [];

            // core.quotepath=off keeps non-ASCII paths literal; with it on, git
            // prints them octal-escaped in quotes and is_file() never matches.
            exec(
                $this->git(sprintf(
                    "-c core.quotepath=off diff --relative --name-only --diff-filter=ACMR %s -- '*.php'",
                    escapeshellarg($ref.'...HEAD'),
                )).' 2>/dev/null',
                $output,
                $exitCode,
            );

            if ($exitCode === 0) {
                $this->resolvedBase = $ref;

                return $output;
            }
        }

        return null;
    }

    /**
     * Build a git command that runs from the application root.
     */
    private function git(string $arguments): string
    {
        return 'git -C '.escapeshellarg(base_path()).' '.$arguments;
    }

    /**
     * Normalise a `--path` restriction to an app-relative path without slashes at the ends.
     */
    private function normaliseRestriction(?string $restrictTo): ?string
    {
        if ($restrictTo === null || trim($restrictTo) === '') {
            return null;
        }

        $path = str_replace('\\', '/', trim($restrictTo));
        $base = str_replace('\\', '/', base_path()).'/';

        if (str_starts_with($path, $base)) {
            $path = substr($path, strlen($base));
        }

        if (str_starts_with($path, './')) {
            $path = substr($path, 2);
        }

        $path = trim($path, '/');

        return $path === '' ? null : $path;
    }

    /**
     * Determine if a relative file path falls within any of the configured scan paths.
     *
     * @param  array<int, string>  $scanPaths
     */
    private function isWithinScanPaths(string $relativePath, array $scanPaths): bool
    {
        foreach ($scanPaths as $scanPath) {
            $normalized = rtrim($scanPath, '/').'/';

            if (str_starts_with($relativePath, $normalized) || $relativePath === rtrim($scanPath, '/')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if a relative file path matches any sensitive pattern.
     *
     * @param  array<int, string>  $sensitivePatterns
     */
    private function matchesSensitivePattern(string $relativePath, array $sensitivePatterns): bool
    {
        $filename = basename($relativePath);

        foreach ($sensitivePatterns as $pattern) {
            if (fnmatch($pattern, $relativePath)) {
                return true;
            }

            if (fnmatch($pattern, $filename)) {
                return true;
            }
        }

        return false;
    }
}
