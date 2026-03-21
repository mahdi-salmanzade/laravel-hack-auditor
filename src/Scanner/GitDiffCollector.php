<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner;

use RuntimeException;

class GitDiffCollector
{
    /**
     * Get PHP files that changed compared to the base branch.
     *
     * Runs a git diff against the given base branch (or auto-detected default)
     * and returns only PHP files within configured scan paths that are not
     * matched by sensitive patterns. Useful in CI to scan only what a PR touches.
     *
     * @return array<int, string> Absolute file paths
     *
     * @throws RuntimeException If not inside a git repository.
     */
    public function getChangedFiles(string $baseBranch = 'main'): array
    {
        $this->ensureGitRepository();

        $files = $this->diffAgainstBranch($baseBranch);

        if ($files === null) {
            $fallback = $baseBranch === 'main' ? 'master' : 'main';
            $files = $this->diffAgainstBranch($fallback);
        }

        if ($files === null) {
            return [];
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

        $absolutePaths = [];

        foreach ($files as $relativePath) {
            $relativePath = trim($relativePath);

            if ($relativePath === '') {
                continue;
            }

            if (! $this->isWithinScanPaths($relativePath, $scanPaths)) {
                continue;
            }

            if ($this->matchesSensitivePattern($relativePath, $sensitivePatterns)) {
                continue;
            }

            $absolutePath = $basePath.DIRECTORY_SEPARATOR.$relativePath;

            if (file_exists($absolutePath)) {
                $absolutePaths[] = $absolutePath;
            }
        }

        sort($absolutePaths);

        return array_values($absolutePaths);
    }

    /**
     * Detect the default base branch for the repository.
     *
     * Tries `main` first, then `master`, falling back to `main` if neither exists.
     */
    private function detectBaseBranch(): string
    {
        exec('git rev-parse --verify main 2>/dev/null', $output, $exitCode);

        if ($exitCode === 0) {
            return 'main';
        }

        exec('git rev-parse --verify master 2>/dev/null', $output, $exitCode);

        if ($exitCode === 0) {
            return 'master';
        }

        return 'main';
    }

    /**
     * Ensure we are inside a git repository.
     *
     * @throws RuntimeException If not inside a git work tree.
     */
    private function ensureGitRepository(): void
    {
        exec('git rev-parse --is-inside-work-tree 2>/dev/null', $output, $exitCode);

        if ($exitCode !== 0) {
            throw new RuntimeException('Not a git repository');
        }
    }

    /**
     * Run git diff against the given branch and return file paths, or null on failure.
     *
     * @return array<int, string>|null
     */
    private function diffAgainstBranch(string $branch): ?array
    {
        $command = sprintf(
            "git diff --name-only --diff-filter=ACMR %s...HEAD -- '*.php'",
            escapeshellarg($branch),
        );

        exec($command.' 2>/dev/null', $output, $exitCode);

        if ($exitCode !== 0) {
            return null;
        }

        return $output;
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
