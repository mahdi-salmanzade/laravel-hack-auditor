<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Support;

use Mahdi\HackAuditor\Scanner\Vulnerability;

/**
 * Stable identity for a finding across scans.
 *
 * Every consumer that needs "is this the same finding as last time" — the
 * baseline, the scan-to-scan comparison, SARIF's partialFingerprints, code
 * scanning dashboards — used to key off something that drifts:
 *
 *  - the description, which the AI rewords on every run, so an accepted
 *    finding came back as "new" the moment the model chose a synonym;
 *  - the line number, which moves whenever code above it is edited;
 *  - file + type alone, which collapses two SQL injections in one controller
 *    into a single finding, so fixing one silently "resolves" both.
 *
 * The fingerprint is built from what actually identifies a flaw: its type, the
 * file it lives in (relative, forward slashes) and the normalised CONTENT of
 * the flagged source line. Editing code above it does not change it; rewording
 * does not change it; fixing the line does. Identical keys within one report
 * are told apart by an occurrence index, assigned in report order.
 */
final class Fingerprint
{
    /**
     * Version tag mixed into every hash, and the SARIF partialFingerprints key.
     */
    public const string VERSION = 'hackAuditor/v1';

    /**
     * Number of hex characters kept from the sha256 digest.
     */
    private const int LENGTH = 32;

    /**
     * Cap on cached files, so a long-running process (MCP server, queue
     * worker) cannot grow the cache without bound.
     */
    private const int CACHE_LIMIT = 256;

    /**
     * Source lines of recently read files, keyed by path|mtime|size so an
     * edited file is re-read rather than served stale. Null means unreadable.
     *
     * @var array<string, array<int, string>|null>
     */
    private static array $lineCache = [];

    /**
     * Compute the fingerprint of a finding.
     *
     * $occurrence distinguishes findings whose identity key is otherwise
     * identical in the same report (0 for the first, 1 for the second, …).
     */
    public static function of(Vulnerability $finding, int $occurrence = 0): string
    {
        return self::hash(self::identityKey($finding), $occurrence);
    }

    /**
     * Compute fingerprints for a list of findings, in order.
     *
     * The occurrence index is assigned here, so two findings with the same
     * type, file and source line stay distinct instead of collapsing.
     *
     * @param  array<int, Vulnerability>  $findings
     * @return array<int, string> Fingerprints keyed like $findings.
     */
    public static function forFindings(array $findings): array
    {
        $seen = [];
        $fingerprints = [];

        foreach ($findings as $index => $finding) {
            $key = self::identityKey($finding);
            $occurrence = $seen[$key] ?? 0;
            $seen[$key] = $occurrence + 1;

            $fingerprints[$index] = self::hash($key, $occurrence);
        }

        return $fingerprints;
    }

    /**
     * The occurrence-free identity of a finding: type | path | source line.
     */
    public static function identityKey(Vulnerability $finding): string
    {
        $path = self::normalisePath($finding->location);
        $content = self::lineContent($finding->location, $finding->line);

        // The prefixes keep a source line that happens to read "line:12" from
        // colliding with the fallback for an unreadable file.
        $anchor = $content !== null
            ? 'src:'.$content
            : 'line:'.$finding->line;

        return $finding->type->value.'|'.$path.'|'.$anchor;
    }

    /**
     * Normalise a finding location to a project-relative, forward-slash path.
     *
     * The same file must fingerprint identically whether a detector reported
     * it absolute or relative, and on Windows or POSIX.
     */
    public static function normalisePath(string $location): string
    {
        $path = str_replace('\\', '/', trim($location));
        $base = rtrim(str_replace('\\', '/', self::basePath()), '/');

        if ($base !== '' && str_starts_with($path, $base.'/')) {
            $path = substr($path, strlen($base) + 1);
        }

        while (str_starts_with($path, './')) {
            $path = substr($path, 2);
        }

        return ltrim($path, '/');
    }

    /**
     * Whitespace-collapsed content of the given 1-based line, or null when the
     * file cannot be read or has no such line.
     */
    public static function lineContent(string $location, int $line): ?string
    {
        if ($line < 1) {
            return null;
        }

        $lines = self::lines(self::absolutePath($location));

        if ($lines === null || ! array_key_exists($line - 1, $lines)) {
            return null;
        }

        return trim((string) preg_replace('/\s+/', ' ', $lines[$line - 1]));
    }

    /**
     * Drop every cached file. Intended for tests and long-lived processes.
     */
    public static function flushCache(): void
    {
        self::$lineCache = [];
    }

    /**
     * Hash an identity key and occurrence index into the public fingerprint.
     */
    private static function hash(string $key, int $occurrence): string
    {
        return substr(hash('sha256', self::VERSION.'|'.$key.'|'.$occurrence), 0, self::LENGTH);
    }

    /**
     * Read a file's lines through the cache.
     *
     * @return array<int, string>|null
     */
    private static function lines(string $path): ?array
    {
        if (! is_file($path) || ! is_readable($path)) {
            return null;
        }

        clearstatcache(true, $path);
        $cacheKey = $path.'|'.(int) @filemtime($path).'|'.(int) @filesize($path);

        if (array_key_exists($cacheKey, self::$lineCache)) {
            return self::$lineCache[$cacheKey];
        }

        if (count(self::$lineCache) >= self::CACHE_LIMIT) {
            self::$lineCache = [];
        }

        $contents = @file_get_contents($path);

        $lines = $contents === false
            ? null
            : preg_split('/\r\n|\r|\n/', $contents);

        return self::$lineCache[$cacheKey] = $lines === false ? null : $lines;
    }

    /**
     * Resolve a finding location to an absolute path on disk.
     */
    private static function absolutePath(string $location): string
    {
        // Forward slashes work on every platform PHP runs on, and a detector
        // that reported a Windows-style path must read the same file.
        $path = str_replace('\\', '/', trim($location));

        if (str_starts_with($path, '/') || preg_match('/^[A-Za-z]:\//', $path) === 1) {
            return $path;
        }

        return rtrim(str_replace('\\', '/', self::basePath()), '/').'/'.ltrim($path, '/');
    }

    /**
     * The application base path, or an empty string outside a container.
     */
    private static function basePath(): string
    {
        try {
            return function_exists('base_path') ? base_path() : '';
        } catch (\Throwable) {
            return '';
        }
    }
}
