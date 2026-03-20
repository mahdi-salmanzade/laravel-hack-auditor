<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner;

use Illuminate\Support\Collection;
use SplFileInfo;
use Symfony\Component\Finder\Finder;

final class FileCollector
{
    /** @var array<int, string> */
    private readonly array $paths;

    /** @var array<int, string> */
    private readonly array $exclude;

    /** @var array<int, string> */
    private readonly array $fileExtensions;

    private readonly int $maxFileSizeKb;

    /** @var array<int, string> */
    private readonly array $sensitivePatterns;

    /**
     * Create a new FileCollector instance, reading all settings from config.
     */
    public function __construct()
    {
        /** @var array<int, string> $paths */
        $paths = config('hack-auditor.scan.paths', [
            'app/Http/Controllers',
            'app/Models',
            'app/Http/Requests',
            'app/Http/Middleware',
            'routes',
        ]);

        /** @var array<int, string> $exclude */
        $exclude = config('hack-auditor.scan.exclude', [
            '*/vendor/*',
            '*/node_modules/*',
            '*/tests/*',
        ]);

        /** @var array<int, string> $fileExtensions */
        $fileExtensions = config('hack-auditor.scan.file_extensions', ['.php']);

        /** @var int $maxFileSizeKb */
        $maxFileSizeKb = config('hack-auditor.scan.max_file_size_kb', 500);

        /** @var array<int, string> $sensitivePatterns */
        $sensitivePatterns = config('hack-auditor.scan.sensitive_patterns', [
            '.env*',
            '*.key',
            '*.pem',
            'storage/logs/*',
        ]);

        $this->paths = $paths;
        $this->exclude = $exclude;
        $this->fileExtensions = $fileExtensions;
        $this->maxFileSizeKb = $maxFileSizeKb;
        $this->sensitivePatterns = $sensitivePatterns;
    }

    /**
     * Collect all PHP files from configured scan paths.
     *
     * Scans the configured directories, applies exclusion patterns (including
     * sensitive file patterns), respects file extension and size limits, skips
     * binary files, and returns results sorted by path.
     *
     * @return Collection<int, SplFileInfo>
     */
    public function collect(): Collection
    {
        $files = new Collection();
        $basePath = base_path();
        $maxSizeBytes = $this->maxFileSizeKb * 1024;

        foreach ($this->paths as $relativePath) {
            $absolutePath = $basePath . DIRECTORY_SEPARATOR . $relativePath;

            if (! is_dir($absolutePath)) {
                continue;
            }

            $finder = new Finder();
            $finder->files()->in($absolutePath);

            $this->applyExtensionFilters($finder);
            $this->applyExcludePatterns($finder);
            $this->applySensitivePatterns($finder);

            $finder->size('<= ' . $maxSizeBytes);

            foreach ($finder as $file) {
                if ($this->isBinaryFile($file)) {
                    continue;
                }

                $files->push($file);
            }
        }

        return $files
            ->sortBy(fn (SplFileInfo $file): string => $file->getRealPath())
            ->values();
    }

    /**
     * Apply file extension filters to the Finder instance.
     */
    private function applyExtensionFilters(Finder $finder): void
    {
        $patterns = array_map(
            fn (string $ext): string => '*' . ltrim($ext, '*'),
            $this->fileExtensions,
        );

        foreach ($patterns as $pattern) {
            $finder->name($pattern);
        }
    }

    /**
     * Apply exclusion glob patterns to the Finder instance.
     */
    private function applyExcludePatterns(Finder $finder): void
    {
        foreach ($this->exclude as $pattern) {
            $normalized = trim($pattern, '*/');
            $finder->notPath($normalized);
        }
    }

    /**
     * Apply sensitive file patterns to always exclude them from scans.
     */
    private function applySensitivePatterns(Finder $finder): void
    {
        foreach ($this->sensitivePatterns as $pattern) {
            if (str_contains($pattern, '/')) {
                $normalized = trim($pattern, '*/');
                $finder->notPath($normalized);
            } else {
                $finder->notName($pattern);
            }
        }
    }

    /**
     * Determine if a file is binary using a simple heuristic.
     *
     * Reads the first 8KB and checks for null bytes, which indicate
     * binary content rather than text.
     */
    private function isBinaryFile(SplFileInfo $file): bool
    {
        $path = $file->getRealPath();

        if ($path === false) {
            return true;
        }

        $handle = fopen($path, 'rb');

        if ($handle === false) {
            return true;
        }

        $chunk = fread($handle, 8192);
        fclose($handle);

        if ($chunk === false || $chunk === '') {
            return false;
        }

        return str_contains($chunk, "\0");
    }
}
