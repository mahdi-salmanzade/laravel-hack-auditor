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
        $files = new Collection;
        $basePath = base_path();

        foreach ($this->paths as $relativePath) {
            $absolutePath = $basePath.DIRECTORY_SEPARATOR.$relativePath;

            if (! is_dir($absolutePath)) {
                continue;
            }

            if ($this->isSensitivePath($relativePath)) {
                continue;
            }

            foreach ($this->findIn($absolutePath) as $file) {
                $files->push($file);
            }
        }

        return $this->sortByPath($files);
    }

    /**
     * Collect scannable PHP files from one specific directory.
     *
     * This backs `hack:scan --path=<directory>`, which the signature has always
     * advertised. It applies the same extension, size, exclusion, sensitive-file
     * and binary filters as a full scan, so pointing `--path` at a directory can
     * never widen what a normal scan would read — in particular it can never
     * reach `.env`, `*.key`, `*.pem` or log files.
     *
     * Returns an empty collection when the directory does not exist or is itself
     * a sensitive location.
     *
     * @return Collection<int, SplFileInfo>
     */
    public function collectFrom(string $directory): Collection
    {
        if (! is_dir($directory)) {
            return new Collection;
        }

        if ($this->matchesSensitivePattern($directory)) {
            return new Collection;
        }

        $files = new Collection;

        foreach ($this->findIn($directory) as $file) {
            $realPath = $file->getRealPath();

            if ($realPath !== false && $this->matchesSensitivePattern($realPath)) {
                continue;
            }

            $files->push($file);
        }

        return $this->sortByPath($files);
    }

    /**
     * Run a filtered Finder over one directory and yield the surviving files.
     *
     * @return \Generator<int, SplFileInfo>
     */
    private function findIn(string $absolutePath): \Generator
    {
        $finder = new Finder;
        $finder->files()->in($absolutePath);

        $this->applyExtensionFilters($finder);
        $this->applyExcludePatterns($finder);
        $this->applySensitivePatterns($finder);

        $finder->size('<= '.($this->maxFileSizeKb * 1024));

        foreach ($finder as $file) {
            if ($this->isBinaryFile($file)) {
                continue;
            }

            yield $file;
        }
    }

    /**
     * Sort a file collection by absolute path for stable, reproducible ordering.
     *
     * @param  Collection<int, SplFileInfo>  $files
     * @return Collection<int, SplFileInfo>
     */
    private function sortByPath(Collection $files): Collection
    {
        return $files
            ->sortBy(fn (SplFileInfo $file): string => (string) $file->getRealPath())
            ->values();
    }

    /**
     * Determine whether a path matches any configured sensitive pattern.
     *
     * Accepts either an absolute path (which is reduced to a path relative to
     * base_path) or a path already relative to the application root. Matches
     * the same `scan.sensitive_patterns` globs the Finder enforces during a
     * directory scan (e.g. `.env*`, `*.key`, `*.pem`, `storage/logs/*`), so
     * single-file entry points cannot bypass the exclusion list.
     */
    public function matchesSensitivePattern(string $path): bool
    {
        $basePath = base_path().DIRECTORY_SEPARATOR;

        $relativePath = str_starts_with($path, $basePath)
            ? substr($path, strlen($basePath))
            : $path;

        $relativePath = ltrim(str_replace('\\', '/', $relativePath), '/');
        $basename = basename($relativePath);

        foreach ($this->sensitivePatterns as $pattern) {
            if (str_contains($pattern, '/')) {
                $normalized = trim($pattern, '*/');

                if ($relativePath === $normalized
                    || str_starts_with($relativePath, $normalized.'/')
                    || str_contains($relativePath, '/'.$normalized.'/')
                    || str_contains('/'.$relativePath, '/'.$normalized.'/')
                    || fnmatch($pattern, $relativePath)
                ) {
                    return true;
                }
            } elseif (fnmatch($pattern, $basename)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Apply file extension filters to the Finder instance.
     */
    private function applyExtensionFilters(Finder $finder): void
    {
        $patterns = array_map(
            fn (string $ext): string => '*'.ltrim($ext, '*'),
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
     * Determine if a scan path itself falls under a sensitive pattern.
     *
     * This catches cases where a sensitive directory (e.g. storage/logs)
     * is explicitly listed in scan paths — the Finder-level notPath filter
     * cannot exclude files when the Finder root is the sensitive directory itself.
     */
    private function isSensitivePath(string $relativePath): bool
    {
        foreach ($this->sensitivePatterns as $pattern) {
            if (! str_contains($pattern, '/')) {
                continue;
            }

            $normalized = rtrim($pattern, '/*');

            if ($relativePath === $normalized || str_starts_with($relativePath, $normalized.'/')) {
                return true;
            }
        }

        return false;
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

    /**
     * Collect paths to context files needed for security-aware scanning.
     *
     * Returns absolute paths to files that provide security context:
     * route files, middleware, policies, form requests, models, providers,
     * config files, and base controllers. These are READ for context, not
     * scanned for vulnerabilities.
     *
     * @return array<string, array<int, string>> Category => file paths
     */
    public function collectContextFiles(): array
    {
        $basePath = base_path();
        $context = [];

        // Route files
        $routeFiles = $this->globFiles($basePath.'/routes', '*.php');
        if ($routeFiles !== []) {
            $context['routes'] = $routeFiles;
        }

        // Bootstrap/Kernel (detect Laravel version)
        $bootstrapApp = $basePath.'/bootstrap/app.php';
        $kernel = $basePath.'/app/Http/Kernel.php';
        if (file_exists($bootstrapApp)) {
            $context['bootstrap'] = [$bootstrapApp];
        }
        if (file_exists($kernel)) {
            $context['kernel'] = [$kernel];
        }

        // Middleware
        $middlewareFiles = $this->globFiles($basePath.'/app/Http/Middleware', '*.php');
        if ($middlewareFiles !== []) {
            $context['middleware'] = $middlewareFiles;
        }

        // Policies
        $policyFiles = $this->globFiles($basePath.'/app/Policies', '*.php');
        if ($policyFiles !== []) {
            $context['policies'] = $policyFiles;
        }

        // Form Requests
        $requestFiles = $this->globFiles($basePath.'/app/Http/Requests', '*.php');
        if ($requestFiles !== []) {
            $context['form_requests'] = $requestFiles;
        }

        // Models
        $modelFiles = $this->globFiles($basePath.'/app/Models', '*.php');
        if ($modelFiles !== []) {
            $context['models'] = $modelFiles;
        }

        // Service Providers
        $providerFiles = [];
        foreach (['AuthServiceProvider.php', 'AppServiceProvider.php', 'RouteServiceProvider.php'] as $provider) {
            $path = $basePath.'/app/Providers/'.$provider;
            if (file_exists($path)) {
                $providerFiles[] = $path;
            }
        }
        if ($providerFiles !== []) {
            $context['providers'] = $providerFiles;
        }

        // Config files
        $configFiles = [];
        foreach (['auth.php', 'cors.php', 'session.php', 'sanctum.php'] as $config) {
            $path = $basePath.'/config/'.$config;
            if (file_exists($path)) {
                $configFiles[] = $path;
            }
        }
        if ($configFiles !== []) {
            $context['config'] = $configFiles;
        }

        // Base controller
        $baseController = $basePath.'/app/Http/Controllers/Controller.php';
        if (file_exists($baseController)) {
            $context['base_controller'] = [$baseController];
        }

        // Extra context paths from config
        $extraPaths = config('hack-auditor.context.extra_context_paths', []);
        if (is_array($extraPaths)) {
            foreach ($extraPaths as $extraPath) {
                $absolutePath = $basePath.'/'.ltrim($extraPath, '/');
                if (file_exists($absolutePath)) {
                    $context['extra'][] = $absolutePath;
                }
            }
        }

        return $context;
    }

    /**
     * Find files matching a glob pattern in a directory.
     *
     * @return array<int, string>
     */
    private function globFiles(string $directory, string $pattern): array
    {
        if (! is_dir($directory)) {
            return [];
        }

        $files = glob($directory.DIRECTORY_SEPARATOR.$pattern);

        return $files === false ? [] : $files;
    }
}
