<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;
use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\AI\ResponseParser;
use Mahdi\HackAuditor\Contracts\ScannerInterface;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlAnalyzer;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\Php\PhpAstParser;
use Mahdi\HackAuditor\Scanner\Php\PolicyInspector;
use Mahdi\HackAuditor\Scanner\Php\TypeNames;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\UsageTracker;
use SplFileInfo;

final class HackScanner implements ScannerInterface
{
    /**
     * Create a new HackScanner instance with all required dependencies.
     */
    public function __construct(
        private readonly FileCollector $fileCollector,
        private readonly CodeExtractor $codeExtractor,
        private readonly PromptBuilder $promptBuilder,
        private readonly ResponseParser $responseParser,
        private readonly AIAdapter $aiAdapter,
        private readonly ?RouteAnalyzer $routeAnalyzer = null,
        private readonly ?RuntimeIntrospector $runtimeIntrospector = null,
        private readonly ?ContextCollector $contextCollector = null,
        private readonly ?VerificationEngine $verificationEngine = null,
        private readonly ?AccessControlAnalyzer $accessControlAnalyzer = null,
    ) {}

    private ?AppContext $appContext = null;

    private ?UsageTracker $usageTracker = null;

    private int $filesSkipped = 0;

    private int $chunksFailedParse = 0;

    private int $filesDiscovered = 0;

    private int $filesAnalyzed = 0;

    /** @var array<int, array{path: string, reason: string}> */
    private array $skippedFiles = [];

    private bool $verify = false;

    /**
     * Enable or disable multi-pass exploit verification for HIGH+ findings.
     *
     * When enabled, each High/Critical finding from pass 1 is sent back to
     * the AI with a request to produce a concrete exploit. Findings that
     * cannot be exploited are downgraded one severity tier.
     */
    public function setVerify(bool $verify): self
    {
        $this->verify = $verify;

        return $this;
    }

    /**
     * Set the usage tracker for token consumption monitoring.
     */
    public function setUsageTracker(UsageTracker $tracker): void
    {
        $this->usageTracker = $tracker;
        $this->resetCoverage();
    }

    /**
     * Get the number of chunks that failed to parse during the last scan.
     */
    public function getChunksFailedParse(): int
    {
        return $this->chunksFailedParse;
    }

    /**
     * Get the coverage record for the most recent scan.
     */
    public function getCoverage(): ScanCoverage
    {
        return new ScanCoverage(
            filesDiscovered: $this->filesDiscovered,
            filesAnalyzed: $this->filesAnalyzed,
            skipped: $this->skippedFiles,
        );
    }

    /**
     * Scan the entire application for security vulnerabilities.
     *
     * Collects files from configured paths, chunks them for batched AI analysis,
     * sends each chunk to the AI provider, parses the responses, and merges all
     * results into a single report with a recalculated weighted average score.
     */
    public function scan(): VulnerabilityReport
    {
        $this->resetCoverage();

        return $this->scanCollection(
            $this->fileCollector->collect(),
            'No files found to scan.',
        );
    }

    /**
     * Scan a specific file — or an entire directory — for vulnerabilities.
     *
     * `--path` has always advertised "a specific file or directory", but a
     * directory used to fall straight through to the single-file read path:
     * file_exists() is true for directories, and CodeExtractor returns empty
     * content for one. The result was a full-price AI request over an empty
     * file and a confident, evidence-free report. Directories now walk their
     * contents through the same collector, chunking and coverage accounting as
     * a full scan.
     */
    public function scanFile(string $path): VulnerabilityReport
    {
        $this->resetCoverage();

        $absolutePath = str_starts_with($path, DIRECTORY_SEPARATOR)
            ? $path
            : base_path($path);

        if (! file_exists($absolutePath)) {
            return $this->attachScanState(new VulnerabilityReport(
                vulnerabilities: [],
                overallScore: 100,
                summary: "File not found: {$path}",
                ctfIdea: '',
            ));
        }

        if (($refusal = $this->guardScanPath($absolutePath, $path)) !== null) {
            return $this->attachScanState($refusal);
        }

        if (is_dir($absolutePath)) {
            return $this->scanCollection(
                $this->fileCollector->collectFrom($absolutePath),
                "No scannable files found in directory: {$path}",
            );
        }

        $file = new SplFileInfo($absolutePath);
        $extracted = $this->codeExtractor->extract($file);
        $this->filesDiscovered = 1;

        // Collect context for single file scan
        if ($this->contextCollector !== null && $extracted['type'] === 'controller') {
            $this->appContext = $this->contextCollector->collect([$extracted]);
        }

        try {
            $report = $this->analyzeFiles([$extracted]);
            $this->filesAnalyzed = 1;
        } catch (\Throwable $e) {
            $this->chunksFailedParse++;
            $this->recordSkippedFile($extracted['path'], ScanCoverage::REASON_AI_FAILURE);

            Log::warning('[HackAuditor] AI scan failed for file', [
                'path' => $path,
                'error' => $e->getMessage(),
            ]);

            $report = new VulnerabilityReport(
                vulnerabilities: [],
                overallScore: 0,
                summary: "AI scan failed for {$path}: {$e->getMessage()}. Re-run the scan to retry.",
                ctfIdea: '',
            );
        }

        $report = $this->mergeAccessControlFindings($report, [$extracted]);

        $report = $this->maybeVerify($report);

        return $this->attachScanState($report);
    }

    /**
     * Chunk, analyse and merge a collection of files, tracking coverage.
     *
     * Shared by the full-application scan and by `--path=<directory>` so both
     * paths get identical chunking, context collection, deterministic merging,
     * usage accounting and coverage accounting.
     *
     * @param  Collection<int, SplFileInfo>  $files
     */
    private function scanCollection(Collection $files, string $emptyMessage): VulnerabilityReport
    {
        $this->filesDiscovered = $files->count();

        if ($files->isEmpty()) {
            return $this->attachScanState(new VulnerabilityReport(
                vulnerabilities: [],
                overallScore: 100,
                summary: $emptyMessage,
                ctfIdea: '',
            ));
        }

        $chunks = $this->codeExtractor->chunk($files);

        // Collect context once using all controller files from all chunks
        $this->collectAppContext($chunks);

        $report = $this->scanChunks($chunks);

        $flatFiles = [];
        foreach ($chunks as $chunk) {
            foreach ($chunk as $file) {
                $flatFiles[] = $file;
            }
        }

        $report = $this->mergeAccessControlFindings($report, $flatFiles);

        return $this->attachScanState($report);
    }

    /**
     * Clear per-run coverage and skip accounting.
     */
    private function resetCoverage(): void
    {
        $this->filesSkipped = 0;
        $this->chunksFailedParse = 0;
        $this->filesDiscovered = 0;
        $this->filesAnalyzed = 0;
        $this->skippedFiles = [];
    }

    /**
     * Attach the usage tracker and coverage record to the finished report.
     *
     * This is the LAST thing every public entry point does. Attaching earlier is
     * how spend went missing: the deterministic access-control merge rebuilds the
     * report, and a rebuilt report used to arrive with no tracker, so the whole
     * scan recorded zero tokens and never reached the usage log.
     */
    private function attachScanState(VulnerabilityReport $report): VulnerabilityReport
    {
        if ($this->usageTracker !== null) {
            $report->setUsageTracker($this->usageTracker);
        }

        $report->setCoverage($this->getCoverage());

        return $report;
    }

    /**
     * Record every file in a chunk as unanalysed, with the reason.
     *
     * @param  array<int, array{path: string, content: string, type: string}>  $chunk
     */
    private function recordSkippedChunk(array $chunk, string $reason): void
    {
        foreach ($chunk as $file) {
            $this->recordSkippedFile($file['path'], $reason);
        }
    }

    /**
     * Record a single file as unanalysed, with the reason.
     */
    private function recordSkippedFile(string $path, string $reason): void
    {
        $this->skippedFiles[] = ['path' => $path, 'reason' => $reason];
    }

    /**
     * Enforce path-safety guards before a single file is read and sent to the AI.
     *
     * This is the read-path counterpart to the FileCollector exclusion list.
     * It (a) rejects any path that, once symlink/`..`-resolved, escapes the
     * application's base_path, preventing arbitrary-file-read / traversal
     * (e.g. `../../.env`, `/etc/passwd`); and (b) rejects any path matching the
     * configured `scan.sensitive_patterns` globs (e.g. `.env*`, `*.key`,
     * `*.pem`, `storage/logs/*`) so secrets are never exfiltrated to the
     * cloud AI. Returns a refusal report when the path is unsafe, or null when
     * the path is safe to scan.
     */
    private function guardScanPath(string $absolutePath, string $originalPath): ?VulnerabilityReport
    {
        $resolved = realpath($absolutePath);
        $base = realpath(base_path());

        if ($resolved === false || $base === false) {
            return $this->refusedReport($originalPath, 'path could not be resolved');
        }

        $baseWithSeparator = rtrim($base, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;

        if ($resolved !== $base && ! str_starts_with($resolved, $baseWithSeparator)) {
            return $this->refusedReport($originalPath, 'path is outside the application root');
        }

        if ($this->fileCollector->matchesSensitivePattern($resolved)) {
            return $this->refusedReport($originalPath, 'path matches a sensitive-file exclusion pattern');
        }

        return null;
    }

    /**
     * Build a clean refusal report for a path that fails the safety guards.
     *
     * The file is never read, so no contents can leak into the AI prompt.
     */
    private function refusedReport(string $path, string $reason): VulnerabilityReport
    {
        Log::warning('[HackAuditor] Refused to scan path', [
            'path' => $path,
            'reason' => $reason,
        ]);

        return new VulnerabilityReport(
            vulnerabilities: [],
            overallScore: 100,
            summary: "Refused to scan \"{$path}\": {$reason}.",
            ctfIdea: '',
        );
    }

    /**
     * Scan a raw code string for security vulnerabilities.
     */
    public function scanCode(string $code): VulnerabilityReport
    {
        $this->resetCoverage();

        $fileData = [
            'path' => 'inline-code.php',
            'content' => $code,
            'type' => 'other',
        ];

        $this->filesDiscovered = 1;

        try {
            $report = $this->analyzeFiles([$fileData]);
            $this->filesAnalyzed = 1;
        } catch (\Throwable $e) {
            $this->chunksFailedParse++;
            $this->recordSkippedFile($fileData['path'], ScanCoverage::REASON_AI_FAILURE);

            Log::warning('[HackAuditor] AI scan failed for inline code', [
                'error' => $e->getMessage(),
            ]);

            $report = new VulnerabilityReport(
                vulnerabilities: [],
                overallScore: 0,
                summary: "AI scan failed: {$e->getMessage()}. Re-run the scan to retry.",
                ctfIdea: '',
            );
        }

        $report = $this->mergeAccessControlFindings($report, [$fileData]);

        $report = $this->maybeVerify($report, inlineCode: $code);

        return $this->attachScanState($report);
    }

    /**
     * Scan multiple chunks of files and merge results into a single report.
     *
     * @param  array<int, array<int, array{path: string, content: string, type: string}>>  $chunks
     */
    private function scanChunks(array $chunks): VulnerabilityReport
    {
        /** @var array<int, VulnerabilityReport> $reports */
        $reports = [];

        foreach ($chunks as $chunk) {
            if ($this->usageTracker !== null && $this->usageTracker->isLimitSet()) {
                $estimatedTokens = $this->estimateChunkTokens($chunk) + 4000;

                if ($this->usageTracker->wouldExceedLimit($estimatedTokens)) {
                    $this->filesSkipped += count($chunk);
                    $this->recordSkippedChunk($chunk, ScanCoverage::REASON_TOKEN_LIMIT);

                    continue;
                }
            }

            try {
                $reports[] = $this->analyzeFiles($chunk);
                $this->filesAnalyzed += count($chunk);
            } catch (\Throwable $e) {
                $this->chunksFailedParse++;
                $this->recordSkippedChunk($chunk, ScanCoverage::REASON_AI_FAILURE);

                Log::warning('[HackAuditor] Skipping chunk due to AI failure', [
                    'files' => array_map(fn (array $f): string => $f['path'], $chunk),
                    'error' => $e->getMessage(),
                ]);
            }
        }

        $report = $this->mergeReports($reports);

        return $this->maybeVerify($report);
    }

    /**
     * Collect application context once from all controller files across chunks.
     *
     * @param  array<int, array<int, array{path: string, content: string, type: string}>>  $chunks
     */
    private function collectAppContext(array $chunks): void
    {
        if ($this->contextCollector === null) {
            return;
        }

        // Flatten all controller files from all chunks
        $controllerFiles = [];
        foreach ($chunks as $chunk) {
            foreach ($chunk as $file) {
                if ($file['type'] === 'controller') {
                    $controllerFiles[] = $file;
                }
            }
        }

        $this->appContext = $this->contextCollector->collect($controllerFiles);
    }

    /**
     * Estimate the total tokens for a chunk of files.
     *
     * Uses ~4 chars per token as a conservative approximation.
     *
     * @param  array<int, array{path: string, content: string, type: string}>  $chunk
     */
    private function estimateChunkTokens(array $chunk): int
    {
        $totalChars = 0;

        foreach ($chunk as $file) {
            $totalChars += strlen($file['content']);
        }

        return (int) ceil($totalChars / 4);
    }

    /**
     * Send a batch of files to the AI for security analysis.
     *
     * When a RouteAnalyzer is available, injects middleware context, routed
     * method names, and FormRequest file contents for controller files to
     * help the AI avoid false positives.
     *
     * @param  array<int, array{path: string, content: string, type: string}>  $files
     */
    private function analyzeFiles(array $files): VulnerabilityReport
    {
        $this->injectRouteContext($files);
        $this->injectRoutedMethods($files);
        $this->injectFormRequestContext($files);
        $this->injectModelContext($files);

        if ($this->appContext !== null) {
            $this->promptBuilder->withAppContext($this->appContext);
        }

        $systemPrompt = $this->promptBuilder->systemPrompt();
        $userPrompt = $this->promptBuilder->userPrompt($files);

        if ($this->usageTracker !== null) {
            $result = $this->aiAdapter->sendWithUsage($systemPrompt, $userPrompt);

            $this->usageTracker->record(
                $result['usage']['prompt_tokens'],
                $result['usage']['completion_tokens'],
            );

            return $this->responseParser->parse($result['text']);
        }

        $response = $this->aiAdapter->send($systemPrompt, $userPrompt);

        return $this->responseParser->parse($response);
    }

    /**
     * Inject route middleware context for controller files in the batch.
     *
     * Prefers RuntimeIntrospector (authoritative, uses Laravel Router) over
     * RouteAnalyzer (static file parsing) when available.
     *
     * @param  array<int, array{path: string, content: string, type: string}>  $files
     */
    private function injectRouteContext(array $files): void
    {
        if ($this->runtimeIntrospector === null && $this->routeAnalyzer === null) {
            return;
        }

        $allRouteContext = [];

        foreach ($files as $file) {
            if ($file['type'] !== 'controller') {
                continue;
            }

            $className = $this->extractClassName($file['content']);

            if ($className === null) {
                continue;
            }

            try {
                // Prefer RuntimeIntrospector for authoritative middleware resolution
                $routes = $this->runtimeIntrospector !== null
                    ? $this->runtimeIntrospector->getRouteMiddleware($className)
                    : $this->routeAnalyzer->analyze($className);

                foreach ($routes as $route => $middleware) {
                    $allRouteContext[$route] = $middleware;
                }
            } catch (\Throwable) {
                // Route analysis is best-effort — skip on failure
            }
        }

        if ($allRouteContext !== []) {
            $this->promptBuilder->withRouteContext($allRouteContext);
        }
    }

    /**
     * Inject routed method names for controller files in the batch.
     *
     * Prefers RuntimeIntrospector over RouteAnalyzer when available.
     *
     * @param  array<int, array{path: string, content: string, type: string}>  $files
     */
    private function injectRoutedMethods(array $files): void
    {
        if ($this->runtimeIntrospector === null && $this->routeAnalyzer === null) {
            return;
        }

        $allRoutedMethods = [];

        foreach ($files as $file) {
            if ($file['type'] !== 'controller') {
                continue;
            }

            $className = $this->extractClassName($file['content']);

            if ($className === null) {
                continue;
            }

            try {
                $methods = $this->runtimeIntrospector !== null
                    ? $this->runtimeIntrospector->getRoutedMethods($className)
                    : $this->routeAnalyzer->getRoutedMethods($className);

                foreach ($methods as $method => $route) {
                    $allRoutedMethods[$method] = $route;
                }
            } catch (\Throwable) {
                // Route analysis is best-effort
            }
        }

        if ($allRoutedMethods !== []) {
            $this->promptBuilder->withRoutedMethods($allRoutedMethods);
        }
    }

    /**
     * Inject FormRequest file contents for controller files in the batch.
     *
     * Parses controller type hints to find FormRequest classes, reads their
     * source files, and adds them to the prompt context so the AI can check
     * authorize() and rules() methods before flagging false positives.
     *
     * @param  array<int, array{path: string, content: string, type: string}>  $files
     */
    private function injectFormRequestContext(array $files): void
    {
        $formRequests = [];
        $seen = [];

        foreach ($files as $file) {
            if ($file['type'] !== 'controller') {
                continue;
            }

            $requestClasses = $this->extractFormRequestTypeHints($file['content']);

            foreach ($requestClasses as $fqcn) {
                if (isset($seen[$fqcn])) {
                    continue;
                }

                $seen[$fqcn] = true;
                $filePath = $this->resolveClassPath($fqcn);

                if ($filePath === null || ! file_exists($filePath)) {
                    continue;
                }

                $basePath = base_path().DIRECTORY_SEPARATOR;
                $relativePath = str_starts_with($filePath, $basePath)
                    ? substr($filePath, strlen($basePath))
                    : $filePath;

                $formRequests[] = [
                    'path' => $relativePath,
                    'content' => (string) file_get_contents($filePath),
                ];
            }
        }

        if ($formRequests !== []) {
            $this->promptBuilder->withFormRequestContext($formRequests);
        }
    }

    /**
     * Inject Eloquent model metadata for models referenced in the batch.
     *
     * Uses RuntimeIntrospector to get authoritative model properties ($fillable,
     * $hidden, $guarded, $casts) so the AI can verify mass assignment and
     * sensitive data exposure findings against actual model configuration.
     *
     * Falls back to ContextCollector's regex-based parsing when RuntimeIntrospector
     * cannot instantiate a model (e.g., constructor dependencies, missing DB).
     *
     * Processes ALL file types (controllers, models, routes, services) to ensure
     * model context is available regardless of which file references the model.
     *
     * @param  array<int, array{path: string, content: string, type: string}>  $files
     */
    private function injectModelContext(array $files): void
    {
        if ($this->runtimeIntrospector === null && $this->contextCollector === null) {
            return;
        }

        $modelContext = [];

        foreach ($files as $file) {
            // For model files, extract the FQCN from the file itself
            if ($file['type'] === 'model') {
                $fqcn = $this->extractClassName($file['content']);

                if ($fqcn !== null && ! isset($modelContext[$fqcn])) {
                    $info = $this->resolveModelInfo($fqcn, $file['content']);

                    if ($info !== null) {
                        $modelContext[$fqcn] = $info;
                    }
                }

                continue;
            }

            // For all other file types, extract model references from use statements
            $modelClasses = $this->extractModelReferences($file['content']);

            foreach ($modelClasses as $modelClass) {
                if (isset($modelContext[$modelClass])) {
                    continue;
                }

                $info = $this->resolveModelInfo($modelClass);

                if ($info !== null) {
                    $modelContext[$modelClass] = $info;
                }
            }
        }

        if ($modelContext !== []) {
            $this->promptBuilder->withModelContext($modelContext);
        }
    }

    /**
     * Resolve model metadata using RuntimeIntrospector with regex fallback.
     *
     * First attempts RuntimeIntrospector (authoritative, reads actual class properties).
     * If that returns null (class not found, instantiation failure, DB dependency),
     * falls back to regex-based parsing of the model source file.
     *
     * @param  string  $modelClass  The FQCN of the model
     * @param  string|null  $sourceContent  Optional pre-read source content (for model files already in the batch)
     * @return array{fillable: array<int, string>, hidden: array<int, string>, guarded: array<int, string>, casts: array<string, string>}|null
     */
    private function resolveModelInfo(string $modelClass, ?string $sourceContent = null): ?array
    {
        // Try RuntimeIntrospector first (authoritative)
        if ($this->runtimeIntrospector !== null) {
            try {
                $info = $this->runtimeIntrospector->getModelInfo($modelClass);

                if ($info !== null) {
                    return $info;
                }
            } catch (\Throwable) {
                // Fall through to regex fallback
            }
        }

        // Fallback: read model source and parse with regex
        if ($sourceContent === null) {
            $filePath = $this->resolveClassPath($modelClass);

            if ($filePath === null || ! file_exists($filePath)) {
                Log::debug('[HackAuditor] Could not resolve model info for {model} — runtime introspection failed and source file not found', [
                    'model' => $modelClass,
                ]);

                return null;
            }

            $sourceContent = (string) file_get_contents($filePath);
        }

        $fillable = $this->parsePropertyArray($sourceContent, 'fillable');
        $hidden = $this->parsePropertyArray($sourceContent, 'hidden');
        $guarded = $this->parsePropertyArray($sourceContent, 'guarded');
        $casts = $this->parsePropertyAssocArray($sourceContent, 'casts');

        // If all arrays are empty, the regex likely couldn't parse anything useful
        if ($fillable === [] && $hidden === [] && $guarded === [] && $casts === []) {
            Log::debug('[HackAuditor] Regex fallback found no model properties for {model}', [
                'model' => $modelClass,
            ]);

            return null;
        }

        return [
            'fillable' => $fillable,
            'hidden' => $hidden,
            'guarded' => $guarded,
            'casts' => $casts,
        ];
    }

    /**
     * Parse a simple PHP array property from source code using regex.
     *
     * Handles both single-line and multi-line array definitions with bracket
     * nesting awareness. Returns string values found in the array.
     *
     * @return array<int, string>
     */
    private function parsePropertyArray(string $content, string $propertyName): array
    {
        $escaped = preg_quote($propertyName, '/');

        // Match the property assignment, handling nested brackets
        if (! preg_match('/\$'.$escaped.'\s*=\s*\[/s', $content, $match, PREG_OFFSET_CAPTURE)) {
            return [];
        }

        $startOffset = $match[0][1] + strlen($match[0][0]);
        $depth = 1;
        $length = strlen($content);
        $pos = $startOffset;

        // Walk forward tracking bracket depth to find the matching close bracket
        while ($pos < $length && $depth > 0) {
            if ($content[$pos] === '[') {
                $depth++;
            } elseif ($content[$pos] === ']') {
                $depth--;
            }
            $pos++;
        }

        $arrayContent = substr($content, $startOffset, $pos - $startOffset - 1);

        $values = [];

        if (preg_match_all("/['\"]([^'\"]+)['\"]/", $arrayContent, $valueMatches)) {
            $values = $valueMatches[1];
        }

        return $values;
    }

    /**
     * Parse a PHP associative array property from source code using regex.
     *
     * @return array<string, string>
     */
    private function parsePropertyAssocArray(string $content, string $propertyName): array
    {
        $escaped = preg_quote($propertyName, '/');

        if (! preg_match('/\$'.$escaped.'\s*=\s*\[/s', $content, $match, PREG_OFFSET_CAPTURE)) {
            return [];
        }

        $startOffset = $match[0][1] + strlen($match[0][0]);
        $depth = 1;
        $length = strlen($content);
        $pos = $startOffset;

        while ($pos < $length && $depth > 0) {
            if ($content[$pos] === '[') {
                $depth++;
            } elseif ($content[$pos] === ']') {
                $depth--;
            }
            $pos++;
        }

        $arrayContent = substr($content, $startOffset, $pos - $startOffset - 1);

        $values = [];

        if (preg_match_all("/['\"]([^'\"]+)['\"]\s*=>\s*['\"]?([^'\",\]\s]+)['\"]?/", $arrayContent, $valueMatches, PREG_SET_ORDER)) {
            foreach ($valueMatches as $valueMatch) {
                $values[$valueMatch[1]] = rtrim($valueMatch[2], ',');
            }
        }

        return $values;
    }

    /**
     * Extract Eloquent model class FQCNs referenced in controller code.
     *
     * Looks for use statements importing classes from the App\Models namespace.
     *
     * @return array<int, string>
     */
    private function extractModelReferences(string $content): array
    {
        $models = [];

        if (preg_match_all('/use\s+([\w\\\\]+);/', $content, $matches)) {
            foreach ($matches[1] as $use) {
                if (str_contains($use, 'Models\\')) {
                    $models[] = $use;
                }
            }
        }

        return array_values(array_unique($models));
    }

    /**
     * Extract FormRequest class FQCNs from controller type hints.
     *
     * Parses use statements and method signatures to find type-hinted
     * parameters that reference FormRequest subclasses.
     *
     * @return array<int, string>
     */
    private function extractFormRequestTypeHints(string $content): array
    {
        // Parse use statements into short name => FQCN map
        $uses = [];

        if (preg_match_all('/use\s+([\w\\\\]+);/', $content, $matches)) {
            foreach ($matches[1] as $use) {
                $parts = explode('\\', $use);
                $short = end($parts);
                $uses[$short] = $use;
            }
        }

        // Find method parameter type hints that look like FormRequests
        $formRequests = [];

        if (preg_match_all('/function\s+\w+\s*\(([^)]*)\)/s', $content, $matches)) {
            foreach ($matches[1] as $params) {
                if (preg_match_all('/\??(\w+)\s+\$\w+/', $params, $paramMatches)) {
                    foreach ($paramMatches[1] as $typeHint) {
                        if (isset($uses[$typeHint]) && str_contains($uses[$typeHint], 'Requests\\')) {
                            $formRequests[] = $uses[$typeHint];
                        }
                    }
                }
            }
        }

        return array_values(array_unique($formRequests));
    }

    /**
     * Resolve a fully-qualified class name to an absolute file path.
     *
     * Converts PSR-4 App\ namespace to the app/ directory.
     */
    private function resolveClassPath(string $fqcn): ?string
    {
        if (! str_starts_with($fqcn, 'App\\')) {
            return null;
        }

        $relativePath = str_replace('\\', DIRECTORY_SEPARATOR, $fqcn);
        $relativePath = 'app'.substr($relativePath, 3);

        return base_path($relativePath.'.php');
    }

    /**
     * Extract the fully-qualified class name from PHP source code.
     */
    private function extractClassName(string $content): ?string
    {
        $namespace = null;
        $class = null;

        if (preg_match('/namespace\s+([^;]+);/', $content, $match)) {
            $namespace = trim($match[1]);
        }

        if (preg_match('/class\s+(\w+)/', $content, $match)) {
            $class = $match[1];
        }

        if ($class === null) {
            return null;
        }

        return $namespace !== null ? "{$namespace}\\{$class}" : $class;
    }

    /**
     * Run exploit verification over HIGH+ findings when --verify is active.
     *
     * For each High/Critical finding, loads the source file and asks the AI
     * to construct a working exploit. Findings with a concrete exploit retain
     * their severity (with exploit_verified=true); findings the model cannot
     * exploit are downgraded one tier (Critical→High, High→Medium) with
     * original_severity preserved for audit trail.
     *
     * Score is adjusted by the weight delta of each downgrade so reports
     * reflect the reduced exposure. Returns a new VulnerabilityReport.
     */
    private function maybeVerify(VulnerabilityReport $report, ?string $inlineCode = null): VulnerabilityReport
    {
        if (! $this->verify || $this->verificationEngine === null) {
            return $report;
        }

        if ($this->usageTracker === null) {
            $this->usageTracker = new UsageTracker;
        }

        $verified = [];
        $verifiedCount = 0;
        $downgradedCount = 0;
        $scoreImprovement = 0;
        $fileCache = [];

        foreach ($report->vulnerabilities as $vuln) {
            if (! $this->isVerifiable($vuln)) {
                $verified[] = $vuln;

                continue;
            }

            $contents = $this->loadFileForVerification($vuln->location, $fileCache, $inlineCode);

            if ($contents === null) {
                $verified[] = $vuln;

                continue;
            }

            $updated = $this->verificationEngine->verify($vuln, $contents, $this->usageTracker);
            $verified[] = $updated;

            if ($updated->exploitVerified === true) {
                $verifiedCount++;
            } elseif ($updated->exploitVerified === false && $updated->originalSeverity !== null) {
                $downgradedCount++;
                $scoreImprovement += $updated->originalSeverity->weight() - $updated->severity->weight();
            }
        }

        $newScore = min(100, $report->overallScore + $scoreImprovement);

        return (new VulnerabilityReport(
            vulnerabilities: $verified,
            overallScore: $newScore,
            summary: $report->summary,
            ctfIdea: $report->ctfIdea,
            verificationAttempted: true,
            verifiedCount: $verifiedCount,
            downgradedCount: $downgradedCount,
            verificationInputTokens: $this->usageTracker->getVerificationPromptTokens(),
            verificationOutputTokens: $this->usageTracker->getVerificationCompletionTokens(),
        ))->inheritScanStateFrom($report);
    }

    /**
     * Whether this finding is eligible for exploit verification.
     *
     * Review items are excluded: verification exists to confirm or downgrade an
     * ASSERTION, and a downgrade credits the score back. Paying a second AI
     * request to "verify" a question would let review items move the score
     * upward, which is the same defect as letting them move it downward.
     */
    private function isVerifiable(Vulnerability $vuln): bool
    {
        if (! $vuln->isConfirmedVulnerability()) {
            return false;
        }

        return $vuln->severity === SeverityLevel::Critical
            || $vuln->severity === SeverityLevel::High;
    }

    /**
     * Resolve and cache the source file for a vulnerability location.
     *
     * For inline scans (hack:scanCode), returns the original code regardless
     * of location. For real files, resolves relative paths against base_path
     * and caches reads to avoid re-reading a file for multiple findings.
     */
    private function loadFileForVerification(string $location, array &$cache, ?string $inlineCode): ?string
    {
        if ($inlineCode !== null) {
            return $inlineCode;
        }

        if (array_key_exists($location, $cache)) {
            return $cache[$location];
        }

        $absolute = str_starts_with($location, DIRECTORY_SEPARATOR)
            ? $location
            : base_path($location);

        if (! is_file($absolute) || ! is_readable($absolute)) {
            return $cache[$location] = null;
        }

        $contents = file_get_contents($absolute);

        return $cache[$location] = $contents === false ? null : $contents;
    }

    /**
     * Run the deterministic access-control analyzer over the scanned files and
     * merge its findings into the AI report, de-duplicating overlaps.
     *
     * This is default-on and provider-independent. New findings are appended
     * (after dedupe at file+line+type) and the overall score is reduced by the
     * combined severity weight of any newly-added findings so the report
     * reflects the additional exposure. Never throws — analysis failures are
     * logged and the original report is returned unchanged.
     *
     * @param  array<int, array{path: string, content: string, type: string}>  $files
     */
    private function mergeAccessControlFindings(VulnerabilityReport $report, array $files): VulnerabilityReport
    {
        $analyzer = $this->accessControlAnalyzer ?? new AccessControlAnalyzer;

        try {
            $context = $this->buildAccessControlContext($files);
            $deterministic = $analyzer->analyze($files, $context);
        } catch (\Throwable $e) {
            Log::warning('[HackAuditor] Access-control analysis failed', [
                'error' => $e->getMessage(),
            ]);

            return $report;
        }

        // Always reconcile the AI findings against the deterministic findings.
        // merge() de-dupes across the WHOLE combined list, so even when the
        // deterministic analyzer finds nothing this still collapses duplicate AI
        // findings (same file+line+type) the model emitted for a single issue.
        $merged = $analyzer->merge($report->vulnerabilities, $deterministic);

        // If nothing was appended and nothing collapsed, the report is unchanged.
        if ($merged === $report->vulnerabilities) {
            return $report;
        }

        // Genuinely-new findings (not in the original AI list by identity) are the
        // deterministic findings that were not collapsed into an existing one;
        // penalise the score by their combined severity weight. Collapsing a
        // duplicate AI finding carries no penalty.
        $newFindings = array_filter(
            $merged,
            static fn (Vulnerability $vulnerability): bool => ! in_array($vulnerability, $report->vulnerabilities, true),
        );

        // Only ASSERTED findings move the score. A review item is a question,
        // and a question is not evidence of exposure — letting one dock 20
        // points would smuggle unproven findings back into the number the
        // detectors were rewritten to keep them out of.
        $scorePenalty = 0;
        foreach ($newFindings as $vulnerability) {
            if (! $vulnerability->isConfirmedVulnerability()) {
                continue;
            }

            $scorePenalty += $vulnerability->severity->weight();
        }

        $newScore = max(0, $report->overallScore - $scorePenalty);

        return (new VulnerabilityReport(
            vulnerabilities: $merged,
            overallScore: $newScore,
            summary: $report->summary,
            ctfIdea: $report->ctfIdea,
            verificationAttempted: $report->verificationAttempted,
            verifiedCount: $report->verifiedCount,
            downgradedCount: $report->downgradedCount,
            verificationInputTokens: $report->verificationInputTokens,
            verificationOutputTokens: $report->verificationOutputTokens,
        ))->inheritScanStateFrom($report);
    }

    /**
     * Build the read-only context the access-control detectors consume.
     *
     * Routed-method metadata is sourced from the Laravel Router via
     * RuntimeIntrospector (no DB), and Policy presence is detected by scanning
     * the app/Policies directory on disk.
     *
     * @param  array<int, array{path: string, content: string, type: string}>  $files
     */
    private function buildAccessControlContext(array $files): AccessControlContext
    {
        $routedMethods = [];

        if ($this->runtimeIntrospector !== null) {
            foreach ($files as $file) {
                if ($file['type'] !== 'controller') {
                    continue;
                }

                $className = $this->extractClassName($file['content']);

                if ($className === null) {
                    continue;
                }

                try {
                    $methods = $this->runtimeIntrospector->getRoutedMethods($className);
                    $middlewareMap = $this->runtimeIntrospector->getRouteMiddleware($className);
                } catch (\Throwable) {
                    continue;
                }

                foreach ($methods as $method => $route) {
                    $routedMethods["{$className}@{$method}"] = [
                        'route' => $route,
                        'middleware' => $this->matchMiddlewareForRoute($route, $middlewareMap),
                    ];
                }
            }
        }

        return new AccessControlContext(
            routedMethods: $routedMethods,
            modelsWithPolicy: $this->collectModelsWithPolicy(),
            policyAbilities: $this->collectPolicyAbilities(),
        );
    }

    /**
     * Read app/Policies and report the abilities each Policy ACTUALLY declares.
     *
     * Policy files are context, not scan targets, so they are usually absent
     * from the file list the detectors receive. Without this map a detector can
     * only learn that "a Policy exists", which is the assumption that produced
     * three false "authentication bypass" reports against store() actions whose
     * policy declares no create ability at all. Parsed with the AST layer, never
     * pattern-matched.
     *
     * @return array<string, array<int, string>> Short model name => ability names
     */
    private function collectPolicyAbilities(): array
    {
        $policiesPath = base_path('app/Policies');

        if (! is_dir($policiesPath)) {
            return [];
        }

        $files = glob($policiesPath.DIRECTORY_SEPARATOR.'*.php');

        if ($files === false) {
            return [];
        }

        $parser = new PhpAstParser;
        $inspector = new PolicyInspector;
        $abilities = [];

        foreach ($files as $file) {
            $parsed = $parser->parseFile($file);

            foreach ($parsed->classes() as $class) {
                if (! $inspector->isPolicy($class)) {
                    continue;
                }

                $model = $inspector->modelFor($class);

                if ($model === null) {
                    continue;
                }

                $abilities[TypeNames::shortName($model)] = $inspector->abilities($class);
            }
        }

        return $abilities;
    }

    /**
     * Match the middleware stack for a routed method's route description.
     *
     * The routed-method route is like 'PUT /rooms/{room}'; the middleware map
     * is keyed by 'PUT /rooms/{room}'. We align on the URI portion.
     *
     * @param  array<string, array<int, string>>  $middlewareMap
     * @return array<int, string>
     */
    private function matchMiddlewareForRoute(string $route, array $middlewareMap): array
    {
        $uri = trim((string) strrchr(' '.$route, ' '));

        foreach ($middlewareMap as $key => $middleware) {
            if (str_ends_with($key, $uri) || str_contains($key, $uri)) {
                return $middleware;
            }
        }

        return [];
    }

    /**
     * Collect the set of short model names that have a Policy class on disk.
     *
     * Uses convention (FooPolicy => Foo) without booting the database.
     *
     * @return array<int, string>
     */
    private function collectModelsWithPolicy(): array
    {
        $policiesPath = base_path('app/Policies');

        if (! is_dir($policiesPath)) {
            return [];
        }

        $files = glob($policiesPath.DIRECTORY_SEPARATOR.'*.php');

        if ($files === false) {
            return [];
        }

        $models = [];

        foreach ($files as $file) {
            $name = basename($file, '.php');

            if (str_ends_with($name, 'Policy')) {
                $models[] = substr($name, 0, -strlen('Policy'));
            }
        }

        return array_values(array_unique($models));
    }

    /**
     * Merge multiple VulnerabilityReports into a single consolidated report.
     *
     * Combines all vulnerabilities, calculates a weighted average overall score
     * based on the number of files in each chunk, concatenates summaries, and
     * picks the most relevant CTF idea.
     *
     * @param  array<int, VulnerabilityReport>  $reports
     */
    private function mergeReports(array $reports): VulnerabilityReport
    {
        if (count($reports) === 0) {
            return new VulnerabilityReport(
                vulnerabilities: [],
                overallScore: 100,
                summary: 'No files analyzed.',
                ctfIdea: '',
            );
        }

        if (count($reports) === 1) {
            return $reports[0];
        }

        $allVulnerabilities = [];
        $scoreSum = 0;
        $summaries = [];
        $ctfIdea = '';
        $lowestScore = 100;

        foreach ($reports as $report) {
            $allVulnerabilities = array_merge($allVulnerabilities, $report->vulnerabilities);
            $scoreSum += $report->overallScore;

            if ($report->summary !== '') {
                $summaries[] = $report->summary;
            }

            if ($report->overallScore < $lowestScore && $report->ctfIdea !== '') {
                $lowestScore = $report->overallScore;
                $ctfIdea = $report->ctfIdea;
            }
        }

        $averageScore = (int) round($scoreSum / count($reports));

        $mergedSummary = implode("\n\n", $summaries);

        return new VulnerabilityReport(
            vulnerabilities: $allVulnerabilities,
            overallScore: $averageScore,
            summary: $mergedSummary,
            ctfIdea: $ctfIdea,
        );
    }
}
