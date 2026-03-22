<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner;

use Illuminate\Support\Facades\Log;
use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\AI\ResponseParser;
use Mahdi\HackAuditor\Contracts\ScannerInterface;
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
    ) {}

    private ?AppContext $appContext = null;

    private ?UsageTracker $usageTracker = null;

    private int $filesSkipped = 0;

    private int $chunksFailedParse = 0;

    /**
     * Set the usage tracker for token consumption monitoring.
     */
    public function setUsageTracker(UsageTracker $tracker): void
    {
        $this->usageTracker = $tracker;
        $this->filesSkipped = 0;
        $this->chunksFailedParse = 0;
    }

    /**
     * Get the number of chunks that failed to parse during the last scan.
     */
    public function getChunksFailedParse(): int
    {
        return $this->chunksFailedParse;
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
        $files = $this->fileCollector->collect();

        if ($files->isEmpty()) {
            return new VulnerabilityReport(
                vulnerabilities: [],
                overallScore: 100,
                summary: 'No files found to scan.',
                ctfIdea: '',
            );
        }

        $chunks = $this->codeExtractor->chunk($files);

        // Collect context once using all controller files from all chunks
        $this->collectAppContext($chunks);

        return $this->scanChunks($chunks);
    }

    /**
     * Scan a specific file for security vulnerabilities.
     */
    public function scanFile(string $path): VulnerabilityReport
    {
        $absolutePath = str_starts_with($path, DIRECTORY_SEPARATOR)
            ? $path
            : base_path($path);

        if (! file_exists($absolutePath)) {
            return new VulnerabilityReport(
                vulnerabilities: [],
                overallScore: 100,
                summary: "File not found: {$path}",
                ctfIdea: '',
            );
        }

        $file = new SplFileInfo($absolutePath);
        $extracted = $this->codeExtractor->extract($file);

        // Collect context for single file scan
        if ($this->contextCollector !== null && $extracted['type'] === 'controller') {
            $this->appContext = $this->contextCollector->collect([$extracted]);
        }

        try {
            $report = $this->analyzeFiles([$extracted]);
        } catch (\Throwable $e) {
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

        if ($this->usageTracker !== null) {
            $report->setUsageTracker($this->usageTracker);
        }

        return $report;
    }

    /**
     * Scan a raw code string for security vulnerabilities.
     */
    public function scanCode(string $code): VulnerabilityReport
    {
        $fileData = [
            'path' => 'inline-code.php',
            'content' => $code,
            'type' => 'other',
        ];

        try {
            $report = $this->analyzeFiles([$fileData]);
        } catch (\Throwable $e) {
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

        if ($this->usageTracker !== null) {
            $report->setUsageTracker($this->usageTracker);
        }

        return $report;
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

                    continue;
                }
            }

            try {
                $reports[] = $this->analyzeFiles($chunk);
            } catch (\Throwable $e) {
                $this->chunksFailedParse++;

                Log::warning('[HackAuditor] Skipping chunk due to AI failure', [
                    'files' => array_map(fn (array $f): string => $f['path'], $chunk),
                    'error' => $e->getMessage(),
                ]);
            }
        }

        $report = $this->mergeReports($reports);

        if ($this->usageTracker !== null) {
            $report->setUsageTracker($this->usageTracker);
            $report->setFilesSkipped($this->filesSkipped);
        }

        return $report;
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
     * @param  array<int, array{path: string, content: string, type: string}>  $files
     */
    private function injectModelContext(array $files): void
    {
        if ($this->runtimeIntrospector === null) {
            return;
        }

        $modelContext = [];

        foreach ($files as $file) {
            if ($file['type'] !== 'controller') {
                continue;
            }

            $modelClasses = $this->extractModelReferences($file['content']);

            foreach ($modelClasses as $modelClass) {
                if (isset($modelContext[$modelClass])) {
                    continue;
                }

                try {
                    $info = $this->runtimeIntrospector->getModelInfo($modelClass);

                    if ($info !== null) {
                        $modelContext[$modelClass] = $info;
                    }
                } catch (\Throwable) {
                    // Model introspection is best-effort
                }
            }
        }

        if ($modelContext !== []) {
            $this->promptBuilder->withModelContext($modelContext);
        }
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
                if (preg_match_all('/(\w+)\s+\$\w+/', $params, $paramMatches)) {
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
