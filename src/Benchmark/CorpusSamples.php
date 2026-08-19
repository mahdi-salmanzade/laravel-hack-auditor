<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Benchmark;

use FilesystemIterator;
use Mahdi\HackAuditor\Scanner\Php\PhpAstParser;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use SplFileInfo;

/**
 * The labeled corpus, loaded from disk in the shape the scanner passes around.
 *
 * Two jobs:
 *
 *  1. Hand the deterministic engine the corpus files directly, so the accuracy
 *     gate can be driven with no AI provider and no application boot.
 *  2. AUDIT the corpus for analysability. A benchmark sample that the engine
 *     silently drops before analysis is worse than a failing sample: the gate
 *     keeps printing a score while measuring less and less. That is exactly how
 *     the planted IDOR at samples/IdorController.php:14 stopped being credited
 *     without a single test going red.
 *
 * The audit answers two questions about every sample:
 *
 *  - does it parse? (an unparsable sample is dropped by the AST layer)
 *  - is every public controller action in it named by the route manifest?
 *    (an unrouted action resolves to 'unreachable' and is dropped by the
 *     access-control engine)
 *
 * Content is read RAW. The full scan pipeline normalises whitespace and strips
 * block comments before analysis; the corpus contains neither, so raw and
 * normalised content are byte-identical and the ground-truth line numbers mean
 * the same thing on both paths.
 */
final readonly class CorpusSamples
{
    /**
     * @param  array<int, array{path: string, content: string, type: string}>  $files
     */
    public function __construct(
        public string $root,
        public array $files,
    ) {}

    /**
     * Load the corpus packaged with the benchmark.
     */
    public static function default(): self
    {
        return self::fromDirectory(GroundTruth::defaultSamplesPath());
    }

    /**
     * Load every PHP file under a samples directory, sorted by relative path so
     * the corpus is enumerated in a stable order on every machine.
     */
    public static function fromDirectory(string $directory): self
    {
        if (! is_dir($directory)) {
            throw new RuntimeException("Benchmark samples directory not found: {$directory}");
        }

        $root = realpath($directory);
        $root = $root === false ? $directory : $root;

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        );

        $files = [];

        foreach ($iterator as $file) {
            if (! $file instanceof SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }

            $relative = str_replace(
                DIRECTORY_SEPARATOR,
                '/',
                substr($file->getPathname(), strlen($root) + 1),
            );

            $content = (string) file_get_contents($file->getPathname());

            $files[] = [
                'path' => $relative,
                'content' => $content,
                'type' => self::detectType($content, $relative),
            ];
        }

        usort($files, static fn (array $a, array $b): int => strcmp($a['path'], $b['path']));

        return new self($root, $files);
    }

    /**
     * Corpus files whose type the scanner treats as a controller.
     *
     * @return array<int, array{path: string, content: string, type: string}>
     */
    public function controllerFiles(): array
    {
        return array_values(array_filter(
            $this->files,
            static fn (array $file): bool => $file['type'] === 'controller',
        ));
    }

    /**
     * Corpus files the AST layer cannot parse, as "path: error" strings.
     *
     * @return array<int, string>
     */
    public function unparsableFiles(): array
    {
        $parser = new PhpAstParser;
        $broken = [];

        foreach ($this->files as $file) {
            $parsed = $parser->parse($file['path'], $file['content']);

            if (! $parsed->isAnalysable()) {
                $broken[] = $file['path'].': '.($parsed->parseError ?? 'not analysable');
            }
        }

        return $broken;
    }

    /**
     * Every public controller action in the corpus, as "path::Class@method".
     *
     * @return array<int, array{path: string, class: string, method: string}>
     */
    public function controllerActions(): array
    {
        $parser = new PhpAstParser;
        $actions = [];

        foreach ($this->controllerFiles() as $file) {
            $parsed = $parser->parse($file['path'], $file['content']);

            foreach ($parsed->classes() as $class) {
                foreach ($class->publicMethods() as $method) {
                    if ($method->isConstructor() || $method->isMagic() || $method->isStatic()) {
                        continue;
                    }

                    $actions[] = [
                        'path' => $file['path'],
                        'class' => $class->shortName(),
                        'method' => $method->name(),
                    ];
                }
            }
        }

        return $actions;
    }

    /**
     * Controller actions the route manifest does NOT name.
     *
     * A non-empty result invalidates the measurement: those samples resolve to
     * 'unreachable' and are dropped before the access-control engine ever looks
     * at them, so any recall the gate reports for them is a fiction.
     *
     * @return array<int, string> Human-readable "path: Class@method" entries
     */
    public function unroutedActions(CorpusRoutes $routes): array
    {
        $unrouted = [];

        foreach ($this->controllerActions() as $action) {
            if ($routes->covers($action['class'], $action['method'])) {
                continue;
            }

            $unrouted[] = sprintf('%s: %s@%s', $action['path'], $action['class'], $action['method']);
        }

        return $unrouted;
    }

    /**
     * Classify a corpus file the same way CodeExtractor classifies a scanned one.
     *
     * Kept deliberately identical in behaviour so a sample that the full scan
     * treats as a controller is also treated as one on the deterministic path;
     * a divergence here would mean the two paths measure different corpora.
     */
    private static function detectType(string $content, string $relativePath): string
    {
        if (str_contains($relativePath, 'routes/')) {
            return 'route';
        }

        return match (true) {
            (bool) preg_match('/extends\s+Controller\b/', $content) => 'controller',
            (bool) preg_match('/extends\s+Model\b/', $content) => 'model',
            (bool) preg_match('/extends\s+Middleware\b/', $content) => 'middleware',
            (bool) preg_match('/extends\s+FormRequest\b/', $content) => 'request',
            default => 'other',
        };
    }
}
