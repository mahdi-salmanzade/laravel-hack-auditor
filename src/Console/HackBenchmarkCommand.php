<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Console;

use Illuminate\Console\Command;
use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Routing\Router;
use Mahdi\HackAuditor\Benchmark\BenchmarkRunner;
use Mahdi\HackAuditor\Benchmark\CorpusRoutes;
use Mahdi\HackAuditor\Benchmark\CorpusSamples;
use Mahdi\HackAuditor\Benchmark\GroundTruth;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlAnalyzer;
use Mahdi\HackAuditor\Scanner\FileCollector;
use Mahdi\HackAuditor\Scanner\HackScanner;
use Mahdi\HackAuditor\Scanner\RuntimeIntrospector;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;

/**
 * Runs the scanner over the packaged labeled corpus and reports its accuracy
 * (precision / recall / F1) against the ground-truth labels.
 *
 * WHAT THIS MEASURES. The corpus is synthetic: every sample was authored
 * alongside the detectors, and the routes that expose them are declared in the
 * corpus's own manifest. That makes this a RECALL check and a regression gate —
 * "does the engine still find the bugs it is supposed to find" — not a precision
 * claim about real code. Precision is measured separately, against unmodified
 * third-party applications. The command says so in its own output; do not quote
 * these numbers as a real-world false-positive rate.
 *
 * REACHABILITY. The access-control engine refuses to report a record exposure it
 * cannot attribute to a routed entry point. Standalone fixture files have no
 * application around them, so without a route table every sample resolved to
 * 'unreachable' and was dropped before analysis — the gate went on printing a
 * score for detectors it had stopped exercising. The corpus therefore ships its
 * own route manifest, and this command builds a Router from it and hands the
 * scanner a RuntimeIntrospector backed by that Router. The reachability rule is
 * untouched; the corpus simply describes the application it is.
 *
 * Any controller sample the manifest does not name is reported and the run FAILS
 * — an unmeasured sample must never be mistaken for a passing one.
 *
 * Designed as a CI gate: pass --min-f1 to fail the build when accuracy drops
 * below a threshold. --deterministic scores only the reproducible engine and
 * needs no AI key at all; a full run needs one (tests fake the AIAdapter).
 */
final class HackBenchmarkCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'hack:benchmark
        {--min-f1= : Minimum overall F1 score required to pass (0.0 - 1.0); exits non-zero when below}
        {--ground-truth= : Path to a custom ground-truth.json file}
        {--samples= : Path to a custom samples directory}
        {--routes= : Path to a custom corpus route manifest (see tests/Fixtures/benchmark/routes.php)}
        {--deterministic : Score only the reproducible engine (no AI provider required)}
        {--json : Output the benchmark result as JSON}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Measure scanner accuracy (precision/recall/F1) against a labeled vulnerability corpus';

    /**
     * The scope caveat printed with every result. Stated in the output, not only
     * in the docs, so a number copied out of a terminal carries its own context.
     */
    private const CAVEAT = 'Measured on a SYNTHETIC corpus authored alongside the detectors: a recall check '
        .'and regression gate, not a precision claim about real code. Real-code precision is measured separately.';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $groundTruthPath = $this->stringOption('ground-truth') ?? GroundTruth::defaultPath();
        $samplesPath = $this->stringOption('samples') ?? GroundTruth::defaultSamplesPath();
        $routesPath = $this->stringOption('routes') ?? CorpusRoutes::defaultPath();

        if (! is_dir($samplesPath)) {
            $this->error("Samples directory not found: {$samplesPath}");

            return self::FAILURE;
        }

        try {
            $groundTruth = GroundTruth::fromFile($groundTruthPath);
            $routes = CorpusRoutes::fromFile($routesPath);
            $samples = CorpusSamples::fromDirectory($samplesPath);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        if (! $this->assertCorpusIsAnalysable($samples, $routes, $routesPath)) {
            return self::FAILURE;
        }

        $deterministic = (bool) $this->option('deterministic');
        $scored = $deterministic
            ? $groundTruth->onlyEngine(GroundTruth::ENGINE_DETERMINISTIC)
            : $groundTruth;

        $findings = $deterministic
            ? $this->analyzeCorpus($samples, $routes)
            : $this->scanCorpus($samplesPath, $routes)->vulnerabilities;

        $result = (new BenchmarkRunner($scored))->score($findings);

        $minF1 = $this->minF1();
        $passed = $minF1 === null || $result['f1'] >= $minF1;

        if ($this->option('json')) {
            return $this->outputJson($result, $groundTruth, $minF1, $passed, $deterministic);
        }

        $this->renderTable($result, $scored, $groundTruth, $minF1, $passed, $deterministic);

        return $passed ? self::SUCCESS : self::FAILURE;
    }

    /**
     * Refuse to score a corpus the engine cannot actually analyse.
     *
     * Two ways a sample goes silently unmeasured: it fails to parse, or no route
     * names its controller action so the access-control engine treats it as
     * unreachable and drops it. Either one turns the reported score into a claim
     * about a smaller corpus than the one on disk, which is precisely the defect
     * this check exists to make impossible.
     */
    private function assertCorpusIsAnalysable(CorpusSamples $samples, CorpusRoutes $routes, string $routesPath): bool
    {
        $unparsable = $samples->unparsableFiles();

        if ($unparsable !== []) {
            $this->error('Corpus samples that do not parse (they would be dropped before analysis):');

            foreach ($unparsable as $entry) {
                $this->line('  - '.$entry);
            }

            return false;
        }

        $unrouted = $samples->unroutedActions($routes);

        if ($unrouted !== []) {
            $this->error('Corpus controller actions with no route in the manifest:');

            foreach ($unrouted as $entry) {
                $this->line('  - '.$entry);
            }

            $this->newLine();
            $this->line('  Unrouted actions resolve to <fg=yellow>unreachable</> and are dropped before the');
            $this->line('  access-control engine sees them, so any score reported for them is a fiction.');
            $this->line('  Add them to <fg=cyan>'.$routesPath.'</> (or point <fg=cyan>--routes</> at a manifest that covers them).');

            return false;
        }

        return true;
    }

    /**
     * Run ONLY the reproducible detectors over the corpus.
     *
     * No AI provider, no application boot, no network: the deterministic engine
     * is handed the corpus files and a context built straight from the corpus's
     * route manifest. This is the path a CI gate can run on every commit.
     *
     * @return array<int, Vulnerability>
     */
    private function analyzeCorpus(CorpusSamples $samples, CorpusRoutes $routes): array
    {
        if (! $this->option('json')) {
            $this->line('  Analysing labeled corpus at <fg=cyan>'.$samples->root.'</> (deterministic engine only)...');
        }

        return (new AccessControlAnalyzer)->analyze($samples->files, $routes->context());
    }

    /**
     * Run a real, full scan over the corpus directory.
     *
     * Temporarily repoints the application's base path and scan configuration at
     * the samples directory, and swaps in a RuntimeIntrospector backed by a
     * Router carrying ONLY the corpus's own routes, so the scanner sees the
     * corpus as the self-contained application it describes. Everything is
     * restored regardless of outcome.
     */
    private function scanCorpus(string $samplesPath, CorpusRoutes $routes): VulnerabilityReport
    {
        /** @var string $originalBasePath */
        $originalBasePath = $this->laravel->basePath();
        $config = $this->laravel['config'];

        $originalPaths = $config->get('hack-auditor.scan.paths');
        $originalExclude = $config->get('hack-auditor.scan.exclude');
        $originalIntrospector = $this->laravel->make(RuntimeIntrospector::class);

        $resolvedSamples = realpath($samplesPath);
        $samplesRoot = $resolvedSamples === false ? $samplesPath : $resolvedSamples;

        try {
            $this->laravel->setBasePath($samplesRoot);
            $config->set('hack-auditor.scan.paths', ['']);
            $config->set('hack-auditor.scan.exclude', []);

            $this->laravel->instance(
                RuntimeIntrospector::class,
                new RuntimeIntrospector($this->corpusRouter($routes)),
            );

            // Rebuild the FileCollector so it re-reads the overridden config, and
            // the HackScanner so it takes the corpus-backed RuntimeIntrospector.
            $this->laravel->forgetInstance(FileCollector::class);
            $this->laravel->forgetInstance(HackScanner::class);

            if (! $this->option('json')) {
                $this->line('  Scanning labeled corpus at <fg=cyan>'.$samplesRoot.'</> ('
                    .count($routes->routes).' corpus routes)...');
            }

            /** @var HackScanner $scanner */
            $scanner = $this->laravel->make(HackScanner::class);

            return $scanner->scan();
        } finally {
            $this->laravel->setBasePath($originalBasePath);
            $config->set('hack-auditor.scan.paths', $originalPaths);
            $config->set('hack-auditor.scan.exclude', $originalExclude);
            $this->laravel->instance(RuntimeIntrospector::class, $originalIntrospector);
            $this->laravel->forgetInstance(FileCollector::class);
            $this->laravel->forgetInstance(HackScanner::class);
        }
    }

    /**
     * A Router carrying only the corpus's own routes.
     *
     * Built fresh rather than mutating the host application's route table, so a
     * benchmark run can never leave routes behind or read the host's. The
     * controller classes the manifest names are fixture text and are never
     * loaded: Laravel resolves a controller only when dispatching a request,
     * and the scanner only ever reads the table.
     */
    private function corpusRouter(CorpusRoutes $routes): Router
    {
        $application = $this->laravel;

        $router = new Router(
            $this->laravel->make(Dispatcher::class),
            $application instanceof Container ? $application : null,
        );

        $routes->registerInto($router);

        return $router;
    }

    /**
     * Render the human-readable benchmark report.
     *
     * @param  array<string, mixed>  $result
     */
    private function renderTable(
        array $result,
        GroundTruth $scored,
        GroundTruth $full,
        ?float $minF1,
        bool $passed,
        bool $deterministic,
    ): void {
        $this->newLine();
        $this->components->info('Hack Auditor — Accuracy Benchmark');

        $this->line('  <fg=gray>corpus</>     '.count($full->files()).' samples '
            .'('.$full->expectedVulnerabilityCount().' labeled vulns, '
            .$full->cleanSampleCount().' clean)');
        $this->line('  <fg=gray>scope</>      '.($deterministic
            ? 'deterministic engine only — '.$scored->expectedVulnerabilityCount().' of '
                .$full->expectedVulnerabilityCount().' labels scored, no AI provider used'
            : 'full pipeline — AI pass + deterministic engine'));
        $this->newLine();

        $this->table(
            ['<options=bold>Metric</>', '<options=bold>Value</>'],
            [
                ['True Positives', (string) $result['true_positives']],
                ['False Positives', (string) $result['false_positives']],
                ['False Negatives', (string) $result['false_negatives']],
                ['Precision', $this->pct($result['precision'])],
                ['Recall', $this->pct($result['recall'])],
                ['F1 Score', $this->pct($result['f1'])],
            ],
        );

        if ($result['per_type'] !== []) {
            $this->newLine();
            $this->line('  <options=bold>Per-Type Breakdown</>');

            $rows = [];
            foreach ($result['per_type'] as $type => $row) {
                $rows[] = [
                    $type,
                    $row['true_positives'].' / '.$row['false_positives'].' / '.$row['false_negatives'],
                    $this->pct($row['precision']),
                    $this->pct($row['recall']),
                    $this->pct($row['f1']),
                ];
            }

            $this->table(
                ['<options=bold>Type</>', '<options=bold>TP/FP/FN</>', '<options=bold>Prec</>', '<options=bold>Rec</>', '<options=bold>F1</>'],
                $rows,
            );
        }

        if ($deterministic) {
            $excluded = $full->labelsExcludedFrom(GroundTruth::ENGINE_DETERMINISTIC);

            if ($excluded !== []) {
                $this->newLine();
                $this->line('  <fg=gray>Not scored here (AI-owned labels): '.implode(', ', $excluded).'</>');
            }
        }

        $this->newLine();
        $this->line('  <fg=yellow>SCOPE</> '.wordwrap(self::CAVEAT, 100, "\n        "));
        $this->newLine();

        if ($minF1 === null) {
            $this->line('  <fg=gray>No --min-f1 threshold set; reporting only.</>');

            return;
        }

        if ($passed) {
            $this->line(sprintf(
                '  <fg=green;options=bold>PASS</> F1 %s >= threshold %s',
                $this->pct($result['f1']),
                $this->pct($minF1),
            ));
        } else {
            $this->line(sprintf(
                '  <fg=red;options=bold>FAIL</> F1 %s < threshold %s',
                $this->pct($result['f1']),
                $this->pct($minF1),
            ));
        }
    }

    /**
     * Emit the benchmark result as JSON and return the exit code.
     *
     * @param  array<string, mixed>  $result
     */
    private function outputJson(
        array $result,
        GroundTruth $full,
        ?float $minF1,
        bool $passed,
        bool $deterministic,
    ): int {
        $payload = $result;
        $payload['scope'] = $deterministic ? 'deterministic' : 'full';
        $payload['corpus'] = 'synthetic';
        $payload['caveat'] = self::CAVEAT;

        if ($deterministic) {
            $payload['labels_not_scored'] = $full->labelsExcludedFrom(GroundTruth::ENGINE_DETERMINISTIC);
        }

        $payload['min_f1'] = $minF1;
        $payload['passed'] = $passed;

        $this->line((string) json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        return $passed ? self::SUCCESS : self::FAILURE;
    }

    /**
     * Parse and validate the --min-f1 threshold option.
     */
    private function minF1(): ?float
    {
        $raw = $this->stringOption('min-f1');

        if ($raw === null) {
            return null;
        }

        return max(0.0, min(1.0, (float) $raw));
    }

    /**
     * Return a string option value or null when absent/empty.
     */
    private function stringOption(string $name): ?string
    {
        $value = $this->option($name);

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * Format a 0.0-1.0 ratio as a percentage string.
     */
    private function pct(float $value): string
    {
        return number_format($value * 100, 1).'%';
    }
}
