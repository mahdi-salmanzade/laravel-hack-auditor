<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Console;

use Illuminate\Console\Command;
use Mahdi\HackAuditor\Benchmark\BenchmarkRunner;
use Mahdi\HackAuditor\Benchmark\GroundTruth;
use Mahdi\HackAuditor\Scanner\FileCollector;
use Mahdi\HackAuditor\Scanner\HackScanner;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;

/**
 * Runs the scanner over the packaged labeled corpus and reports its accuracy
 * (precision / recall / F1) against the ground-truth labels.
 *
 * Designed as a CI gate: pass --min-f1 to fail the build when accuracy drops
 * below a threshold. The real scan needs an AI key; tests fake the AIAdapter.
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
        {--json : Output the benchmark result as JSON}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Measure scanner accuracy (precision/recall/F1) against a labeled vulnerability corpus';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $groundTruthPath = $this->stringOption('ground-truth') ?? GroundTruth::defaultPath();
        $samplesPath = $this->stringOption('samples') ?? GroundTruth::defaultSamplesPath();

        if (! is_dir($samplesPath)) {
            $this->error("Samples directory not found: {$samplesPath}");

            return self::FAILURE;
        }

        try {
            $groundTruth = GroundTruth::fromFile($groundTruthPath);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $report = $this->scanCorpus($samplesPath);

        $runner = new BenchmarkRunner($groundTruth);
        $result = $runner->score($report->vulnerabilities);

        $minF1 = $this->minF1();
        $passed = $minF1 === null || $result['f1'] >= $minF1;

        if ($this->option('json')) {
            return $this->outputJson($result, $minF1, $passed);
        }

        $this->renderTable($result, $groundTruth, $minF1, $passed);

        return $passed ? self::SUCCESS : self::FAILURE;
    }

    /**
     * Run a real scan over the corpus directory.
     *
     * Temporarily repoints the application's base path and scan configuration
     * at the samples directory so the existing HackScanner pipeline analyzes the
     * labeled fixtures, then restores the original state regardless of outcome.
     */
    private function scanCorpus(string $samplesPath): VulnerabilityReport
    {
        /** @var string $originalBasePath */
        $originalBasePath = $this->laravel->basePath();
        $config = $this->laravel['config'];

        $originalPaths = $config->get('hack-auditor.scan.paths');
        $originalExclude = $config->get('hack-auditor.scan.exclude');

        $resolvedSamples = realpath($samplesPath);
        $samplesRoot = $resolvedSamples === false ? $samplesPath : $resolvedSamples;

        try {
            $this->laravel->setBasePath($samplesRoot);
            $config->set('hack-auditor.scan.paths', ['']);
            $config->set('hack-auditor.scan.exclude', []);

            // Rebuild the FileCollector so it re-reads the overridden config.
            $this->laravel->forgetInstance(FileCollector::class);
            $this->laravel->forgetInstance(HackScanner::class);

            if (! $this->option('json')) {
                $this->line('  Scanning labeled corpus at <fg=cyan>'.$samplesRoot.'</>...');
            }

            /** @var HackScanner $scanner */
            $scanner = $this->laravel->make(HackScanner::class);

            return $scanner->scan();
        } finally {
            $this->laravel->setBasePath($originalBasePath);
            $config->set('hack-auditor.scan.paths', $originalPaths);
            $config->set('hack-auditor.scan.exclude', $originalExclude);
            $this->laravel->forgetInstance(FileCollector::class);
            $this->laravel->forgetInstance(HackScanner::class);
        }
    }

    /**
     * Render the human-readable benchmark report.
     *
     * @param  array<string, mixed>  $result
     */
    private function renderTable(array $result, GroundTruth $groundTruth, ?float $minF1, bool $passed): void
    {
        $this->newLine();
        $this->components->info('Hack Auditor — Accuracy Benchmark');

        $this->line('  <fg=gray>corpus</>     '.count($groundTruth->files()).' samples '
            .'('.$groundTruth->expectedVulnerabilityCount().' labeled vulns, '
            .$groundTruth->cleanSampleCount().' clean)');
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
    private function outputJson(array $result, ?float $minF1, bool $passed): int
    {
        $payload = $result;
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
