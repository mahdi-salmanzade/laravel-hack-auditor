<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Console;

use Illuminate\Console\Command;
use Mahdi\HackAuditor\Report\HtmlReportGenerator;
use Mahdi\HackAuditor\Report\MarkdownReportGenerator;
use Mahdi\HackAuditor\Report\SarifReportGenerator;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\ScanHistory;

final class HackReportCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'hack:report
        {--latest : Generate report from the most recent saved scan (the default)}
        {--id= : Generate report from a specific scan ID (ULID)}
        {--format=html : Report format: html, sarif or markdown}
        {--output= : Custom output file path}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate an HTML, SARIF or Markdown security report from saved scan results';

    /**
     * File extension per supported format.
     *
     * @var array<string, string>
     */
    private const array FORMATS = [
        'html' => 'html',
        'sarif' => 'sarif',
        'markdown' => 'md',
    ];

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $format = strtolower(trim((string) $this->option('format')));

        if (! array_key_exists($format, self::FORMATS)) {
            $this->components->error("Unknown --format '{$format}'. Use one of: ".implode(', ', array_keys(self::FORMATS)).'.');

            return self::INVALID;
        }

        $scanData = $this->resolveScanData();

        if ($scanData === null) {
            return self::FAILURE;
        }

        // fromArray() round-trips every field the scan saved — finding class,
        // confidence, verification, taint trace, coverage, usage — so the
        // regenerated report shows the same evidence and the same score
        // suppression as the scan did.
        $report = VulnerabilityReport::fromArray($scanData);

        $contents = match ($format) {
            'sarif' => (new SarifReportGenerator)->generate($report),
            'markdown' => (new MarkdownReportGenerator)->generate($report),
            default => $this->renderHtml($report, $scanData),
        };

        $outputPath = $this->resolveOutputPath(self::FORMATS[$format]);

        $dir = dirname($outputPath);

        if (! is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        file_put_contents($outputPath, $contents);

        $label = match ($format) {
            'sarif' => 'SARIF',
            'markdown' => 'Markdown',
            default => 'HTML',
        };

        $this->components->info("{$label} report saved to <fg=cyan>{$outputPath}</>");

        return self::SUCCESS;
    }

    /**
     * Render the HTML report for a rebuilt scan.
     *
     * "Files Analyzed" is left to the generator, which reads it from the
     * restored coverage; the meta key this command used to pass
     * ('files_scanned') was never written by hack:scan, so it always showed 0.
     *
     * @param  array<string, mixed>  $scanData
     */
    private function renderHtml(VulnerabilityReport $report, array $scanData): string
    {
        /** @var HtmlReportGenerator $generator */
        $generator = app(HtmlReportGenerator::class);

        return $generator->generate($report, [
            'scanned_at' => $this->stringMeta($scanData, 'created_at', 'Unknown'),
            'duration' => is_numeric($scanData['scan_duration_ms'] ?? null)
                ? round((int) $scanData['scan_duration_ms'] / 1000, 1).'s'
                : 'N/A',
            'provider' => $this->stringMeta($scanData, 'ai_provider', 'Unknown'),
            'model' => $this->stringMeta($scanData, 'ai_model', 'Unknown'),
        ]);
    }

    /**
     * Read a string meta field from saved scan data.
     *
     * @param  array<string, mixed>  $scanData
     */
    private function stringMeta(array $scanData, string $key, string $default): string
    {
        $value = $scanData[$key] ?? null;

        return is_scalar($value) && (string) $value !== '' ? (string) $value : $default;
    }

    /**
     * Resolve the scan data from JSON files.
     *
     * @return array<string, mixed>|null
     */
    private function resolveScanData(): ?array
    {
        $history = new ScanHistory;

        $id = $this->option('id');

        if (is_string($id) && $id !== '') {
            $result = $history->find($id);

            if ($result === null) {
                $this->components->error("No scan found with ID: {$id}");

                return null;
            }

            return $result;
        }

        $result = $history->latest();

        if ($result === null) {
            $this->components->error('No saved scan results found. Run `php artisan hack:scan --save` first.');

            return null;
        }

        return $result;
    }

    /**
     * Resolve the output file path.
     */
    private function resolveOutputPath(string $extension): string
    {
        $output = $this->option('output');

        if (is_string($output) && $output !== '') {
            return str_starts_with($output, DIRECTORY_SEPARATOR)
                ? $output
                : base_path($output);
        }

        /** @var string $outputBase */
        $outputBase = config('hack-auditor.report.output_path', 'hack-auditor/reports');
        $outputDir = storage_path($outputBase);
        $filename = 'scan-'.now()->format('Y-m-d-His').'.'.$extension;

        return $outputDir.DIRECTORY_SEPARATOR.$filename;
    }
}
