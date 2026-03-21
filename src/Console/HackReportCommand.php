<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Console;

use Illuminate\Console\Command;
use Mahdi\HackAuditor\Models\ScanResult;
use Mahdi\HackAuditor\Report\HtmlReportGenerator;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

final class HackReportCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'hack:report
        {--latest : Generate report from the most recent saved scan}
        {--id= : Generate report from a specific scan ID (ULID)}
        {--output= : Custom output file path}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate an HTML security report from saved scan results';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $scanResult = $this->resolveScanResult();

        if ($scanResult === null) {
            return self::FAILURE;
        }

        $report = $this->buildReport($scanResult);

        /** @var HtmlReportGenerator $generator */
        $generator = app(HtmlReportGenerator::class);

        $html = $generator->generate($report, [
            'scanned_at' => $scanResult->created_at?->format('Y-m-d H:i:s') ?? 'Unknown',
            'duration' => $scanResult->scan_duration_ms !== null
                ? round($scanResult->scan_duration_ms / 1000, 1).'s'
                : 'N/A',
            'provider' => $scanResult->ai_provider ?? 'Unknown',
            'model' => $scanResult->ai_model ?? 'Unknown',
            'total_files' => $scanResult->files_scanned ?? 0,
        ]);

        $outputPath = $this->resolveOutputPath();

        $dir = dirname($outputPath);

        if (! is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        file_put_contents($outputPath, $html);

        $this->components->info("HTML report saved to <fg=cyan>{$outputPath}</>");

        return self::SUCCESS;
    }

    /**
     * Resolve the scan result from the database.
     */
    private function resolveScanResult(): ?ScanResult
    {
        try {
            $id = $this->option('id');

            if (is_string($id) && $id !== '') {
                /** @var ScanResult|null $result */
                $result = ScanResult::query()->find($id);

                if ($result === null) {
                    $this->components->error("No scan found with ID: {$id}");

                    return null;
                }

                return $result;
            }

            /** @var ScanResult|null $result */
            $result = ScanResult::query()->latest()->first();

            if ($result === null) {
                $this->components->error('No saved scan results found. Run `php artisan hack:scan --save` first.');

                return null;
            }

            return $result;
        } catch (\Throwable $e) {
            $this->components->error("Failed to load scan results: {$e->getMessage()}");
            $this->components->warn('Have you run the migrations? Try: php artisan migrate');

            return null;
        }
    }

    /**
     * Build a VulnerabilityReport from a saved ScanResult.
     */
    private function buildReport(ScanResult $scanResult): VulnerabilityReport
    {
        /** @var array<int, array<string, mixed>> $vulnData */
        $vulnData = is_array($scanResult->vulnerabilities) ? $scanResult->vulnerabilities : [];

        $vulnerabilities = array_map(function (array $data): Vulnerability {
            return new Vulnerability(
                type: VulnerabilityType::fromString((string) ($data['type'] ?? 'missing_validation')),
                location: (string) ($data['location'] ?? 'unknown'),
                line: (int) ($data['line'] ?? 0),
                severity: SeverityLevel::fromString((string) ($data['severity'] ?? 'low')),
                description: (string) ($data['description'] ?? ''),
                proof: (string) ($data['proof'] ?? ''),
                fix: (string) ($data['fix'] ?? ''),
            );
        }, $vulnData);

        return new VulnerabilityReport(
            vulnerabilities: $vulnerabilities,
            overallScore: $scanResult->score,
            summary: $scanResult->summary ?? '',
            ctfIdea: '',
        );
    }

    /**
     * Resolve the output file path.
     */
    private function resolveOutputPath(): string
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
        $filename = 'scan-'.now()->format('Y-m-d-His').'.html';

        return $outputDir.DIRECTORY_SEPARATOR.$filename;
    }
}
