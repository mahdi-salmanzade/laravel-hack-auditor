<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Console;

use Illuminate\Console\Command;
use Mahdi\HackAuditor\CTF\CTFGenerator;
use Mahdi\HackAuditor\Models\ScanResult;
use Mahdi\HackAuditor\Support\VulnerabilityType;

use function Laravel\Prompts\spin;

final class HackCTFCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'hack:ctf
        {vulnerability? : Specific vulnerability type}
        {--from-scan : Use latest scan results}
        {--all : Generate CTF for every finding}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate Capture-The-Flag security challenges from scan findings';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $this->displayBanner();

        if ($this->option('from-scan')) {
            return $this->handleFromScan();
        }

        $argument = $this->argument('vulnerability');

        if (is_string($argument) && $argument !== '') {
            return $this->generateForType($argument);
        }

        return $this->handleInteractiveMenu();
    }

    /**
     * Display the CTF command banner.
     */
    private function displayBanner(): void
    {
        $this->newLine();
        $this->line('<fg=cyan>╔══════════════════════════════════════════╗</>');
        $this->line('<fg=cyan>║</>  <options=bold>🏴 HACK AUDITOR — CTF Generator</>         <fg=cyan>║</>');
        $this->line('<fg=cyan>║</>  <fg=gray>Learn security by exploiting it</>.         <fg=cyan>║</>');
        $this->line('<fg=cyan>╚══════════════════════════════════════════╝</>');
        $this->newLine();
    }

    /**
     * Handle CTF generation from the latest scan results.
     */
    private function handleFromScan(): int
    {
        /** @var ScanResult|null $latestScan */
        $latestScan = ScanResult::query()
            ->latest()
            ->first();

        if ($latestScan === null) {
            $this->components->error('No scan results found. Run `php artisan hack:scan --save` first.');

            return self::FAILURE;
        }

        $this->components->info(
            "Loading scan from <options=bold>{$latestScan->created_at->format('Y-m-d H:i')}</>"
            . " — Score: <options=bold>{$latestScan->score}/100</>"
            . " — <options=bold>{$latestScan->total_vulnerabilities}</> vulnerabilities",
        );
        $this->newLine();

        /** @var array<int, array<string, mixed>> $vulnerabilities */
        $vulnerabilities = is_array($latestScan->vulnerabilities) ? $latestScan->vulnerabilities : [];

        if (count($vulnerabilities) === 0) {
            $this->components->warn('The latest scan had no vulnerabilities. Nothing to generate.');

            return self::SUCCESS;
        }

        if ($this->option('all')) {
            return $this->generateAllFromScan($vulnerabilities);
        }

        return $this->pickFromScan($vulnerabilities);
    }

    /**
     * Generate CTF challenges for every vulnerability in the latest scan.
     *
     * @param  array<int, array<string, mixed>>  $vulnerabilities
     */
    private function generateAllFromScan(array $vulnerabilities): int
    {
        $this->components->info("Generating CTF challenges for all <options=bold>" . count($vulnerabilities) . '</> findings...');
        $this->newLine();

        $generator = app(CTFGenerator::class);
        $successCount = 0;

        foreach ($vulnerabilities as $index => $vuln) {
            $type = (string) ($vuln['type'] ?? 'unknown');
            $number = $index + 1;

            $this->line("  <fg=cyan>[{$number}/" . count($vulnerabilities) . "]</> Generating CTF for <options=bold>{$type}</>...");

            try {
                $sourceCode = isset($vuln['proof']) && is_string($vuln['proof']) ? $vuln['proof'] : null;
                $output = spin(
                    callback: fn (): string => $generator->generate($type, $sourceCode),
                    message: "Generating challenge {$number}...",
                );

                $this->displayChallengeResult($output, $type);
                $successCount++;
            } catch (\Throwable $e) {
                $this->components->error("  Failed to generate CTF for {$type}: {$e->getMessage()}");
            }

            $this->newLine();
        }

        $this->displayCompletionSummary($successCount, count($vulnerabilities));

        return self::SUCCESS;
    }

    /**
     * Present scan findings as a numbered list and let the user pick one.
     *
     * @param  array<int, array<string, mixed>>  $vulnerabilities
     */
    private function pickFromScan(array $vulnerabilities): int
    {
        $choices = [];

        foreach ($vulnerabilities as $index => $vuln) {
            $type = (string) ($vuln['type_label'] ?? $vuln['type'] ?? 'Unknown');
            $severity = (string) ($vuln['severity_label'] ?? $vuln['severity'] ?? '?');
            $location = (string) ($vuln['location'] ?? '?');
            $line = (string) ($vuln['line'] ?? '?');

            $choices[] = "[{$severity}] {$type} — {$location}:{$line}";
        }

        /** @var string $selected */
        $selected = $this->choice(
            'Which vulnerability do you want to build a CTF challenge for?',
            $choices,
        );

        $selectedIndex = array_search($selected, $choices, true);

        if ($selectedIndex === false) {
            $this->components->error('Invalid selection.');

            return self::FAILURE;
        }

        $vuln = $vulnerabilities[$selectedIndex];
        $type = (string) ($vuln['type'] ?? 'sql_injection');
        $sourceCode = isset($vuln['proof']) && is_string($vuln['proof']) ? $vuln['proof'] : null;

        return $this->generateChallenge($type, $sourceCode);
    }

    /**
     * Handle the interactive menu when no arguments or flags are provided.
     */
    private function handleInteractiveMenu(): int
    {
        $types = VulnerabilityType::cases();

        $choices = array_map(
            fn (VulnerabilityType $type): string => "{$type->label()} ({$type->owaspCategory()})",
            $types,
        );

        /** @var string $selected */
        $selected = $this->choice(
            'Select a vulnerability type to generate a CTF challenge for',
            $choices,
        );

        $selectedIndex = array_search($selected, $choices, true);

        if ($selectedIndex === false) {
            $this->components->error('Invalid selection.');

            return self::FAILURE;
        }

        $type = $types[$selectedIndex];

        return $this->generateForType($type->value);
    }

    /**
     * Generate a CTF challenge for a specific vulnerability type string.
     */
    private function generateForType(string $vulnerabilityType): int
    {
        try {
            $typeEnum = VulnerabilityType::fromString($vulnerabilityType);
        } catch (\ValueError) {
            $this->components->error("Unknown vulnerability type: {$vulnerabilityType}");
            $this->newLine();
            $this->line('  <fg=gray>Available types:</>');

            foreach (VulnerabilityType::cases() as $case) {
                $this->line("    <fg=cyan>•</> {$case->value} — {$case->label()}");
            }

            return self::FAILURE;
        }

        $this->components->info("Generating CTF challenge for <options=bold>{$typeEnum->label()}</>...");

        return $this->generateChallenge($typeEnum->value);
    }

    /**
     * Generate a single CTF challenge via the CTFGenerator service.
     */
    private function generateChallenge(string $vulnerabilityType, ?string $sourceCode = null): int
    {
        /** @var CTFGenerator $generator */
        $generator = app(CTFGenerator::class);

        try {
            /** @var string $output */
            $output = spin(
                callback: fn (): string => $generator->generate($vulnerabilityType, $sourceCode),
                message: '🏴 Generating CTF challenge...',
            );

            $this->newLine();
            $this->displayChallengeResult($output, $vulnerabilityType);
            $this->newLine();
            $this->displayOutputPath();
            $this->newLine();
            $this->line('  <fg=green;options=bold>Happy hacking! 🏴‍☠️</>');
            $this->newLine();

            return self::SUCCESS;
        } catch (\Throwable $e) {
            $this->components->error("Failed to generate CTF challenge: {$e->getMessage()}");

            return self::FAILURE;
        }
    }

    /**
     * Display the generated challenge summary.
     */
    private function displayChallengeResult(string $output, string $vulnerabilityType): void
    {
        /** @var array<string, mixed>|null $decoded */
        $decoded = json_decode($output, true);

        if (! is_array($decoded)) {
            $this->line("  <fg=green>✓</> Challenge generated for <options=bold>{$vulnerabilityType}</>");

            return;
        }

        $title = (string) ($decoded['title'] ?? 'Untitled Challenge');
        $difficulty = (string) ($decoded['difficulty'] ?? 'Unknown');
        $category = (string) ($decoded['category'] ?? $vulnerabilityType);

        $difficultyColor = match (strtolower($difficulty)) {
            'easy' => 'green',
            'medium' => 'yellow',
            'hard' => 'red',
            'expert' => 'magenta',
            default => 'gray',
        };

        $this->line('  <fg=cyan>━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</>');
        $this->line("  <fg=green;options=bold>✓ Challenge Generated</>");
        $this->line("  <fg=gray>Title:</>       <options=bold>{$title}</>");
        $this->line("  <fg=gray>Category:</>    {$category}");
        $this->line("  <fg=gray>Difficulty:</>  <fg={$difficultyColor}>{$difficulty}</>");

        if (isset($decoded['hints']) && is_string($decoded['hints'])) {
            $this->line("  <fg=gray>Hints:</>       <fg=yellow>" . mb_substr($decoded['hints'], 0, 80) . '...</>');
        }

        $this->line('  <fg=cyan>━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</>');
    }

    /**
     * Display the path where CTF files are generated.
     */
    private function displayOutputPath(): void
    {
        /** @var string $outputPath */
        $outputPath = config('hack-auditor.ctf.output_path', 'storage/hack-auditor/ctf');

        $absolutePath = base_path($outputPath);

        $this->line("  <fg=gray>📁 Challenge files:</> <fg=cyan>{$absolutePath}</>");
    }

    /**
     * Display the summary after generating all CTF challenges.
     */
    private function displayCompletionSummary(int $successCount, int $totalCount): void
    {
        $this->line('  <fg=cyan>━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</>');

        if ($successCount === $totalCount) {
            $this->line("  <fg=green;options=bold>✓ All {$totalCount} CTF challenges generated successfully!</>");
        } else {
            $this->line("  <fg=yellow;options=bold>⚠ Generated {$successCount}/{$totalCount} CTF challenges</>");
        }

        $this->displayOutputPath();
        $this->newLine();
        $this->line('  <fg=green;options=bold>Happy hacking! 🏴‍☠️</>');
        $this->newLine();
    }
}
