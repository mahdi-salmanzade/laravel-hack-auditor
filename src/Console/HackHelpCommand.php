<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Console;

use Illuminate\Console\Command;
use Mahdi\HackAuditor\Support\ScanHistory;
use Mahdi\HackAuditor\Support\VulnerabilityType;

final class HackHelpCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'hack:help {topic? : Show detailed help for a specific command (demo, scan, ctf, report)}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Show all Laravel Hack Auditor commands, flags, and usage examples';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $command = $this->argument('topic');

        if (! is_string($command) || $command === '') {
            $this->showOverview();

            return self::SUCCESS;
        }

        return match ($command) {
            'demo' => $this->showDemoHelp(),
            'scan' => $this->showScanHelp(),
            'ctf' => $this->showCtfHelp(),
            'report' => $this->showReportHelp(),
            default => $this->showUnknownCommand($command),
        };
    }

    /**
     * Display the full command overview with quick start and examples.
     */
    private function showOverview(): void
    {
        $this->displayBanner();

        $this->line('');
        $this->line('  <fg=white;options=bold>QUICK START</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');
        $this->line('  <fg=cyan>php artisan hack:demo</>           Zero-config demo');
        $this->line('  <fg=cyan>php artisan hack:scan</>           Full AI security scan');
        $this->line('  <fg=cyan>php artisan hack:ctf</>            Generate CTF challenges');
        $this->line('  <fg=cyan>php artisan hack:report</>         HTML report from saved scan');
        $this->line('  <fg=cyan>php artisan hack:usage</>         Token usage & cost stats');
        $this->line('');

        $this->showCommandSection(
            'hack:demo',
            'Run a dramatic demo on a purposely vulnerable controller — no API key needed.',
            [
                'php artisan hack:demo' => 'Run with animations',
                'php artisan hack:demo --quick' => 'Skip animations',
            ],
        );

        $this->showCommandSection(
            'hack:scan',
            'Scan your Laravel app for security vulnerabilities using AI.',
            [
                'php artisan hack:scan' => 'Scan all configured paths',
                'php artisan hack:scan --path=app/Http' => 'Scan specific directory',
                'php artisan hack:scan --json' => 'Machine-readable output',
                'php artisan hack:scan --diff' => 'Only scan changed files',
            ],
            'Requires an AI provider API key in .env',
        );

        $this->showCommandSection(
            'hack:ctf',
            'Generate Capture-The-Flag security challenges from scan findings.',
            [
                'php artisan hack:ctf' => 'Interactive menu',
                'php artisan hack:ctf sql_injection' => 'Specific vulnerability type',
                'php artisan hack:ctf --from-scan' => 'From latest saved scan',
                'php artisan hack:ctf --from-scan --all' => 'All findings at once',
            ],
            'Requires an AI provider API key in .env',
        );

        $this->showCommandSection(
            'hack:report',
            'Generate an HTML report from saved scan results.',
            [
                'php artisan hack:report --latest' => 'Most recent saved scan',
                'php artisan hack:report --id=ULID' => 'Specific scan by ID',
                'php artisan hack:report --output=report.html' => 'Custom output path',
            ],
            'Requires --save flag on a prior hack:scan run',
        );

        $this->line('  <fg=white;options=bold>CONFIGURATION</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');

        $this->table(
            ['<options=bold>Environment Variable</>', '<options=bold>Purpose</>'],
            [
                ['HACK_AUDITOR_AI_PROVIDER', 'AI provider override (e.g. openai, anthropic)'],
                ['HACK_AUDITOR_AI_MODEL', 'AI model override (e.g. gpt-4o, claude-sonnet)'],
                ['HACK_AUDITOR_TOKEN_LIMIT', 'Max token budget per scan (0 = unlimited)'],
                ['HACK_AUDITOR_COST_INPUT', 'Cost per 1M input tokens (USD)'],
                ['HACK_AUDITOR_COST_OUTPUT', 'Cost per 1M output tokens (USD)'],
                ['OPENAI_API_KEY', 'OpenAI provider key (via laravel/ai)'],
                ['ANTHROPIC_API_KEY', 'Anthropic provider key (via laravel/ai)'],
                ['GEMINI_API_KEY', 'Gemini provider key (via laravel/ai)'],
            ],
        );

        $this->line('');
        $this->line('  <fg=white;options=bold>PROGRAMMATIC API</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');
        $this->line('  <fg=cyan>use Mahdi\HackAuditor\HackAuditorManager;</>');
        $this->line('');
        $this->line('  <fg=cyan>$manager = app(HackAuditorManager::class);</>');
        $this->line('  <fg=cyan>$report  = $manager->scan();</>');
        $this->line('  <fg=cyan>$report  = $manager->scan(\'app/Http/Controllers\');</>');
        $this->line('  <fg=cyan>$report  = $manager->scanCode($phpCode);</>');
        $this->line('  <fg=cyan>$ctf     = $manager->generateCTF(\'sql_injection\');</>');
        $this->line('  <fg=cyan>$html    = $manager->generateReport($report);</>');
        $this->line('  <fg=cyan>$score   = $manager->score(); // null when coverage was incomplete</>');
        $this->line('');

        $this->showCurrentSetup();

        $this->line('');
        $this->line('  <fg=gray>'.str_repeat('━', 50).'</>');
        $this->line('  Run <fg=cyan>php artisan hack:help <command></> for detailed help.');
        $this->line('  Available: <fg=cyan>demo</>, <fg=cyan>scan</>, <fg=cyan>ctf</>, <fg=cyan>report</>, <fg=cyan>usage</>');
        $this->line('');
    }

    /**
     * Display detailed help for the hack:demo command.
     */
    private function showDemoHelp(): int
    {
        $this->line('');
        $this->line('  <fg=white;options=bold>hack:demo</> — Zero-config demo scan');
        $this->line('  <fg=gray>'.str_repeat('━', 50).'</>');
        $this->line('');
        $this->line('  <fg=white;options=bold>SYNOPSIS</>');
        $this->line('  <fg=cyan>php artisan hack:demo [--quick]</>');
        $this->line('');
        $this->line('  <fg=white;options=bold>DESCRIPTION</>');
        $this->line('  <fg=gray>Creates a temporary InsecureController.php with 12</>');
        $this->line('  <fg=gray>intentional vulnerabilities, runs a hardcoded scan</>');
        $this->line('  <fg=gray>(no AI API call), displays dramatic results, then</>');
        $this->line('  <fg=gray>deletes the temp file. No API key required.</>');
        $this->line('');

        $this->line('  <fg=white;options=bold>FLAGS</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');

        $flags = $this->getCommandFlags('hack:demo');

        if ($flags !== []) {
            $this->table(
                ['<options=bold>Flag</>', '<options=bold>Description</>'],
                array_map(fn (array $f): array => [$f['name'], $f['description']], $flags),
            );
        } else {
            $this->line('  <fg=cyan>--quick</>    Skip animations');
        }

        $this->line('');
        $this->line('  <fg=white;options=bold>EXAMPLES</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:demo</>');
        $this->line('  <fg=gray>  Full animated demo with dramatic output</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:demo --quick</>');
        $this->line('  <fg=gray>  Skip animations for CI or screenshots</>');
        $this->line('');

        $this->line('  <fg=white;options=bold>WHAT IT DOES</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('  <fg=gray>1. Creates temp file in storage/hack-auditor/demo/</>');
        $this->line('  <fg=gray>2. Displays animated scanning steps</>');
        $this->line('  <fg=gray>3. Shows hardcoded results: score 8/100, 12 vulns</>');
        $this->line('  <fg=gray>4. Copies share text to clipboard</>');
        $this->line('  <fg=gray>5. Deletes temp file on exit</>');
        $this->line('');

        return self::SUCCESS;
    }

    /**
     * Display detailed help for the hack:scan command.
     */
    private function showScanHelp(): int
    {
        $this->line('');
        $this->line('  <fg=white;options=bold>hack:scan</> — AI-powered security scanner');
        $this->line('  <fg=gray>'.str_repeat('━', 50).'</>');
        $this->line('');
        $this->line('  <fg=white;options=bold>SYNOPSIS</>');
        $this->line('  <fg=cyan>php artisan hack:scan [options]</>');
        $this->line('');
        $this->line('  <fg=white;options=bold>DESCRIPTION</>');
        $this->line('  <fg=gray>Scans your Laravel application source code for</>');
        $this->line('  <fg=gray>security vulnerabilities using an AI provider.</>');
        $this->line('  <fg=gray>Files are chunked to fit within token limits and</>');
        $this->line('  <fg=gray>analyzed with context-aware prompts.</>');
        $this->line('');

        $this->line('  <fg=white;options=bold>FLAGS</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');

        $flags = $this->getCommandFlags('hack:scan');

        if ($flags !== []) {
            $rows = array_map(fn (array $f): array => [
                $f['name'],
                $f['description'],
                $f['default'] !== null && $f['default'] !== false
                    ? (string) $f['default']
                    : '',
            ], $flags);

            $this->table(
                ['<options=bold>Flag</>', '<options=bold>Description</>', '<options=bold>Default</>'],
                $rows,
            );
        }

        $this->line('');
        $this->line('  <fg=white;options=bold>BASIC USAGE</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan</>');
        $this->line('  <fg=gray>  Scan all configured paths</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --path=app/Http/Controllers</>');
        $this->line('  <fg=gray>  Scan a specific directory</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --path=app/Http/Controllers/AuthController.php</>');
        $this->line('  <fg=gray>  Scan a single file</>');
        $this->line('');

        $this->line('  <fg=white;options=bold>OUTPUT FORMATS</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --json</>');
        $this->line('  <fg=gray>  Machine-readable JSON output</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --html</>');
        $this->line('  <fg=gray>  Generate HTML report alongside console output</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --detailed</>');
        $this->line('  <fg=gray>  Show full descriptions (no truncation)</>');
        $this->line('');

        $this->line('  <fg=white;options=bold>FILTERING</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --severity=High</>');
        $this->line('  <fg=gray>  Only show High and Critical findings</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --fix</>');
        $this->line('  <fg=gray>  Include AI-generated fix suggestions</>');
        $this->line('');

        $this->line('  <fg=white;options=bold>BUDGET CONTROL</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --limit=50000</>');
        $this->line('  <fg=gray>  Stop after 50k tokens (skips remaining files)</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --force</>');
        $this->line('  <fg=gray>  Skip confirmation prompt for large codebases</>');
        $this->line('');

        $this->line('  <fg=white;options=bold>VERIFICATION (v1.6)</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --verify</>');
        $this->line('  <fg=gray>  Run a second AI pass on each HIGH/CRITICAL finding that</>');
        $this->line('  <fg=gray>  tries to construct a concrete exploit. Findings the model</>');
        $this->line('  <fg=gray>  cannot exploit are downgraded one tier (Critical→High,</>');
        $this->line('  <fg=gray>  High→Medium) with the original severity preserved for</>');
        $this->line('  <fg=gray>  audit. Low/Medium findings are not re-verified.</>');
        $this->line('');
        $this->line('  <fg=gray>  Cost: roughly doubles API spend on HIGH+ findings.</>');
        $this->line('  <fg=gray>  Enable by default via HACK_AUDITOR_VERIFY=true.</>');
        $this->line('');

        $this->line('  <fg=white;options=bold>CI/CD & AUTOMATION</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --json --force</>');
        $this->line('  <fg=gray>  Non-interactive JSON for CI pipelines</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --save</>');
        $this->line('  <fg=gray>  Save results to storage/hack-auditor/scans/</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --json --force 2>/dev/null | jq .overall_score</>');
        $this->line('  <fg=gray>  Extract just the score for CI gating (null when coverage was incomplete)</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --json --force 2>/dev/null | jq .coverage</>');
        $this->line('  <fg=gray>  Check which files were analyzed before trusting the score</>');
        $this->line('');

        $this->line('  <fg=white;options=bold>DIFF & BASELINE</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --diff</>');
        $this->line('  <fg=gray>  Only scan files changed vs main branch</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --diff --base=develop</>');
        $this->line('  <fg=gray>  Diff against a custom base branch</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --update-baseline</>');
        $this->line('  <fg=gray>  Save current findings as baseline</>');
        $this->line('');

        $this->line('  <fg=white;options=bold>POWER COMBOS</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --diff --severity=High --fix</>');
        $this->line('  <fg=gray>  Review only critical changes with fix suggestions</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --save --html</>');
        $this->line('  <fg=gray>  Save to JSON file and generate HTML report</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:scan --limit=100000 --json --force</>');
        $this->line('  <fg=gray>  Budget-capped CI scan with JSON output</>');
        $this->line('');

        $this->line('  <fg=white;options=bold>EXIT CODES</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');
        $this->line('  <fg=green>0</>  No critical vulnerabilities found');
        $this->line('  <fg=red>1</>  One or more critical vulnerabilities detected');
        $this->line('');

        $this->line('  <fg=white;options=bold>RELATED CONFIG</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');
        $this->line('  <fg=gray>config/hack-auditor.php:</>');
        $this->line('  <fg=cyan>scan.paths</>              Directories to scan');
        $this->line('  <fg=cyan>scan.exclude</>            Glob patterns to skip');
        $this->line('  <fg=cyan>scan.chunk_size</>         Files per AI request');
        $this->line('  <fg=cyan>scan.confirm_above_files</>  Prompt threshold');
        $this->line('  <fg=cyan>scan.baseline_path</>      Baseline JSON location');
        $this->line('  <fg=cyan>context.enabled</>         Context-aware scanning');
        $this->line('  <fg=cyan>usage.default_limit</>     Default token budget');
        $this->line('');

        return self::SUCCESS;
    }

    /**
     * Display detailed help for the hack:ctf command.
     */
    private function showCtfHelp(): int
    {
        $this->line('');
        $this->line('  <fg=white;options=bold>hack:ctf</> — CTF challenge generator');
        $this->line('  <fg=gray>'.str_repeat('━', 50).'</>');
        $this->line('');
        $this->line('  <fg=white;options=bold>SYNOPSIS</>');
        $this->line('  <fg=cyan>php artisan hack:ctf [vulnerability] [options]</>');
        $this->line('');
        $this->line('  <fg=white;options=bold>DESCRIPTION</>');
        $this->line('  <fg=gray>Generates Capture-The-Flag security challenges using</>');
        $this->line('  <fg=gray>AI. Challenges can be based on a specific vulnerability</>');
        $this->line('  <fg=gray>type or generated from real scan findings.</>');
        $this->line('');

        $this->line('  <fg=white;options=bold>FLAGS</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');

        $flags = $this->getCommandFlags('hack:ctf');

        if ($flags !== []) {
            $this->table(
                ['<options=bold>Flag</>', '<options=bold>Description</>'],
                array_map(fn (array $f): array => [$f['name'], $f['description']], $flags),
            );
        }

        $this->line('');
        $this->line('  <fg=white;options=bold>VULNERABILITY TYPES</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');

        foreach (VulnerabilityType::cases() as $type) {
            $this->line(sprintf(
                '  <fg=cyan>$ php artisan hack:ctf %-28s</> <fg=gray>%s</>',
                $type->value,
                $type->label(),
            ));
        }

        $this->line('');
        $this->line('  <fg=white;options=bold>EXAMPLES</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:ctf</>');
        $this->line('  <fg=gray>  Interactive menu to pick a vulnerability type</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:ctf sql_injection</>');
        $this->line('  <fg=gray>  Generate SQL Injection CTF challenge</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:ctf --from-scan</>');
        $this->line('  <fg=gray>  Pick from latest scan findings</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:ctf --from-scan --all</>');
        $this->line('  <fg=gray>  Generate CTF for every finding in latest scan</>');
        $this->line('');

        $this->line('  <fg=white;options=bold>OUTPUT DIRECTORY</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');

        /** @var string $ctfPath */
        $ctfPath = config('hack-auditor.ctf.output_path', 'hack-auditor/ctf');

        $this->line("  <fg=gray>Challenges are saved to:</> <fg=cyan>{$ctfPath}/</>  ");
        $this->line('  <fg=gray>Configure via:</> <fg=cyan>config/hack-auditor.php -> ctf.output_path</>');
        $this->line('');

        return self::SUCCESS;
    }

    /**
     * Display detailed help for the hack:report command.
     */
    private function showReportHelp(): int
    {
        $this->line('');
        $this->line('  <fg=white;options=bold>hack:report</> — HTML report generator');
        $this->line('  <fg=gray>'.str_repeat('━', 50).'</>');
        $this->line('');
        $this->line('  <fg=white;options=bold>SYNOPSIS</>');
        $this->line('  <fg=cyan>php artisan hack:report [options]</>');
        $this->line('');
        $this->line('  <fg=white;options=bold>DESCRIPTION</>');
        $this->line('  <fg=gray>Generates a self-contained HTML security report from</>');
        $this->line('  <fg=gray>previously saved scan results. Requires at least one</>');
        $this->line('  <fg=gray>prior scan with --save flag.</>');
        $this->line('');

        $this->line('  <fg=white;options=bold>FLAGS</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');

        $flags = $this->getCommandFlags('hack:report');

        if ($flags !== []) {
            $this->table(
                ['<options=bold>Flag</>', '<options=bold>Description</>'],
                array_map(fn (array $f): array => [$f['name'], $f['description']], $flags),
            );
        }

        $this->line('');
        $this->line('  <fg=white;options=bold>EXAMPLES</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:report --latest</>');
        $this->line('  <fg=gray>  Generate report from most recent saved scan</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:report --id=01HXYZ...</>');
        $this->line('  <fg=gray>  Generate report from a specific scan ID</>');
        $this->line('');
        $this->line('  <fg=cyan>$ php artisan hack:report --output=public/security-report.html</>');
        $this->line('  <fg=gray>  Save report to a custom path</>');
        $this->line('');

        /** @var string $reportPath */
        $reportPath = config('hack-auditor.report.output_path', 'hack-auditor/reports');

        $this->line('  <fg=white;options=bold>OUTPUT DIRECTORY</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');
        $this->line("  <fg=gray>Default path:</> <fg=cyan>storage/{$reportPath}/</>  ");
        $this->line('  <fg=gray>Configure via:</> <fg=cyan>config/hack-auditor.php -> report.output_path</>');
        $this->line('');
        $this->line('  <fg=white;options=bold>PREREQUISITE</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line('');
        $this->line('  <fg=gray>Run a scan with --save first:</>');
        $this->line('  <fg=cyan>$ php artisan hack:scan --save</>');
        $this->line('');

        return self::SUCCESS;
    }

    /**
     * Show an error for an unrecognized command argument.
     */
    private function showUnknownCommand(string $command): int
    {
        $this->components->error("Unknown command: {$command}");
        $this->line('');
        $this->line('  Available commands: <fg=cyan>demo</>, <fg=cyan>scan</>, <fg=cyan>ctf</>, <fg=cyan>report</>, <fg=cyan>usage</>');
        $this->line('');
        $this->line('  <fg=gray>Usage:</> <fg=cyan>php artisan hack:help scan</>');
        $this->line('');

        return self::FAILURE;
    }

    /**
     * Display the styled banner box.
     */
    private function displayBanner(): void
    {
        $this->line('');
        $this->line('  <fg=cyan;options=bold>'.str_repeat('═', 60).'</>');
        $this->line('  <fg=cyan;options=bold>         Laravel Hack Auditor — Commands                </>');
        $this->line('  <fg=cyan;options=bold>'.str_repeat('═', 60).'</>');
    }

    /**
     * Display a command section with description and examples.
     *
     * @param  array<string, string>  $examples
     */
    private function showCommandSection(
        string $commandName,
        string $description,
        array $examples,
        ?string $note = null,
    ): void {
        $this->line('  <fg=white;options=bold>'.strtoupper($commandName).'</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');
        $this->line("  <fg=gray>{$description}</>");
        $this->line('');

        foreach ($examples as $example => $desc) {
            $this->line("  <fg=cyan>{$example}</>");
            $this->line("  <fg=gray>  {$desc}</>");
        }

        if ($note !== null) {
            $this->line('');
            $this->line("  <fg=yellow>Note:</> <fg=gray>{$note}</>");
        }

        $this->line('');
    }

    /**
     * Display the current configuration and detected provider setup.
     */
    private function showCurrentSetup(): void
    {
        $this->line('');
        $this->line('  <fg=white;options=bold>CURRENT SETUP</>');
        $this->line('  <fg=gray>'.str_repeat('─', 50).'</>');

        $provider = config('hack-auditor.ai.provider') ?? $this->detectProvider();
        $this->components->twoColumnDetail(
            '  <fg=gray>AI Provider</>',
            $provider ? "<fg=green>{$provider}</>" : '<fg=red>None — set API key in .env</>',
        );

        $model = config('hack-auditor.ai.model') ?? 'default';
        $this->components->twoColumnDetail('  <fg=gray>AI Model</>', $model);

        $limit = (int) config('hack-auditor.usage.default_limit', 0);
        $this->components->twoColumnDetail(
            '  <fg=gray>Token Limit</>',
            $limit > 0 ? number_format($limit) : 'Unlimited',
        );

        $context = config('hack-auditor.context.enabled', true);
        $this->components->twoColumnDetail(
            '  <fg=gray>Context-Aware</>',
            $context ? '<fg=green>Enabled</>' : '<fg=yellow>Disabled</>',
        );

        $history = new ScanHistory;
        $scanCount = $history->count();
        $this->components->twoColumnDetail(
            '  <fg=gray>Saved Scans</>',
            $scanCount > 0 ? "<fg=green>{$scanCount} scans</>" : '<fg=gray>None</>',
        );
    }

    /**
     * Detect the AI provider from environment variables.
     */
    private function detectProvider(): ?string
    {
        if (env('ANTHROPIC_API_KEY')) {
            return 'Anthropic';
        }
        if (env('OPENAI_API_KEY')) {
            return 'OpenAI';
        }
        if (env('GEMINI_API_KEY')) {
            return 'Gemini';
        }

        return null;
    }

    /**
     * Dynamically read flags from a registered command's definition.
     *
     * @return array<int, array{name: string, description: string, default: mixed}>
     */
    private function getCommandFlags(string $commandName): array
    {
        try {
            $command = $this->getApplication()->find($commandName);
            $definition = $command->getDefinition();
            $flags = [];

            foreach ($definition->getOptions() as $option) {
                if (in_array($option->getName(), ['help', 'quiet', 'verbose', 'version', 'ansi', 'no-ansi', 'no-interaction', 'env'], true)) {
                    continue;
                }

                $flags[] = [
                    'name' => '--'.$option->getName().($option->acceptValue() ? '=<'.$option->getName().'>' : ''),
                    'description' => $option->getDescription() ?: 'No description',
                    'default' => $option->getDefault(),
                ];
            }

            return $flags;
        } catch (\Throwable) {
            return [];
        }
    }
}
