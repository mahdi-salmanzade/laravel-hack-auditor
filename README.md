<p align="center">
  <img src="art/banner.jpg" width="700" alt="Laravel Hack Auditor">
</p>

<p align="center">
  <strong>Watch AI hack your Laravel app in 15 seconds.</strong>
</p>

<p align="center">
  <a href="https://packagist.org/packages/mahdisphp/laravel-hack-auditor"><img src="https://img.shields.io/packagist/v/mahdisphp/laravel-hack-auditor.svg?style=flat-square" alt="Latest Version"></a>
  <a href="https://packagist.org/packages/mahdisphp/laravel-hack-auditor"><img src="https://img.shields.io/packagist/dt/mahdisphp/laravel-hack-auditor.svg?style=flat-square" alt="Total Downloads"></a>
  <a href="https://github.com/mahdi-salmanzade/laravel-hack-auditor"><img src="https://img.shields.io/github/stars/mahdi-salmanzade/laravel-hack-auditor?style=flat-square" alt="Stars"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square" alt="License"></a>
</p>

---

> AI-assisted contextual security analysis for Laravel. Catches the vulnerabilities that static analysis misses — IDOR, auth bypass, missing rate limits, business logic flaws — by understanding your code in context. Plus: generate CTF challenges from your actual codebase.

## Install (30 seconds)

```bash
composer require mahdisphp/laravel-hack-auditor
```

That's it. One command and you're ready to scan.

**Optional:** If you want to track scan history in your database:

```bash
php artisan vendor:publish --tag=hack-auditor-migrations
php artisan migrate
```

> Migrations are **not** auto-loaded by default. Set `history.enabled` to `true` in your config and publish the migrations to opt in. No surprise tables in your production database from a dev tool.

## Try It Right Now

```bash
php artisan hack:demo
```

No API key. No configuration. No setup. Just run it and watch AI tear apart a vulnerable controller in your terminal.

The demo ships with intentionally vulnerable code so you can see exactly what a real scan looks like before pointing it at your own app.

## Scan Your Actual App

```bash
php artisan hack:scan
```

Make sure [Laravel AI](https://laravel.com/docs/ai) is configured with your preferred provider (OpenAI, Anthropic, Gemini, etc.) before running a real scan.

### Options

| Flag | Description |
|------|-------------|
| `--path=app/Http/Controllers` | Scan a specific directory or file instead of the full app |
| `--severity=High` | Only report vulnerabilities at this severity or above |
| `--fix` | Include copy-paste fix suggestions for every finding |
| `--json` | Output raw JSON (perfect for CI/CD pipelines) |
| `--save` | Persist results to the database for historical tracking |
| `--force` | Skip confirmation prompt for large scans |

```bash
# Scan only your controllers
php artisan hack:scan --path=app/Http/Controllers

# High and Critical only, with fixes
php artisan hack:scan --severity=High --fix

# JSON output for your CI pipeline
php artisan hack:scan --json

# Save results and track your security score over time
php artisan hack:scan --save
```

## What It Detects

12 vulnerability types mapped to the OWASP Top 10 (2021):

| # | Vulnerability | Severity | OWASP Category |
|---|--------------|----------|----------------|
| 1 | SQL Injection | Critical | A03:2021 - Injection |
| 2 | Cross-Site Scripting (XSS) | High | A03:2021 - Injection |
| 3 | Cross-Site Request Forgery (CSRF) | Medium | A01:2021 - Broken Access Control |
| 4 | Mass Assignment | High | A04:2021 - Insecure Design |
| 5 | Insecure Direct Object Reference (IDOR) | High | A01:2021 - Broken Access Control |
| 6 | Missing Rate Limiting | Medium | A04:2021 - Insecure Design |
| 7 | Authentication Bypass | Critical | A07:2021 - Auth Failures |
| 8 | Insecure Deserialization | Critical | A08:2021 - Integrity Failures |
| 9 | Open Redirect | High | A01:2021 - Broken Access Control |
| 10 | Sensitive Data Exposure | Critical | A02:2021 - Cryptographic Failures |
| 11 | Weak Password Hashing | Critical | A02:2021 - Cryptographic Failures |
| 12 | Missing Input Validation | Medium | A03:2021 - Injection |

Every finding includes the exact file, line number, a plain-English explanation of the risk, and a suggested fix you can copy-paste directly into your code.

### How This Differs From Static Analysis

Tools like PHPStan security rules, Psalm, and Snyk are great at catching pattern-based vulnerabilities (SQL injection via string concatenation, XSS from unescaped output). **Use them.** They're deterministic and don't hallucinate.

Hack Auditor complements those tools by catching **contextual vulnerabilities** that require understanding business logic:

- **IDOR** — "This endpoint fetches a user by ID from the route but never checks ownership"
- **Auth bypass** — "This admin check reads `is_admin` from the request instead of the authenticated user"
- **Missing rate limiting** — "Login route has no throttle middleware"
- **Sensitive data exposure** — "Password field is logged in the auth controller"

AI can reason about these patterns in ways static analysis can't. But AI can also produce false positives. **Review every finding.** This is a development aid, not a replacement for your security pipeline.

## Generate CTF Challenges

Turn your app's real vulnerabilities into hands-on training for your team.

```bash
# Generate a SQL Injection challenge
php artisan hack:ctf SqlInjection

# Generate challenges from your latest scan results
php artisan hack:ctf --from-scan

# Generate a challenge for every finding
php artisan hack:ctf --all
```

Each challenge is a self-contained PHP file with:
- The vulnerable code (sanitized)
- A description of what's wrong
- Hints that progressively reveal the exploit
- A solution file your team can check against

Challenges are saved to `storage/hack-auditor/ctf` by default. Change this in your config.

## Configuration

Publish the config file and customize everything:

```bash
php artisan vendor:publish --tag=hack-auditor-config
```

### AI Provider

| Option | Default | Description |
|--------|---------|-------------|
| `ai.provider` | `null` | AI provider override (`openai`, `anthropic`, `gemini`, etc.). When `null`, uses your Laravel AI default. |
| `ai.model` | `null` | Model override. When `null`, uses your Laravel AI default. |
| `ai.temperature` | `0.3` | Lower = more deterministic analysis. Recommended: `0.1` - `0.5`. |
| `ai.max_tokens` | `4096` | Maximum tokens per AI response. Increase for very large codebases. |

### Scan Paths

| Option | Default | Description |
|--------|---------|-------------|
| `scan.paths` | `['app/Http/Controllers', 'app/Models', 'app/Http/Requests', 'app/Http/Middleware', 'routes']` | Directories to scan (relative to `base_path()`). |
| `scan.exclude` | `['*/vendor/*', '*/node_modules/*', '*/tests/*']` | Glob patterns to exclude from scanning. |
| `scan.file_extensions` | `['.php']` | File extensions to include. |
| `scan.max_file_size_kb` | `500` | Skip files larger than this (KB). |
| `scan.chunk_size` | `10` | Max files per AI request. Actual chunking is token-aware — large files get their own chunk. |
| `scan.confirm_above_files` | `20` | Prompt for confirmation when scanning more than this many files. Prevents surprise API bills. Use `--force` to skip. |
| `scan.sensitive_patterns` | `['.env*', '*.key', '*.pem', 'storage/logs/*']` | **Always excluded.** Safety net to prevent secrets from reaching AI providers. |

### Severity

| Option | Default | Description |
|--------|---------|-------------|
| `severity.minimum_report` | `Low` | Minimum severity to include in reports. Options: `Critical`, `High`, `Medium`, `Low`. |

### CTF

| Option | Default | Description |
|--------|---------|-------------|
| `ctf.output_path` | `storage/hack-auditor/ctf` | Where generated CTF challenge files are saved. |

### History

| Option | Default | Description |
|--------|---------|-------------|
| `history.enabled` | `true` | Persist scan results to the database. |
| `history.keep_days` | `30` | Auto-delete scan results older than this many days. |

### Sharing

| Option | Default | Description |
|--------|---------|-------------|
| `share.default_hashtags` | `['#LaravelSecurity', '#HackAuditor', '#CTF']` | Hashtags appended when sharing results. |

## Programmatic Usage

Use the `HackAuditor` facade anywhere in your application:

```php
use Mahdi\HackAuditor\Facades\HackAuditor;

// Scan your entire app
$report = HackAuditor::scan();

echo "Security Score: {$report->overallScore}/100";
echo "Total Vulnerabilities: {$report->totalCount()}";
echo "Critical Issues: {$report->criticalCount()}";

// Scan a specific file
$report = HackAuditor::scan('app/Http/Controllers/PaymentController.php');

// Scan a raw code string
$code = file_get_contents('app/Http/Controllers/AuthController.php');
$report = HackAuditor::scanCode($code);

// Check individual severity counts
$report->criticalCount();  // int
$report->highCount();       // int
$report->mediumCount();     // int
$report->lowCount();        // int

// Check for critical issues
if ($report->hasCritical()) {
    // Alert your team, block deployment, etc.
}

// Export as JSON (great for dashboards)
$json = $report->toJson();

// Export as array
$data = $report->toArray();

// Generate a CTF challenge
$path = HackAuditor::generateCTF('SqlInjection');

// Generate a CTF challenge based on real code
$path = HackAuditor::generateCTF('MassAssignment', $vulnerableCode);

// Get your latest security score
$score = HackAuditor::score(); // 0-100
```

### CI/CD Integration

Add this to your GitHub Actions, GitLab CI, or any pipeline:

```yaml
# .github/workflows/security.yml
name: Security Audit
on: [push, pull_request]
jobs:
  hack-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'
      - run: composer install --no-interaction
      - name: Run Security Scan
        run: php artisan hack:scan --json --severity=High
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

## Share Your Results

After every scan, the package generates a shareable summary:

```
My Laravel app scored 82/100 on security.
Found 3 vulnerabilities (0 Critical, 1 High, 2 Medium).
Scanned with Laravel Hack Auditor.
#LaravelSecurity #HackAuditor #CTF
```

Post it on X/Twitter, share it with your team, or use it in your security review meetings. The hashtags are configurable in your `hack-auditor.php` config.

## Real-World Scan Results

We ran Hack Auditor against a production Laravel backend (42 controllers, magic link auth, social auth, crews, leaderboards) using Anthropic Claude Opus 4.6:

| Score | Vulnerabilities | Critical | High | Medium | Low |
|-------|----------------|----------|------|--------|-----|
| **35/100** | 7 | 1 | 2 | 3 | 1 |

Top finding: a test endpoint (`/auth/test-otp`) that returns **real OTP codes** in the JSON response — full account takeover if accessible in production. This is the kind of contextual vulnerability that static analysis tools miss entirely.

See the full report: [SCAN_RESULTS.md](SCAN_RESULTS.md)

## Security Warning

**This package sends your application's source code to AI providers for analysis.**

- Never run scans on production servers with sensitive business logic.
- Review the `scan.sensitive_patterns` config to ensure secrets, keys, and certificates are excluded.
- Files matching `.env*`, `*.key`, `*.pem`, and `storage/logs/*` are excluded by default.
- Understand your AI provider's data retention policies before scanning proprietary code.

If you discover a security vulnerability in this package itself, please report it responsibly by emailing **mahdi@mindzone.tech** instead of opening a public issue.

## Contributing

Contributions are welcome and appreciated.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-detection`)
3. Write tests for your changes
4. Ensure all tests pass (`composer test`)
5. Run the formatter (`vendor/bin/pint`)
6. Commit your changes (`git commit -m 'Add amazing detection'`)
7. Push to the branch (`git push origin feature/amazing-detection`)
8. Open a Pull Request

Please make sure your PR includes tests and follows the existing code style.

## Credits

- **Mahdi Salmanzade**
- Built with [Laravel AI](https://laravel.com/docs/ai)
- Powered by the Laravel community

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=mahdi-salmanzade/laravel-hack-auditor&type=Date)](https://star-history.com/#mahdi-salmanzade/laravel-hack-auditor&Date)

## License

The MIT License (MIT). Please see [LICENSE](LICENSE) for more information.

---

<p align="center">
  <strong>If this package saved you from getting hacked, give it a star.</strong>
</p>
