<p align="center">
  <img src="art/banner.jpg" width="700" alt="Laravel Hack Auditor">
</p>

<h3 align="center">Watch AI hack your Laravel app in 15 seconds.</h3>

<p align="center">
  <a href="https://packagist.org/packages/mahdisphp/laravel-hack-auditor"><img src="https://img.shields.io/packagist/v/mahdisphp/laravel-hack-auditor" alt="Latest Version"></a>
  <a href="https://packagist.org/packages/mahdisphp/laravel-hack-auditor"><img src="https://img.shields.io/packagist/dt/mahdisphp/laravel-hack-auditor" alt="Total Downloads"></a>
  <a href="https://github.com/mahdi-salmanzade/laravel-hack-auditor"><img src="https://img.shields.io/github/stars/mahdi-salmanzade/laravel-hack-auditor" alt="Stars"></a>
</p>

Watch AI literally hack a vulnerable Laravel controller in front of your eyes — no setup, no API key.

<p align="center">
  <img src="art/demo.gif" width="600" alt="hack:demo in action">
</p>

```bash
composer require mahdisphp/laravel-hack-auditor
php artisan hack:demo
```

That's it. Two commands. Watch 12 vulnerabilities get ripped out of a controller in your terminal.

---

> We scanned a real production Laravel app (42 controllers). Score: **35/100**. Top finding: a test endpoint returning **real OTP codes** in JSON — full account takeover. [See the full report.](SCAN_RESULTS.md)

---

## Four commands. That's the whole package.

```bash
php artisan hack:demo                   # See it in action (no API key)
php artisan hack:scan                   # Scan YOUR app with AI
php artisan hack:scan --diff --html     # Scan only changed files, export HTML report
php artisan hack:ctf sql_injection      # Turn vulns into CTF challenges
php artisan hack:report --latest        # Generate HTML report from saved scan
```

**`hack:scan` finds what PHPStan and Snyk can't:**
- "This endpoint fetches a user by ID but never checks ownership" *(IDOR)*
- "Admin check reads `is_admin` from the request, not the session" *(Auth bypass)*
- "Login route has no throttle middleware" *(Brute-forceable)*
- "Room owner can add any user by ID without consent" *(Design-level access control)*

12 vulnerability types. OWASP Top 10 mapped. Every finding has file, line, explanation, and a copy-paste fix.

### Low false-positive rate

v1.2 reads your actual Laravel runtime — route middleware stacks, FormRequest `authorize()` methods, Eloquent `$fillable`/`$hidden` — and feeds it to the AI before analysis. Self-contradicting findings are auto-suppressed. Unrouted controller methods are skipped. The result: findings you actually need to fix, not noise.

## Quick setup (2 minutes)

```bash
php artisan install:ai                  # Install Laravel AI
```

Add one API key to `.env`:

```env
ANTHROPIC_API_KEY=sk-ant-your-key-here  # or OPENAI_API_KEY, or GEMINI_API_KEY
```

Scan:

```bash
php artisan hack:scan
```

Done. The package uses whatever provider you configured in Laravel AI. Optionally override just for this package:

```env
HACK_AUDITOR_AI_PROVIDER=anthropic
HACK_AUDITOR_AI_MODEL=claude-opus-4-6
```

<details>
<summary><strong>All scan flags</strong></summary>

| Flag | What it does |
|------|-------------|
| `--path=app/Http/Controllers` | Scan specific directory or file |
| `--severity=High` | Filter to High+ only |
| `--fix` | Include fix suggestions |
| `--json` | JSON output for CI/CD |
| `--html` | Generate HTML report |
| `--save` | Save to database |
| `--force` | Skip confirmation prompt |
| `--detailed` | Full descriptions in table |
| `--diff` | Only scan git-changed files (great for CI) |
| `--base=develop` | Base branch for `--diff` |
| `--update-baseline` | Save current findings as baseline |
| `--no-baseline` | Ignore baseline file |

</details>

## Generate CTF challenges from real vulns

Train your team by turning actual findings into Capture The Flag exercises:

```bash
php artisan hack:ctf sql_injection    # By type
php artisan hack:ctf --from-scan      # From latest scan results
php artisan hack:ctf --all            # Generate for every finding
```

Each challenge outputs a ready-to-run directory: README, vulnerable code, solution, flag file, and docker-compose.

## HTML reports, git-aware scanning, baselines

```bash
php artisan hack:scan --html            # Beautiful dark-themed HTML report
php artisan hack:scan --diff            # Only scan files changed in your branch
php artisan hack:scan --update-baseline # Accept current findings as known
php artisan hack:report --latest        # Regenerate report from saved scan
```

The HTML report is a single self-contained file — dark theme, animated score ring, collapsible cards, copy-paste code blocks. Professional enough to attach to a security audit.

`--diff` scans only what your PR touches. `--update-baseline` lets teams acknowledge known risks so CI doesn't fail on accepted findings.

## Use it in code

```php
use Mahdi\HackAuditor\Facades\HackAuditor;

$report = HackAuditor::scan();

if ($report->hasCritical()) {
    // Block deployment, alert Slack, panic, etc.
}

echo $report->overallScore;    // 0-100
echo $report->criticalCount(); // int
```

<details>
<summary><strong>CI/CD pipeline example</strong></summary>

```yaml
# .github/workflows/security.yml
name: Security Audit
on: [push, pull_request]
jobs:
  hack-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.3'
      - run: composer install --no-interaction
      - run: php artisan hack:scan --json --severity=High
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

</details>

<details>
<summary><strong>All configuration options</strong></summary>

```bash
php artisan vendor:publish --tag=hack-auditor-config
```

| Option | Default | Description |
|--------|---------|-------------|
| `ai.provider` | `null` | AI provider override |
| `ai.model` | `null` | Model override |
| `ai.temperature` | `0.3` | Lower = more deterministic |
| `ai.timeout` | `120` | HTTP timeout in seconds |
| `scan.paths` | Controllers, Models, Requests, Middleware, routes | What to scan |
| `scan.confirm_above_files` | `20` | Prompt before large scans |
| `scan.sensitive_patterns` | `.env*, *.key, *.pem, storage/logs/*` | Always excluded |
| `history.enabled` | `true` | Save results to database |
| `ctf.output_path` | `storage/hack-auditor/ctf` | CTF output directory |

Optional database history:

```bash
php artisan vendor:publish --tag=hack-auditor-migrations
php artisan migrate
```

</details>

## Security

This package sends source code to AI providers. Files matching `.env*`, `*.key`, `*.pem`, and `storage/logs/*` are always excluded. Review your provider's data retention policies.

Found a vulnerability in this package? Email **mahdi@mindzone.tech**.

## Contributing

PRs welcome. Run `composer test` and `vendor/bin/pint` before submitting.

## License

MIT — [LICENSE](LICENSE)

---

<p align="center">
  <strong>If this saved you from getting hacked, star the repo.</strong>
</p>
