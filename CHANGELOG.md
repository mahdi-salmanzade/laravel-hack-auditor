# Changelog

All notable changes to `laravel-hack-auditor` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.0] - 2026-06-01

This cycle adds four strategic differentiators — a deterministic Laravel access-control engine, an MCP server, a provable-accuracy benchmark, and a zero-egress privacy layer — plus a refreshed model registry and a fix for a silent determinism bug.

### Measured Impact

- **Measured accuracy on the labeled corpus: F1 ≈ 0.94** (precision ≈ 0.89, recall 1.00, 0 false negatives) via `hack:benchmark` — up from F1 0.71 before the SSRF/sensitive-data detectors and the dedup fix. A real, reproducible number, not a marketing claim.
- **Test suite: 341 → 648 tests** (891 → 1583 assertions), all green. +307 tests across the new engines, the benchmark scorer, the MCP tools, and adversarially-found regression cases.
- **Determinism restored** — `config('hack-auditor.ai.temperature')` and `ai.max_tokens` were silently dropped (laravel/ai resolves them only from class attributes via reflection, and the anonymous agent carried none), so every scan ran at provider default. They are now transmitted on every call — a precondition for the benchmark's reproducibility claim.
- **Pricing registry refreshed to June 2026** — `claude-opus-4-8` (released 2026-05-28, $5/$25 per MTok) is now the Anthropic flagship returned by `recommendedForScanning()`, replacing the March-2026 `claude-opus-4-6` default.

### Added

- **Deterministic detection engine** (`src/Scanner/AccessControl/`) — framework-aware detectors that run alongside the AI pass and merge (with synonym-aware dedupe) into the report, giving reproducible coverage that doesn't depend on AI run-to-run variance: `SensitiveFillableDetector` (privilege/identity fields in `$fillable`), `UnauthorizedModelFetchDetector` (request- **and** route-param-sourced `find()`/`findOrFail()` exposed without an authorization or ownership guard), `PolicyRouteMismatchDetector` (a Policy exists for the model but is never applied), `SsrfDetector` (outbound `Http::`/`file_get_contents`/cURL calls with a user-controlled URL), and `SensitiveDataExposureDetector` (password/token/secret model fields returned in a response/JSON payload). Tuned for low false positives — benign columns (`status`/`type`/`level`/`tier`) are not flagged without a corroborating privilege signal, `$guarded = ['*']` models are skipped, and SSRF/exposure detectors require a user-controlled source or output context respectively.
- **MCP server** (`src/Mcp/`, `routes/ai.php`) — exposes the scanner to AI coding agents (Claude Code, Cursor) via `php artisan mcp:start hack-auditor` with three tools: `scan_path`, `scan_diff`, `explain_finding`. Adds `laravel/mcp` as a dependency.
- **`hack:benchmark` command + `src/Benchmark/`** — runs the scanner against a labeled in-repo corpus and reports precision / recall / F1 (overall + per-type), with `--min-f1` for CI gating and `--json` output. A self-contained, citable accuracy measurement and a regression gate for detection changes.
- **Zero-egress privacy layer** — `SecretRedactor` strips secrets (AWS keys, bearer tokens, DSNs, PEM blocks, secret-keyword assignments incl. quoted/concatenated values) from code before it leaves the machine, replacing them with detection-preserving markers; gated by `privacy.redact_secrets` (default on). Documented fully-local scanning via `HACK_AUDITOR_AI_PROVIDER=ollama`.
- **CWE ids on every `VulnerabilityType`** (`cweId()`) plus new types: `Ssrf`, `CommandInjection`, `DynamicColumnInjection`, `DebugModeExposure`, `CorsMisconfiguration`, `InsecureCookieConfig`, `UnverifiedWebhook`, `DependencyVulnerability`, each wired through `label()`/`description()`/`owaspCategory()`/`fromString()`.
- **New flagship model entries** in `AiProviders`: `claude-opus-4-8` (+ dated alias) and `claude-opus-4-7` ($5/$25, 1M ctx); best-effort lineup bumps for OpenAI `gpt-5.5`, Gemini `gemini-3.5-flash`, xAI `grok-4.3`. A tokenizer note flags that Opus 4.7+ can consume ~35% more tokens.

### Security

- **Path-traversal / arbitrary-file-read fixed** in `HackScanner::scanFile()` — it resolved caller-supplied paths against `base_path()` and read them directly, bypassing the `scan.sensitive_patterns` guard. Reachable via the MCP `scan_path` tool, this allowed reading `.env`, `*.key`, `/etc/passwd`, or `../`-escapes and shipping them to the cloud AI. Now: `realpath`-confined to the app root, sensitive-pattern excluded, with defense-in-depth rejection of absolute/traversal paths in the MCP tool.
- **Secret-redaction leaks closed** — values containing embedded quotes, string-concatenation chains, and short high-signal secrets (e.g. `password`) previously slipped past redaction; now redacted to the marker while ordinary code is left untouched.

### Changed

- **Hardened `ResponseParser::isSubstantiveExploit()`** — rejects bare URLs, lone tag placeholders, and refusal tokens; min substantive length 3 → 5. Real payloads still pass.
- **Prompt guidance** to stop the model mislabeling an outbound HTTP fetch as `open_redirect`/`command_injection` (it's SSRF), and to assign a single primary type per location instead of double-labeling an IDOR as `sensitive_data_exposure`.

### Fixed

- **Duplicate-finding dedupe** now collapses the same vulnerability reported at nearby lines by different sources (e.g. the AI at the vulnerable statement, the deterministic detector at the method signature). The previous `floor(line/3)` bucket put adjacent lines on opposite sides of a boundary so duplicates survived; matching is now by line proximity and path-format-tolerant basename, applied across the whole AI-plus-deterministic list even when no deterministic finding fires. This raised benchmark precision from ≈0.73 to ≈0.89.

### Tests

- New suites for the access-control detectors (FP/FN cases, synonym dedupe), `SecretRedactor` (adversarial leak cases + false-positive guards), `BenchmarkRunner`/`GroundTruth` (scoring math, line tolerance, relative-path keying), the MCP tools (metadata, schemas, faked-scanner invocation, path-traversal refusal), `ScannerAgent` (temperature/max-tokens transmitted), and `VulnerabilityType` (CWE/OWASP/alias coverage). Plus the prior registry, exploit-guard, and HTML-escaping additions.

## [1.6.0] - 2026-04-18

### Added

- **Multi-pass exploit verification** — New `--verify` flag on `hack:scan` runs a second AI pass on each HIGH/CRITICAL finding, asking the model to construct a concrete, working exploit. Findings with a verified exploit retain their severity and gain an `exploit_proof` field. Findings where the model cannot produce a working exploit are downgraded one tier (Critical→High, High→Medium) with `original_severity` preserved for audit trail. Opt-in by default — enable via `--verify` or `HACK_AUDITOR_VERIFY=true`.
- `Vulnerability` DTO fields: `exploit_verified` (bool|null), `exploit_proof` (string|null), `original_severity` (string|null).
- `VulnerabilityReport` DTO fields: `verification_attempted`, `verified_count`, `downgraded_count`, `verification_input_tokens`, `verification_output_tokens`, emitted as a `verification` sub-object in JSON output.
- `UsageTracker` now tracks verification tokens in a separate bucket (`recordVerification()`, `getVerificationPromptTokens()`, `getVerificationCompletionTokens()`, `getVerificationRequests()`). `estimateCost()` sums both buckets.
- `VerificationEngine` class — new second-pass AI coordinator. Skips <High findings, absorbs AI/parse failures as no-ops (never downgrades on technical failure).
- `PromptBuilder::verificationSystemPrompt()` + `PromptBuilder::buildVerificationPrompt(Vulnerability, string)` — pen-tester-style prompt rejecting theoretical or placeholder exploits.
- `ResponseParser::parseVerification(string)` — same 3-tier JSON extraction as the main parser, with a placeholder guard that normalizes empty/`N/A`/`<payload>` responses to `verified=false`.
- HTML report: inline "✓ Verified" (green) and "▽ Downgraded from X" (gray) badges on finding cards; verified exploit payload rendered in an HTML-escaped `<pre><code>` block.
- `hack:help scan` documents the `--verify` flag, cost trade-off, and downgrade behavior.
- 22 new tests (341 total, 891 assertions, 1.45s): 13 unit tests covering `VerificationEngine` skip/verify/downgrade/failure paths; 9 feature tests covering `--verify` CLI integration and JSON output contract.

### Measured Impact

- **vuln-lab** (curated, 8 known intentional vulns):
  - Baseline: 11 findings, 0 FP, score **3/100**.
  - Verified: 11 findings, **8 verified, 0 downgraded**, score **3/100**.
  - All 7 HIGH+ intentional vulns pass 1 detected were verified with concrete exploits.
- **Token cost on vuln-lab**: verification bucket = **1.33× pass-1 cost**. Total scan cost = **2.3× baseline** when `--verify` enabled. Cost scales with HIGH+ finding count, not file count.

### Known Limitations

- Pass-1 detection of command injection shows run-to-run variance on small surfaces. Verification can only annotate findings pass 1 produces — if pass 1 misses a vulnerability, `--verify` will not recover it. Not a regression from v1.5 logic (pass-1 code paths unchanged); tracked for future pass-1 prompt hardening.

## [1.2.0] - 2026-03-21

### Added

- **Runtime Introspection** — New `RuntimeIntrospector` class uses Laravel's `Router` and Eloquent APIs at runtime for authoritative route middleware, routed method detection, and model metadata (`$fillable`, `$hidden`, `$guarded`, `$casts`). Replaces fragile static file parsing with the actual resolved data
- **FormRequest Context Injection** — Scanner auto-resolves FormRequest type hints from controller methods, reads their source files, and injects them into the AI prompt so `authorize()` and `rules()` are visible before flagging IDOR or missing validation
- **Model Context Injection** — Eloquent model metadata injected into AI prompt as structured context. AI verifies mass assignment against actual `$fillable` and sensitive data exposure against actual `$hidden`
- **Routed Methods Detection** — AI prompt now lists which controller methods have registered routes. Unrouted methods (dead code) are automatically skipped, eliminating a category of false positives
- **Self-Contradiction Filter** — `ResponseParser` post-processes AI findings: if a description concludes the code is safe ("this is not a vulnerability", "already handled", etc.) the finding is automatically suppressed
- **HTML Report Exporter** — `--html` flag on `hack:scan` and new `hack:report` command generate self-contained dark-themed HTML security reports with animated score ring, collapsible vulnerability cards, and copy-to-clipboard code blocks
- **Route-Aware Middleware Analysis** — `RouteAnalyzer` extracts middleware from route files and injects context into AI prompts, reducing false positives for rate limiting and auth checks
- **Git Diff Scanning** — `--diff` flag scans only files changed in the current branch vs main/master, essential for CI pipelines
- **Scan Baseline** — `--update-baseline` saves current findings, `--no-baseline` ignores them. Suppresses known/accepted vulnerabilities like PHPStan's baseline
- **Scan History Comparison** — automatically shows score delta and new/resolved findings when history is enabled
- **Scan Transparency** — `hack:scan` output now shows analyzed paths and scan duration after completion
- **GIF-Ready Demo** — `hack:demo` rewritten with dramatic hacking animation (6 escalating steps), top-6 vulnerability table with "...and 6 more", auto-copy tweet, no interactive prompts
- **Narrower Banner** — "AUDITOR" ASCII art (52 chars) replaces "HACK AUDITOR" (89 chars) — fits standard 80-column terminals
- **Severity Calibration** — System prompt enforces strict severity definitions: Critical = RCE/full DB dump, High = data breach, Medium = exploitable with conditions, Low = code quality
- New `hack:report` command for generating HTML reports from saved scan history
- `VulnerabilityReport::compareWith()` for programmatic scan comparison
- `ai.timeout`, `scan.diff_base_branch`, `scan.baseline_path`, `report.output_path`, `share.ai_tweets` config options
- Demo GIF added to README (`art/demo.gif`)
- 39 new tests (165 total, 408 assertions)

### Changed

- `HackScanner` now prefers `RuntimeIntrospector` over `RouteAnalyzer` for route middleware and routed method resolution, falling back to static parsing when runtime introspection unavailable
- System prompt expanded with 8 new rules covering FormRequest authorization, model properties, mass assignment whitelists, sensitive data `$hidden`, self-check mandate, severity calibration, and defensive pattern recognition
- `hack:demo` rewritten for GIF virality: dramatic 6-step animation, compact top-6 table, auto-copy tweet, wider score box with "CRITICALLY INSECURE — FULL COMPROMISE"

### Fixed

- False positive: IDOR flagged when FormRequest `authorize()` already checks ownership
- False positive: "Missing Rate Limiting" flagged despite `throttle:*` middleware on route
- False positive: Vulnerabilities flagged on controller methods with no registered route (dead code)
- False positive: "Mass Assignment" flagged when controller uses `$request->only()` or explicit field enumeration
- False positive: "Sensitive Data Exposure" flagged for fields already in Model's `$hidden`
- False positive: AI emitting findings where its own description concludes code is safe
- CTF output path double-nesting (`storage/storage/...`) — config default changed from `storage/hack-auditor/ctf` to `hack-auditor/ctf`

## [1.1.0] - 2026-03-21

### Added

- Detailed findings section after scan table with full vulnerability descriptions
- `--detailed` flag for full untruncated descriptions in scan table
- Word-wrapped summary paragraphs with blank lines between AI chunk summaries
- Setup steps documentation in README

### Fixed

- CTFGenerator service provider binding (wrong parameter name + missing PromptBuilder)
- CTFGenerator exception method calls (`fromJson` → `malformed`, `fromMissingField` → `missingField`)
- CTFGenerator JSON extraction — code fence regex matching inner backtick blocks
- CTFGenerator JSON sanitization — character walker for unescaped control chars
- Added missing PromptBuilder methods for CTF generation
- AIAdapter `ask()` alias, removed `final` for mockability, increased timeout to 120s
- HackDemoCommand confirm prompt in non-interactive mode
- HackCTFCommand graceful handling when scan history table missing
- FileCollector sensitive path detection at root level
- 27 pre-existing test failures (base_path resolution, assertion mismatches)
- Wider command banners (74 chars), removed hardcoded version number

## [1.0.0] - 2026-03-20

### Added

- Initial release of Laravel Hack Auditor
- AI-powered security scanning of Laravel applications
- CTF (Capture The Flag) challenge generation from discovered vulnerabilities
- Support for multiple AI providers via `laravel/ai`
- Configurable scan paths and file exclusions
- Severity-based filtering for scan results
- Scan history tracking with configurable retention
- Social sharing support with customizable hashtags
- Artisan commands for running scans and generating CTF challenges
