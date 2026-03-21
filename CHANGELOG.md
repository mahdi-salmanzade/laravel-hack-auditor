# Changelog

All notable changes to `laravel-hack-auditor` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
