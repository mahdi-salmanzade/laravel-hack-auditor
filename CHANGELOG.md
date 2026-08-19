# Changelog

All notable changes to `laravel-hack-auditor` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-08-19

The deterministic detection engine was rebuilt on a real AST after a run on a production 73-controller Laravel app returned **0 true positives and 5 false positives**, every one with a wrong line number, and one suggested fix that would have broken room creation. This release is the response to that report.

### Measured Impact

- **Real-world precision: 297 false positives → 0.** The engine was measured over **4,479 files** from six large open-source Laravel applications (Monica, Akaunting, Pixelfed, BookStack, Snipe-IT, Koel), none consulted while writing the detectors. Before: 298 findings, 297 false (**99.7% FP rate**). Now: **0 asserted vulnerabilities**, 28 review items — 3 once a route map is supplied, which is what a real scan has. `UnauthorizedModelFetchDetector` went 191 → 0, `SensitiveFillableDetector` 87 → 3 review, `SsrfDetector` 0 throughout.
- **Recall held.** `laravel-vuln-lab` still yields all 7 planted findings with identical composition, all `class: vulnerability, confidence: proven`. One line was corrected in the process: the IDOR was previously reported on line 99, a *comment line*, and is now on 100.
- **Four distinct species of app-breaking advice eliminated**, each found by an adversary after the previous one was fixed: (1) an ability the policy never declared; (2) a variable bound only inside a closure; (3) a variable bound only in a `try`/`match`/`foreach` — flow-control does not create scope in PHP, so scope-awareness alone was not enough; (4) **`$this->authorize()` itself being undefined** — since Laravel 11 the generated base controller carries no `AuthorizesRequests` trait, so the advice was a **500 on every request**, worse than the original incident. Runtime-proven on a booted app: the old advice threw `Call to undefined method`; the new `Gate::authorize()` reaches the policy and denies correctly.
- **`hack:scan` crashed on any application over ~600 PHP files.** The AST cache was unbounded, so a 750-file app exhausted PHP's default 128M `memory_limit` mid-scan — a FATAL that no `try`/`catch` can intercept, so the parser's graceful-degradation path never ran and the scan produced nothing. All six corpus apps died. Memory is now bounded by a measured byte budget and every app completes at the default limit.
- **Test suite: 663 → 1039 tests** (2,743 assertions), PHPStan level 8 clean.

### Added

- **`src/Scanner/Php/` — a real semantic layer** built on `nikic/php-parser` (now a direct dependency). Resolves receiver types, Laravel input trust, policy abilities, class ancestry and definite assignment. Every previous false positive in this package came from pattern-matching raw PHP source; no regex in the detection path survives.
- **Two finding classes.** `vulnerability` requires a complete evidence chain — source, sink, and the absence of a guard, all resolved from your code. Everything else is `review`: a question, excluded from the count, the score and the exit code. Confidence (`proven`/`probable`/`possible`) is tracked separately from severity, because *"how bad if real"* and *"how sure am I"* are different questions and collapsing them is what produced five confident HIGHs about correct code. Modelled on SonarQube's Vulnerability/Security Hotspot split.
- **A precision corpus** (`tests/Fixtures/precision/`) encoding the five real-world failures as permanent regression tests, plus a location invariant asserting every reported line really contains the construct described.

### Changed

- **A review finding can never carry a suggested fix** — the string is dropped in `Vulnerability`'s constructor, so a detector cannot reintroduce one by forgetting. A fix may only name identifiers proven to exist and be in scope: policy classes are quoted from the class actually resolved (never synthesised as `{Model}Policy`), variables must be **definitely assigned** on all paths, and the method being advised must be callable on that class.
- **Mass-assignment findings require a proven sink.** A privilege field in `$fillable` is not exploitable unless request data can reach it. Ownership keys (`user_id`, `company_id`, `tenant_id`) with no sink now emit nothing — the previous behaviour told Akaunting to remove `company_id` from 25 models, which would have disabled its global tenant scope and caused cross-tenant data exposure.
- **`hack:benchmark` refuses to print a score for samples it could not analyse**, and exits non-zero instead. The gate had silently stopped exercising the access-control detectors.
- **The `F1 ≈ 0.94` claim is retracted.** It was measured on a 10-sample corpus authored alongside the detectors — recall on friendly data, not precision. For scale, Checkmarx measures its own SAST at F1 0.64 on production code. Precision and recall are now published separately, with the corpus named.

### Fixed — scan accounting and honesty

- **A full scan recorded zero tokens and zero cost.** `HackScanner::scan()` attached the `UsageTracker` to the report inside `scanChunks()`, then handed that report to the deterministic access-control merge, which constructs a **new** `VulnerabilityReport` — dropping the tracker. Any scan where the deterministic layer produced or collapsed a finding therefore lost its entire spend record: `hack:usage` never saw it, the saved JSON had no `usage` field, and `--limit` could not budget against it. A real 73-file, 213-second run cost roughly $3–5 and was logged as nothing. Usage and coverage are now attached as the last step of every entry point, `inheritScanStateFrom()` carries them across every report rebuild (merge and verification), and the command logs from the tracker it owns rather than from the report, so a run that dies after paying still records what it spent.
- **Partial coverage was reported as a bare count.** A run printed "1 chunk(s) returned unparseable AI responses and were skipped" followed by a definitive score, with no way to learn which files went unexamined. Every skipped file is now named with its reason (`token_limit`, `ai_failure`) in the console, the JSON report, the HTML report and the MCP `scan_path` response.
- **`overall_score` rewarded scanning nothing.** The score is penalty-only — it starts at 100 and drops per finding — so an empty directory scored a flawless 100/100 while a real codebase scored 0/100. The score is now coverage-gated: it is withheld (console shows "not available", JSON/MCP emit `null` with `score_suppressed` and `score_suppression_reason`) whenever zero files were analysed or any discovered file went unscanned.
- **`--path=<directory>` silently scanned nothing.** The flag has always advertised "a specific file or directory", but a directory satisfied `file_exists()`, extracted to empty content, and produced a full-price AI request over an empty file plus a confident, evidence-free report. Directories now walk their contents through `FileCollector::collectFrom()` — same extension, size, exclusion, sensitive-file and binary filters as a full scan — and get the same chunking and coverage accounting. The same fix applies to the MCP `scan_path` tool, which advertises the same capability.

### Fixed — the accuracy gate measured less than it reported

- **`hack:benchmark` had stopped crediting the access-control corpus entirely, and said nothing.** The access-control engine now refuses to report a record exposure it cannot attribute to a routed entry point — the rule that took 191 false IDOR reports on 6,221 real files down to zero. The benchmark corpus, however, is a directory of standalone fixture files with no application around them: no route table, so every controller sample resolved to `unreachable` and was dropped *before analysis*. The planted IDOR at `tests/Fixtures/benchmark/samples/IdorController.php:14` — `Invoice::findOrFail($id)` returned straight to the caller, textbook ground truth — stopped being credited, and the gate went on printing a score for detectors it had stopped exercising. Not one test went red.
- The fix is not a relaxed detector. The corpus now **describes its own application**: `tests/Fixtures/benchmark/routes.php` names the controller action behind every sample, and the command builds a `Router` from that manifest and hands the scanner a `RuntimeIntrospector` backed by it. The host route table is never mutated or read. Reachability suppression is untouched — with the manifest removed, the corpus scores zero again, which `tests/Feature/BenchmarkCorpusTest.php` asserts explicitly so the credit can never be mistaken for a loosened rule.
- **An unmeasured sample can no longer pass for a clean one.** `hack:benchmark` now refuses to report a score at all — exit 1, offending actions named — when a corpus sample fails to parse or has no route entry. That silence was the whole defect; it is now the loudest failure the command has.
- **The output states its own scope.** Every result carries the caveat that these numbers come from a *synthetic* corpus authored alongside the detectors, making them a **recall check and regression gate, not a precision claim about real code**. Real-code precision is measured separately, on unmodified third-party applications. The README claim was updated to match.

### Added

- **`hack:benchmark --deterministic`** — scores only the reproducible, provider-independent engine, with **no AI key and no network**, so the deterministic half of the scanner is gateable on every commit. Ground-truth labels now carry an `engine` tag (`deterministic` / `ai`) naming which engine the gate holds responsible; the tag is a floor, not a ceiling. Measured: precision 1.00, recall 1.00, F1 1.00 over the 3 deterministic-owned labels (idor, ssrf, sensitive_data_exposure) — including `IdorController.php:14`, at the correct line.
- **`hack:benchmark --routes=`** — point the run at a custom corpus route manifest.
- **`src/Benchmark/CorpusRoutes.php`** and **`src/Benchmark/CorpusSamples.php`** — the corpus's route manifest and its analysability audit (unparsable files, unrouted controller actions). **`GroundTruth::onlyEngine()`** / **`labelsExcludedFrom()`** scope a run to one engine while keeping every sample file in the corpus, so false positives on out-of-scope samples are still penalised.
- **`testbench.yaml`** — lets `vendor/bin/testbench hack:benchmark --deterministic` run the gate straight from the package root.
- 13 regression tests in `tests/Feature/BenchmarkCorpusTest.php` that fail the moment a benchmark sample becomes unanalysable again.
- **`ScanCoverage`** (`src/Scanner/ScanCoverage.php`) — an immutable record of files discovered, files analysed, and every skipped file with its reason. Exposed on `VulnerabilityReport` via `setCoverage()` / `getCoverage()`, and alongside it `scoreIsMeaningful()` and `scoreSuppressionReason()`.
- **`FileCollector::collectFrom(string $directory)`** — filtered collection from one directory, backing `--path=<directory>`.
- `coverage`, `score_suppressed` and `score_suppression_reason` in `hack:scan --json`, `VulnerabilityReport::toArray()` and the MCP structured response; `files_scanned`, `coverage_complete` and `aborted` in the usage log.
- 20 regression tests in `tests/Feature/ScanAccountingTest.php`.

### Changed (breaking for JSON/API consumers)

- `overall_score` is now `null` — not `0`, not `100` — in `--json`, saved scans and MCP output whenever coverage is incomplete or empty. CI gates reading `jq .overall_score` must handle `null`.
- `HackAuditorManager::score()` returns `?int`; it is `null` when no scan is saved or the saved scan withheld its score. It previously returned `0`, which is indistinguishable from a catastrophic result.

## [2.0.1] - 2026-08-19

### Fixed

- **`SensitiveFillableDetector` silently detected nothing when a comment inside `$fillable` contained an apostrophe.** The field list was extracted with `preg_match_all("/['\"]([^'\"]+)['\"]/")` over the raw array body, so quotes were paired *across* comments: one apostrophe — `// lets a request reassign someone else's post` — desynchronised every quote after it and swallowed the remaining fields. `['user_id', 'is_admin']` parsed as `["s post", ", // privilege flag"]`, and the detector returned no findings at all. No error, no warning; one of the five deterministic detectors just stopped working. Apostrophes in comments (`don't`, `it's`, `user's`) are common enough that real models were affected, and escaped quotes inside a value had the same effect. Parsing is now tokenised via `token_get_all()`, which sees comments and escape sequences the way PHP does. Present since the detector shipped in 1.7.0. Found while building fixtures for it in `laravel-vuln-lab`, which is exactly the coverage gap the lab exists to close. Three regression tests added (663 tests total).
- `detectPricing()`'s last-resort fallback now names `claude-sonnet-5` instead of `claude-sonnet-4-6`, matching what `defaultModel('anthropic')` returns. Same rate either way ($3/$15), so no estimate changes — this only removes a disagreement between the two code paths.
- **CI**: added the `phpunit.xml` the package never had. Pest fell back to implicit config discovery, which works on macOS but on Linux resolved an empty `--configuration` path, so PHPUnit read the next CLI token as the config file (`Could not read XML from file "--cache-directory"`). The suite passed locally and failed on every CI leg.

## [2.0.0] - 2026-08-19

A dependency and model-registry refresh that fixes a shipped defect: since v1.7.0 the scanner has been unusable on Anthropic's current flagship models. Major only because the `laravel/ai` floor moves from `^0.3` to `^0.11`, which consuming apps must adopt. No scanner behaviour, output contract, or config key changes apart from the additive `cwe` field.

### Measured Impact

- **Fixed: scans against Claude Opus 4.7 and newer failed outright.** v1.7.0's determinism fix began transmitting `temperature` on every request, but Anthropic removed the sampling parameters from Opus 4.7 onward — Opus 4.7/4.8, Opus 5, Sonnet 5 and Fable 5 reject a request carrying `temperature` with HTTP 400. Any user who set `HACK_AUDITOR_AI_MODEL` to one of those models got a failed scan on every run. The parameter is now omitted for models that reject it, so all five work; the default (unpinned) path was unaffected and is unchanged.
- **4 of the 5 dated Anthropic model IDs in the registry did not exist.** Anthropic switched to dateless IDs at the 4.6 generation, so `claude-opus-4-8-20260528`, `claude-opus-4-6-20250414` and `claude-sonnet-4-6-20250414` were never real, and `claude-sonnet-4-5-20250514` carried the wrong date (`-20250929`). Each would 404 if selected. Removed or corrected, and pricing re-verified against Anthropic's published table on 2026-08-19.
- **Test suite: 648 → 660 tests** (1583 → 1605 assertions), green on **both** supported stacks — Laravel 12.67 / Pest 4.7.8 / PHPUnit 12.5.33 and Laravel 13.26.1 / Pest 5.1.1 / PHPUnit 13.3.0. Both legs were run before release, not inferred.
- **`ScannerAgent` lost 45 lines and its `eval()` call.** laravel/ai 0.6.4 added method-based generation options, retiring the runtime class-synthesis workaround that existed only because attribute arguments must be constant expressions. Removing `eval()` from a security-audit tool is worth the major bump on its own.
- **Static analysis is enforced again.** `phpstan.neon` had included a larastan extension that was never declared as a dependency, so the config had been inert; PHPStan level 8 now runs in CI over an 84-error baseline that blocks new findings.

### Added

- **`AiProviders::supportsSamplingParams()`** and an optional per-model `sampling` flag in the registry, recording whether a model accepts `temperature`/`top_p`/`top_k`. Unknown and unpinned models default to accepting them, so the deterministic low-temperature scan is preserved everywhere it still works.
- **Current Anthropic models**: `claude-opus-5` ($5/$25, 1M context — now the model `recommendedForScanning()` returns), `claude-sonnet-5` ($3/$15, 1M), `claude-fable-5` ($10/$50, 1M), plus `claude-opus-4-5` and its dated alias.
- **`cwe` on every finding in `toArray()`** — `VulnerabilityType::cweId()` existed since v1.7 but reached only the MCP formatter, so JSON consumers could not see it. This unblocks faithful SARIF output in the GitHub Action.
- **CI (`.github/workflows/tests.yml`)** — the package had none. Three test legs (PHP 8.3 + Laravel 12, PHP 8.4 + Laravel 13, PHP 8.5 + Laravel 13) plus a Pint and PHPStan job. The Laravel 12 leg exists because Pest 5 requires PHP 8.4 and cannot resolve against Laravel 12 at all (`symfony/process ^8.1` vs `^7.2`); without it the declared `php ^8.3` and `illuminate/* ^12.41.1` support would ship untested, since Composer validates the live interpreter rather than the declared floor.

### Changed

- **`laravel/ai` `^0.3|^1.0` → `^0.11|^1.0`** (breaking). Composer's caret pins the minor on 0.x, so `^0.3` could never resolve 0.11.0. The SDK surface we consume is unchanged — `prompt()`, `->text` and the usage accessors all kept their signatures.
- **`laravel/mcp` `^0.6` → `^0.6|^0.7.1|^0.8|^0.9`**, resolving 0.9.4. The one source-breaking change in that range (JSON-RPC primitives moving to a shared namespace in 0.7.1) touches classes this package does not reference. `^1.0` is deliberately excluded: it drops the initialize handshake and serves only MCP 2026-07-28, a genuine protocol break. Host apps also need `laravel/boost` ≥ 2.4.13 to actually receive 0.9.x — earlier versions cap it below 0.7.1.
- **Dev dependencies** widened to unions rather than pinned: `orchestra/testbench ^10.11|^11.2`, `pestphp/pest ^4.7|^5.1`, `laravel/pint ^1.30.5`. Testbench 11 is Laravel 13 only, so pinning it alone would have silently dropped Laravel 12 from the matrix.
- **`ScannerAgent` now takes `temperature` and `maxTokens` as constructor arguments** and exposes them as methods. It deliberately carries no `#[Temperature]` attribute: laravel/ai falls back to the attribute when the method returns `null`, so an attribute would silently reinstate the 400 on Opus 4.7+. A regression test asserts the null survives resolution.
- `claude-sonnet-4-5` and `claude-opus-4-5` context corrected to 200K (they are not 1M models).

### Fixed

- Removed two PHPStan options (`checkMissingIterableValueType`, `checkGenericClassInNonGenericObjectType`) that PHPStan 2.x rejects outright, which had made the config unloadable.

### Upgrading from 1.7

Run `composer update mahdisphp/laravel-hack-auditor -W`. Two things to check:

1. **`laravel/ai` must move to ^0.11.** If your app pins it lower, that pin has to move first.
2. **Ollama users:** laravel/ai renamed `OLLAMA_BASE_URL` to `OLLAMA_URL`. If you run the zero-egress local-model path against a non-default host, the old variable is now ignored **silently** and the client falls back to `http://localhost:11434`. No error is raised. Nothing in this package reads that variable — the rename is upstream — but your `.env` needs updating.

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
