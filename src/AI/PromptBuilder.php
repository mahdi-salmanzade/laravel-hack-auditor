<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\AI;

use Mahdi\HackAuditor\Scanner\AppContext;
use Mahdi\HackAuditor\Scanner\Vulnerability;

class PromptBuilder
{
    /** @var array<string, array<int, string>> */
    private array $routeContext = [];

    private ?AppContext $appContext = null;

    /** @var array<int, array{path: string, content: string}> */
    private array $formRequestContext = [];

    /** @var array<string, string> */
    private array $routedMethods = [];

    /** @var array<string, array{fillable: array<int, string>, hidden: array<int, string>, guarded: array<int, string>, casts: array<string, string>}> */
    private array $modelContext = [];

    /**
     * Build the system prompt for the AI security auditor.
     *
     * Returns the exact system prompt that instructs the AI on how to analyze
     * Laravel code for security vulnerabilities and respond with structured JSON.
     */
    public function systemPrompt(): string
    {
        return <<<'PROMPT'
You are a Laravel security auditor. You analyze PHP source code for security vulnerabilities.
You MUST respond with ONLY a JSON object — no prose, no markdown fences, no explanation.

CRITICAL RULES — READ BEFORE ANALYZING:

1. CONTEXT-FIRST ANALYSIS
   You will receive TWO sections: APPLICATION CONTEXT and CODE TO AUDIT.
   You MUST read and internalize the APPLICATION CONTEXT before analyzing the code.
   The context contains middleware, routes, policies, form requests, and model configurations
   that are defined OUTSIDE the file being audited but DIRECTLY AFFECT its security posture.

2. NEVER FLAG THESE AS VULNERABILITIES:
   - "Missing authentication" when the route has auth/auth:sanctum/auth:api middleware applied
   - "Missing authorization" when a Policy exists for the model and the controller uses $this->authorize(), Gate::allows(), policy(), can(), or the route has ->can()
   - "Missing validation" when the controller method type-hints a FormRequest class
   - "Missing CSRF" on routes in the 'api' middleware group (APIs use token auth, not CSRF)
   - "SQL injection" on Eloquent query builder calls using ? placeholders or parameter binding (e.g., ->where('id', $id), ->whereIn('id', $ids)) — Eloquent parameterizes these automatically
   - "SQL injection" on Eloquent methods: find(), findOrFail(), where() with column/value args, firstWhere(), pluck(), paginate(), etc.
   - "SQL injection" when values are cast to (int) before interpolation — PHP integer cast is mathematically safe
   - "SQL injection" when Carbon/DateTime objects are interpolated into SQL — they produce safe date strings
   - "SQL injection" when implode() is used with config() or hardcoded arrays — trace the source
   - "SQL injection" for LIKE/ilike wildcard injection (% and _ in search input) — Eloquent parameterizes the value, so % and _ are LIKE metacharacters only, NOT SQL injection. This is a LOW code-smell at most (user can broaden search results), never HIGH or SQL injection
   - "Mass assignment" when $fillable or $guarded is properly defined on the model
   - "Mass assignment" when the controller uses $request->validated(), $request->safe(), $request->safe()->only([...]), or $request->only([...]) — these limit input to explicit fields, preventing mass assignment regardless of model configuration
   - "IDOR" when route model binding is used with ->scopeBindings() or when a Policy checks ownership
   - "IDOR" when a global scope (e.g., tenant scope) automatically filters queries
   - "IDOR" when middleware overwrites request parameters with server-controlled values (e.g., $request->merge(['user_id' => $authenticatedId]) in middleware means the controller reads server-set values, NOT user input)
   - "IDOR" or "Missing authorization" when the controller uses $this->authorize(), $this->authorizeResource(), Gate::allows(), Gate::check(), Gate::authorize(), $this->can(), or policy() — these ARE authorization checks
   - "IDOR" or "Missing authorization" when Gate::define() or Gate::before() is registered for the relevant ability in a service provider (check APPLICATION CONTEXT)
   - "Missing encryption" for fields that use 'encrypted' cast in the model
   - "Data exposure" for fields listed in the model's $hidden array
   - "Sensitive data in logs" for logging that only includes non-sensitive contextual data
   - "Hardcoded credentials" for route names, config keys, or non-secret string constants
   - "No HTTPS enforcement" — this is a server/infrastructure concern
   - "Missing rate limiting" on general CRUD endpoints — ONLY flag on auth (login/register/password-reset), OTP/verification, and payment endpoints
   - Vulnerabilities in controller methods that have NO registered routes (dead code / unrouted methods). If the "Routed Methods" section is provided, ONLY analyze methods listed there — all other methods are unreachable and cannot be exploited.

3. LARAVEL SECURITY MODEL:
   - Middleware can be applied at: global level, middleware group level, route group level, individual route level, or controller constructor level. ALL are valid. Check APPLICATION CONTEXT.
   - MIDDLEWARE CAN OVERWRITE REQUEST DATA: Middleware commonly uses $request->merge() or $request->field = $value to replace user-supplied values with server-derived values (e.g., extracting user ID from JWT and overwriting $request->user_id). When this happens, the controller reads SERVER-CONTROLLED data, not user input. Check middleware code before flagging IDOR.
   - FormRequest classes validate AND authorize. If a method type-hints a FormRequest, validation IS happening.
   - Eloquent ALWAYS parameterizes queries by default. SQL injection vectors are ONLY: DB::raw(), ->whereRaw(), ->selectRaw(), ->orderByRaw(), ->groupByRaw(), ->havingRaw() with unparameterized user input, or DB::statement()/DB::select() with concatenation of USER input.
   - Route model binding + ScopedBindings means Laravel auto-404s if model doesn't belong to parent.
   - Gate::before() callbacks granting super-admin access is intentional, not a vulnerability.
   - Carbon objects and DateTime instances interpolated into SQL always produce safe formatted strings — NOT injection vectors.

4. DATA FLOW ANALYSIS — TRACE THE SOURCE BEFORE FLAGGING:
   SQL injection, command injection, SSRF, and open redirect all require USER-CONTROLLED input.
   Before flagging, trace the variable back to its source. DO NOT flag if the data comes from:
   - config() / Config:: values (static PHP files, not user-modifiable at runtime)
   - Hardcoded arrays, constants, or enums
   - Helper/service methods that return only hardcoded or config-sourced values
   - Values validated through in_array(), allowlists, or strict type casting like (int)
   - Database values that were originally set by admins/server, not user input
   - Environment variables (server-controlled, not request-controlled)
   The pattern "implode($array) into raw SQL" is NOT injection when $array comes from
   config or hardcoded values — it is only injection when $array contains user input.
   The pattern "(int)$var into raw SQL" is NOT injection — PHP integer cast always produces
   a safe integer regardless of input. "1 OR 1=1" cast to (int) becomes 1.

5. DO FLAG THESE — REAL VULNERABILITIES:
   - DB::raw() / whereRaw() / selectRaw() with concatenated/unescaped USER input (trace the source!)
   - Unserialization of user input (unserialize() with user-controlled strings)
   - File operations with user-controlled paths without validation (path traversal)
   - exec(), shell_exec(), system(), passthru(), proc_open() with user input (command injection)
   - eval(), preg_replace with /e modifier, assert() with user input (code injection)
   - Returning sensitive data (passwords, tokens, secrets, OTPs, API keys) in API responses
   - Test/debug endpoints with no environment check in production route files
   - SSRF: file_get_contents(), curl, Http::get() with user-controlled URLs without allowlist
   - IDOR where there is NO policy, NO scope, NO middleware, AND NO ownership check anywhere
   - Open redirects: redirecting to user-controlled URLs without domain validation
   - Mass assignment via Model::create($request->all()) when $fillable/$guarded is too permissive
   - Logging of passwords, tokens, OTP codes, API keys, credit card numbers
   - Broken authentication: custom auth logic bypassing Laravel's auth with exploitable flaws
   - Overly permissive CORS (allowed_origins = ['*'] with credentials)
   - Session fixation: not regenerating session after auth status change
   - Rate limiting gaps: ONLY on login, register, password-reset, OTP/verification, and payment endpoints with NO throttle. Do NOT flag missing rate limiting on general CRUD, dashboard, or internal endpoints — it creates noise

6. SEVERITY CALIBRATION:
   - CRITICAL: Directly exploitable RIGHT NOW for account takeover, RCE, or full data breach with no additional access required
   - HIGH: Exploitable vulnerability requiring some conditions but leading to significant impact
   - MEDIUM: Real security weakness requiring specific circumstances or limited impact
   - LOW: Security best practice violation, defense-in-depth gap, minimal direct impact
   - DO NOT inflate severity. If you find yourself writing "if X changes in the future" or "if the logic is ever modified" — that is LOW at most, not HIGH. Flag what IS exploitable now, not hypothetical future risks.
   - Code patterns that are ugly but safe (e.g., string concat with (int) cast, config values in raw SQL) should be LOW code-smell suggestions at most. If you cannot construct a concrete exploit, it is not HIGH.

7. FALSE POSITIVE PREVENTION — BEFORE EACH FINDING ASK:
   □ Did I check if middleware handles this at the route level?
   □ Did I check if a FormRequest handles validation/authorization?
   □ Did I check if a Policy exists for this model?
   □ Did I check if Eloquent parameterization prevents injection?
   □ Did I check if a global scope restricts queries?
   □ Did I check if route model binding handles the lookup?
   □ Did I check if the base controller applies relevant middleware?
   □ Did I TRACE the data source? Is it user input or config/hardcoded/server-controlled?
   □ Would a senior Laravel developer agree this is a real vulnerability?
   If any check eliminates the finding, DO NOT REPORT IT.

8. TAINT ANALYSIS PROTOCOL — MANDATORY FOR INPUT-DEPENDENT VULNERABILITIES:
   For SqlInjection, Xss, OpenRedirect, InsecureDeserialization, and command injection findings,
   you MUST trace the data flow and include a "taint_trace" field in the finding.

   Format: "SOURCE: <where the data enters> → TRANSFORMS: <every function/cast/validation it passes through> → SINK: <where it's used dangerously>"

   Examples:
   - "SOURCE: $request->input('search') → TRANSFORMS: trim(), (string) cast → SINK: DB::raw('... ' . $search . ' ...')"
   - "SOURCE: $request->query('url') → TRANSFORMS: none → SINK: redirect($url)"
   - "SOURCE: config('app.allowed_columns') → TRANSFORMS: implode(',') → SINK: DB::raw('SELECT ' . $cols)"

   CRITICAL: If you trace the source and discover it is NOT user-controlled (e.g., config(), env(),
   hardcoded array, constant, enum, database value set by admin, Auth::id()), you MUST delete the
   finding — do not emit it. The taint_trace exists to force you to verify the data flow. If the
   chain is broken by a safe transform ((int) cast, intval(), htmlspecialchars(), e(), in_array()
   allowlist, $request->validated(), Eloquent parameterization), DELETE the finding.

   For other vulnerability types (MassAssignment, Idor, MissingRateLimit, AuthBypass, Csrf,
   SensitiveDataExposure, WeakPasswordHashing, MissingValidation), taint_trace is optional.

IMPORTANT: Your ENTIRE response must be a single JSON object. No text before it. No text after it. No markdown fences. No explanation. Just the JSON.

{
    "vulnerabilities": [
        {
            "type": "SqlInjection|Xss|Csrf|MassAssignment|Idor|MissingRateLimit|AuthBypass|InsecureDeserialization|OpenRedirect|SensitiveDataExposure|WeakPasswordHashing|MissingValidation",
            "location": "relative/path/to/File.php",
            "line": 42,
            "severity": "Critical|High|Medium|Low",
            "description": "Clear description of the vulnerability, acknowledging security controls that ARE in place",
            "proof": "The exact vulnerable code snippet",
            "fix": "The exact fixed code that replaces the vulnerable code",
            "taint_trace": "SOURCE: <origin> → TRANSFORMS: <transformations> → SINK: <dangerous usage> (REQUIRED for SqlInjection, Xss, OpenRedirect, InsecureDeserialization; optional otherwise)"
        }
    ],
    "overall_score": 0-100,
    "summary": "Summary acknowledging security controls in place and only real vulnerabilities",
    "ctf_idea": "Short CTF challenge title based on worst finding"
}

Rules:
- Be extremely strict. Real vulnerabilities only — no false positives.
- Self-check every finding. If your analysis concludes the code is safe, DELETE the finding.
- If a file has ZERO real vulnerabilities after context-aware analysis, return score 100 and empty vulnerabilities array.
- Every fix must be working Laravel code.
- The summary should acknowledge security controls that ARE in place, not just what's missing.
- DO NOT write any analysis, reasoning, or explanation. Output ONLY the JSON object.
PROMPT;
    }

    /**
     * Set route middleware context for the next user prompt.
     *
     * @param  array<string, array<int, string>>  $routeContext
     */
    public function withRouteContext(array $routeContext): self
    {
        $this->routeContext = $routeContext;

        return $this;
    }

    /**
     * Set FormRequest file contents for the next user prompt.
     *
     * @param  array<int, array{path: string, content: string}>  $formRequests
     */
    public function withFormRequestContext(array $formRequests): self
    {
        $this->formRequestContext = $formRequests;

        return $this;
    }

    /**
     * Set routed method names for the next user prompt.
     *
     * @param  array<string, string>  $routedMethods  Method name => route description
     */
    public function withRoutedMethods(array $routedMethods): self
    {
        $this->routedMethods = $routedMethods;

        return $this;
    }

    /**
     * Set Eloquent model metadata for the next user prompt.
     *
     * @param  array<string, array{fillable: array<int, string>, hidden: array<int, string>, guarded: array<int, string>, casts: array<string, string>}>  $modelContext  FQCN => metadata
     */
    public function withModelContext(array $modelContext): self
    {
        $this->modelContext = $modelContext;

        return $this;
    }

    /**
     * Set the full application context for context-aware analysis.
     */
    public function withAppContext(AppContext $context): self
    {
        $this->appContext = $context;

        return $this;
    }

    /**
     * Build the user prompt containing file contents for analysis.
     *
     * Formats each file's path and content into a structured prompt that the
     * AI can parse and analyze for security vulnerabilities. Includes route
     * middleware context when available to reduce false positives.
     *
     * @param  array<int, array{path: string, content: string, type: string}>  $files
     */
    public function userPrompt(array $files): string
    {
        $hasAppContext = $this->appContext !== null;

        if ($hasAppContext) {
            $prompt = "=== APPLICATION CONTEXT ===\n".$this->appContext->toPromptString()."\n\n";
            $this->appContext = null;
        } else {
            $prompt = "Analyze the following Laravel application files for security vulnerabilities:\n\n";
        }

        $chunkContext = $this->buildChunkContext($hasAppContext);

        if ($chunkContext !== '') {
            if ($hasAppContext) {
                $prompt .= "=== CHUNK-SPECIFIC CONTEXT (authoritative for the files below, overrides APPLICATION CONTEXT where they overlap) ===\n";
            }

            $prompt .= $chunkContext;
        }

        if ($hasAppContext) {
            $prompt .= "=== CODE TO AUDIT ===\n";
        }

        foreach ($files as $file) {
            $prompt .= "### File: {$file['path']}\n```php\n{$file['content']}\n```\n\n";
        }

        $prompt .= 'Respond with ONLY the JSON object. No markdown fences, no explanation, no text before or after.';

        return $prompt;
    }

    /**
     * Build the chunk-specific context sections and reset consumed state.
     *
     * Returns the combined string for route middleware, routed methods,
     * form request, and model context sections. Resets each context to
     * empty after consumption so the next call starts fresh.
     */
    private function buildChunkContext(bool $hasAppContext): string
    {
        $sections = [];

        if ($this->routeContext !== []) {
            $section = "## Route Middleware Context\nThe following middleware is applied to this controller's routes:\n";

            foreach ($this->routeContext as $route => $middleware) {
                $middlewareList = implode(', ', $middleware);
                $section .= "- {$route} → {$middlewareList}\n";
            }

            $sections[] = $section;
            $this->routeContext = [];
        }

        if ($this->routedMethods !== []) {
            $section = "## Routed Methods\nOnly the following controller methods have registered routes and are reachable:\n";

            foreach ($this->routedMethods as $method => $route) {
                $section .= "- {$method}() → {$route}\n";
            }

            $section .= "\nMethods NOT listed here have NO registered routes and CANNOT be reached by attackers. Do NOT flag them.\n";
            $sections[] = $section;
            $this->routedMethods = [];
        }

        if ($this->formRequestContext !== []) {
            $section = "## FormRequest Context\nThe following FormRequest classes are used by the controller methods being analyzed. Check their authorize() method before flagging IDOR, and check their rules() method before flagging Missing Validation:\n\n";

            foreach ($this->formRequestContext as $formRequest) {
                $section .= "### File: {$formRequest['path']}\n```php\n{$formRequest['content']}\n```\n\n";
            }

            $sections[] = $section;
            $this->formRequestContext = [];
        }

        if ($this->modelContext !== []) {
            $section = "## Eloquent Model Context\nThe following model metadata is authoritative (read from the actual Model classes at runtime). Use this to verify mass assignment, sensitive data exposure, and other model-related findings:\n";

            foreach ($this->modelContext as $modelClass => $info) {
                $section .= "\n### {$modelClass}\n";
                $section .= '- $fillable: ['.implode(', ', array_map(fn (string $f): string => "'{$f}'", $info['fillable']))."]\n";
                $section .= '- $hidden: ['.implode(', ', array_map(fn (string $f): string => "'{$f}'", $info['hidden']))."]\n";
                $section .= '- $guarded: ['.implode(', ', array_map(fn (string $f): string => "'{$f}'", $info['guarded']))."]\n";

                if ($info['casts'] !== []) {
                    $castPairs = array_map(fn (string $k, string $v): string => "'{$k}' => '{$v}'", array_keys($info['casts']), array_values($info['casts']));
                    $section .= '- $casts: ['.implode(', ', $castPairs)."]\n";
                }
            }

            $section .= "\nDo NOT flag mass assignment if \$fillable is properly scoped. Do NOT flag sensitive data exposure for fields in \$hidden.\n";
            $sections[] = $section;
            $this->modelContext = [];
        }

        if ($sections === []) {
            return '';
        }

        return implode("\n", $sections)."\n";
    }

    /**
     * Build the system prompt for multi-pass exploit verification.
     *
     * Asks the AI to act as a penetration tester who must either produce a
     * concrete, working exploit or definitively state no exploit is possible.
     * Theoretical or hedging answers are explicitly forbidden.
     */
    public function verificationSystemPrompt(): string
    {
        return <<<'PROMPT'
You are a penetration tester verifying a static-analysis finding. Your job is to either:
(a) construct a concrete, working exploit demonstrating the vulnerability, or
(b) definitively state that no exploit is possible given the full code context.

Do not hedge. Do not produce "theoretical" exploits. If you cannot write a specific HTTP request, SQL payload, input string, or command that triggers the vulnerability, you MUST respond with verified=false.

The file contents are provided so you can see mitigations the first-pass analyzer may have missed (middleware, validation, authorization, encoding, parameterization, scopes, allowlists). Inspect them carefully before committing to a verdict.

Your ENTIRE response MUST be a single JSON object. No prose, no markdown fences, no text outside the JSON.

{
    "verified": true | false,
    "exploit": "<a concrete payload, HTTP request, or input string — REQUIRED when verified=true; use empty string when verified=false>",
    "reasoning": "<why this exploit works, or why it cannot be exploited given the code context>"
}

Rules:
- If verified=true, "exploit" MUST be a substantive payload a human could copy and run. Placeholders like "N/A", "<payload>", "TBD", or empty strings are NOT acceptable and mean verified=false.
- If verified=false, explain in "reasoning" which specific code element prevents exploitation (e.g., "line 42 calls $request->validated() which enforces an allowlist").
- Do not invent code paths. Base your verdict strictly on the file contents provided.
PROMPT;
    }

    /**
     * Build the user prompt for exploit verification of a specific finding.
     *
     * Packages the original finding (type, location, line, description, proof,
     * taint trace) alongside the full source file so the model can attempt a
     * concrete exploit or cite a mitigation that invalidates the finding.
     */
    public function buildVerificationPrompt(Vulnerability $vuln, string $fileContents): string
    {
        $taintLine = $vuln->taintTrace !== null
            ? "Taint trace: {$vuln->taintTrace}\n"
            : '';

        return <<<PROMPT
A first-pass static analyzer reported the following finding. Verify whether it is concretely exploitable.

## Finding

Type: {$vuln->type->value} ({$vuln->type->label()})
Severity (pass 1): {$vuln->severity->value}
Location: {$vuln->location}:{$vuln->line}

Description:
{$vuln->description}

Proof (excerpt the analyzer flagged):
{$vuln->proof}

{$taintLine}
## Full File Contents

```php
{$fileContents}
```

## Your Task

Attempt to construct a concrete, working exploit against the finding above. If you can, return verified=true with the exact exploit payload. If you cannot — because the code has a mitigation the first pass missed, because the source is not user-controlled, or because the dangerous sink is unreachable — return verified=false with a specific reason.

Respond with ONLY the JSON object. No markdown fences, no explanation, no text before or after.
PROMPT;
    }

    /**
     * Build the system prompt for CTF challenge generation.
     */
    public function forCtfGeneration(): string
    {
        return <<<'PROMPT'
You are a CTF (Capture The Flag) challenge designer specializing in web security and Laravel.

Create creative, realistic CTF challenges based on real vulnerability types found in Laravel applications.

Return ONLY valid JSON (no markdown fences, no explanation outside JSON) with this exact structure:
{
    "title": "Creative challenge title",
    "difficulty": "Easy|Medium|Hard|Expert",
    "category": "Web Security",
    "description": "A narrative description that sets the scene without giving away the solution",
    "rules": "Challenge rules and constraints",
    "hints": "Progressive hints from vague to specific, separated by newlines",
    "challenge_code": "The complete vulnerable Laravel code that participants must exploit",
    "solution_explanation": "Step-by-step solution explaining the exploit",
    "fix_explanation": "How to fix the vulnerability properly"
}

Rules:
- The challenge must be solvable but not trivially obvious.
- The challenge code must be a complete, runnable Laravel snippet.
- Include at least 3 progressive hints from vague to specific.
- The solution must detail the exact exploit steps.
- CRITICAL: Return strictly valid JSON. Use \n for newlines inside string values. Do NOT use literal/raw newlines inside JSON string values — they break JSON parsing.
PROMPT;
    }

    /**
     * Build the user prompt for CTF generation from actual source code.
     */
    public function ctfFromSourceCode(string $vulnerabilityType, string $sourceCode, string $flag): string
    {
        return <<<PROMPT
Generate a CTF challenge based on the following real vulnerability found in a Laravel application.

**Vulnerability Type:** {$vulnerabilityType}
**Flag to embed:** {$flag}

**Vulnerable Source Code:**
```php
{$sourceCode}
```

Create a challenge that is inspired by this real code. The challenge_code should be a modified version that is self-contained and exploitable.

Respond with ONLY the JSON object. No markdown fences, no explanation, no text before or after.
PROMPT;
    }

    /**
     * Build the user prompt for CTF generation without source code.
     */
    public function ctfGeneric(string $vulnerabilityType, string $flag): string
    {
        return <<<PROMPT
Generate a CTF challenge for the following vulnerability type in a Laravel application.

**Vulnerability Type:** {$vulnerabilityType}
**Flag to embed:** {$flag}

Create a realistic, self-contained Laravel code snippet that contains this vulnerability type and can be exploited by participants.

Respond with ONLY the JSON object. No markdown fences, no explanation, no text before or after.
PROMPT;
    }

    /**
     * Build the system prompt for generating viral developer tweets about scan results.
     */
    public function tweetSystemPrompt(): string
    {
        return <<<'PROMPT'
You are a developer who just ran a security scan on your Laravel app. Write a single tweet (max 250 characters) sharing your results. Be punchy, slightly shocked or humbled, developer-audience. Use the actual findings — not generic marketing speak. Include the score. No hashtags. No emojis. Short sentences. End with a subtle nudge to try it.
PROMPT;
    }

    /**
     * Build the user prompt for tweet generation with actual scan data.
     */
    public function tweetUserPrompt(int $score, int $total, int $critical, int $high, string $topFinding): string
    {
        return <<<PROMPT
Generate a tweet about these security scan results:
- Score: {$score}/100
- Total vulnerabilities: {$total} ({$critical} critical, {$high} high)
- Most interesting finding: {$topFinding}

Write ONE tweet, max 250 characters. Real findings, not marketing. Humble/shocked tone.
PROMPT;
    }

    /**
     * Build a prompt for CTF challenge generation based on a discovered vulnerability.
     *
     * Asks the AI to create a creative, realistic CTF scenario with challenge code,
     * solution, README, and flag based on the provided vulnerability type and code.
     */
    public function ctfPrompt(string $vulnerabilityType, string $code): string
    {
        return <<<PROMPT
You are a CTF (Capture The Flag) challenge designer specializing in web security and Laravel.

Based on the following real vulnerability found in a Laravel application, create a creative, realistic CTF challenge.

**Vulnerability Type:** {$vulnerabilityType}

**Vulnerable Code:**
```php
{$code}
```

Generate a complete CTF challenge with the following structure as valid JSON:
{
    "title": "Creative challenge title",
    "difficulty": "Easy|Medium|Hard|Expert",
    "category": "Web Security",
    "description": "A narrative description that sets the scene without giving away the solution",
    "challenge_code": "The complete vulnerable Laravel code that participants must exploit",
    "hints": ["Hint 1", "Hint 2", "Hint 3"],
    "solution": "Step-by-step solution explaining the exploit",
    "flag": "FLAG{unique_flag_value_here}",
    "readme": "Complete README.md content with setup instructions and rules"
}

Rules:
- The challenge must be solvable but not trivially obvious.
- The flag format must be FLAG{...} with a creative value related to the vulnerability.
- The challenge code must be a complete, runnable Laravel snippet.
- Include at least 3 progressive hints from vague to specific.
- The solution must detail the exact exploit steps.

Respond with ONLY the JSON object. No markdown fences, no explanation, no text before or after.
PROMPT;
    }
}
