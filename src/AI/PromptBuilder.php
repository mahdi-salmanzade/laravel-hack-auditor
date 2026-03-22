<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\AI;

use Mahdi\HackAuditor\Scanner\AppContext;

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
   - "Missing rate limiting" when the route has throttle middleware or a named rate limiter
   - "Missing CSRF" on routes in the 'api' middleware group (APIs use token auth, not CSRF)
   - "SQL injection" on Eloquent query builder calls using ? placeholders or parameter binding (e.g., ->where('id', $id), ->whereIn('id', $ids)) — Eloquent parameterizes these automatically
   - "SQL injection" on Eloquent methods: find(), findOrFail(), where() with column/value args, firstWhere(), pluck(), paginate(), etc.
   - "Mass assignment" when $fillable or $guarded is properly defined on the model
   - "IDOR" when route model binding is used with ->scopeBindings() or when a Policy checks ownership
   - "IDOR" when a global scope (e.g., tenant scope) automatically filters queries
   - "Missing encryption" for fields that use 'encrypted' cast in the model
   - "Data exposure" for fields listed in the model's $hidden array
   - "Sensitive data in logs" for logging that only includes non-sensitive contextual data
   - "Hardcoded credentials" for route names, config keys, or non-secret string constants
   - "No HTTPS enforcement" — this is a server/infrastructure concern

3. LARAVEL SECURITY MODEL:
   - Middleware can be applied at: global level, middleware group level, route group level, individual route level, or controller constructor level. ALL are valid. Check APPLICATION CONTEXT.
   - FormRequest classes validate AND authorize. If a method type-hints a FormRequest, validation IS happening.
   - Eloquent ALWAYS parameterizes queries by default. SQL injection vectors are ONLY: DB::raw(), ->whereRaw(), ->selectRaw(), ->orderByRaw(), ->groupByRaw(), ->havingRaw() with unparameterized user input, or DB::statement()/DB::select() with concatenation.
   - Route model binding + ScopedBindings means Laravel auto-404s if model doesn't belong to parent.
   - Gate::before() callbacks granting super-admin access is intentional, not a vulnerability.

4. DO FLAG THESE — REAL VULNERABILITIES:
   - DB::raw() / whereRaw() / selectRaw() with concatenated/unescaped user input
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
   - Rate limiting gaps: auth/OTP/password-reset endpoints with NO throttle at any level

5. SEVERITY CALIBRATION:
   - CRITICAL: Directly exploitable for account takeover, RCE, or full data breach
   - HIGH: Exploitable vulnerability requiring some conditions but significant impact
   - MEDIUM: Real security weakness requiring specific circumstances or limited impact
   - LOW: Security best practice violation, defense-in-depth gap, minimal direct impact
   - DO NOT inflate severity.

6. FALSE POSITIVE PREVENTION — BEFORE EACH FINDING ASK:
   □ Did I check if middleware handles this at the route level?
   □ Did I check if a FormRequest handles validation/authorization?
   □ Did I check if a Policy exists for this model?
   □ Did I check if Eloquent parameterization prevents injection?
   □ Did I check if a global scope restricts queries?
   □ Did I check if route model binding handles the lookup?
   □ Did I check if the base controller applies relevant middleware?
   □ Would a senior Laravel developer agree this is a real vulnerability?
   If any check eliminates the finding, DO NOT REPORT IT.

Return ONLY valid JSON (no markdown fences, no explanation outside JSON) with this exact structure:
{
    "vulnerabilities": [
        {
            "type": "SqlInjection|Xss|Csrf|MassAssignment|Idor|MissingRateLimit|AuthBypass|InsecureDeserialization|OpenRedirect|SensitiveDataExposure|WeakPasswordHashing|MissingValidation",
            "location": "relative/path/to/File.php",
            "line": 42,
            "severity": "Critical|High|Medium|Low",
            "description": "Clear description of the vulnerability, acknowledging security controls that ARE in place",
            "proof": "The exact vulnerable code snippet",
            "fix": "The exact fixed code that replaces the vulnerable code"
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

        if ($this->routeContext !== []) {
            $prompt .= "## Route Middleware Context\nThe following middleware is applied to this controller's routes:\n";

            foreach ($this->routeContext as $route => $middleware) {
                $middlewareList = implode(', ', $middleware);
                $prompt .= "- {$route} → {$middlewareList}\n";
            }

            $prompt .= "\n";
            $this->routeContext = [];
        }

        if ($this->routedMethods !== []) {
            $prompt .= "## Routed Methods\nOnly the following controller methods have registered routes and are reachable:\n";

            foreach ($this->routedMethods as $method => $route) {
                $prompt .= "- {$method}() → {$route}\n";
            }

            $prompt .= "\nMethods NOT listed here have NO registered routes and CANNOT be reached by attackers. Do NOT flag them.\n\n";
            $this->routedMethods = [];
        }

        if ($this->formRequestContext !== []) {
            $prompt .= "## FormRequest Context\nThe following FormRequest classes are used by the controller methods being analyzed. Check their authorize() method before flagging IDOR, and check their rules() method before flagging Missing Validation:\n\n";

            foreach ($this->formRequestContext as $formRequest) {
                $prompt .= "### File: {$formRequest['path']}\n```php\n{$formRequest['content']}\n```\n\n";
            }

            $this->formRequestContext = [];
        }

        if ($this->modelContext !== []) {
            $prompt .= "## Eloquent Model Context\nThe following model metadata is authoritative (read from the actual Model classes at runtime). Use this to verify mass assignment, sensitive data exposure, and other model-related findings:\n";

            foreach ($this->modelContext as $modelClass => $info) {
                $prompt .= "\n### {$modelClass}\n";
                $prompt .= '- $fillable: ['.implode(', ', array_map(fn (string $f): string => "'{$f}'", $info['fillable']))."]\n";
                $prompt .= '- $hidden: ['.implode(', ', array_map(fn (string $f): string => "'{$f}'", $info['hidden']))."]\n";
                $prompt .= '- $guarded: ['.implode(', ', array_map(fn (string $f): string => "'{$f}'", $info['guarded']))."]\n";

                if ($info['casts'] !== []) {
                    $castPairs = array_map(fn (string $k, string $v): string => "'{$k}' => '{$v}'", array_keys($info['casts']), array_values($info['casts']));
                    $prompt .= '- $casts: ['.implode(', ', $castPairs)."]\n";
                }
            }

            $prompt .= "\nDo NOT flag mass assignment if \$fillable is properly scoped. Do NOT flag sensitive data exposure for fields in \$hidden.\n\n";
            $this->modelContext = [];
        }

        if ($hasAppContext) {
            $prompt .= "=== CODE TO AUDIT ===\n";
        }

        foreach ($files as $file) {
            $prompt .= "### File: {$file['path']}\n```php\n{$file['content']}\n```\n\n";
        }

        return $prompt;
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
PROMPT;
    }
}
