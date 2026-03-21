<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\AI;

class PromptBuilder
{
    /** @var array<string, array<int, string>> */
    private array $routeContext = [];

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
You are an elite Laravel security auditor and CTF creator with deep knowledge of OWASP Top 10 2025, Laravel internals, and common PHP security pitfalls.

Analyze the provided Laravel code files for security vulnerabilities. You must check for:
1. SQL Injection — raw queries, missing parameter bindings, unsafe DB::raw(), whereRaw() with concatenation
2. XSS — echoing user input without {!! !!} awareness, missing e() helper, Blade unescaped output
3. CSRF — missing @csrf in forms, excluded routes in VerifyCsrfToken, API routes without sanctum/auth
4. Mass Assignment — models without $fillable or $guarded, or with $guarded = []
5. IDOR — direct use of route parameters to query models without ownership/policy checks
6. Missing Rate Limiting — auth routes (login, register, password reset) without throttle middleware
7. Auth Bypass — custom auth logic that can be circumvented, missing auth middleware on sensitive routes
8. Insecure Deserialization — use of unserialize() on user input, unsafe cache drivers
9. Open Redirects — redirect() using user-supplied input without validation
10. Sensitive Data Exposure — logging sensitive fields (password, token, secret, credit_card), .env exposure
11. Weak Password Hashing — using md5(), sha1(), or custom hashing instead of Hash::make()
12. Missing Validation — controller methods accepting request input without FormRequest or inline validation

Return ONLY valid JSON (no markdown fences, no explanation outside JSON) with this exact structure:
{
    "vulnerabilities": [
        {
            "type": "SqlInjection|Xss|Csrf|MassAssignment|Idor|MissingRateLimit|AuthBypass|InsecureDeserialization|OpenRedirect|SensitiveDataExposure|WeakPasswordHashing|MissingValidation",
            "location": "relative/path/to/File.php",
            "line": 42,
            "severity": "Critical|High|Medium|Low",
            "description": "Clear description of the vulnerability",
            "proof": "The exact vulnerable code snippet",
            "fix": "The exact fixed code that replaces the vulnerable code"
        }
    ],
    "overall_score": 0-100,
    "summary": "One paragraph summary of the security posture",
    "ctf_idea": "Short one-line CTF challenge title based on the worst finding"
}

Rules:
- Be extremely strict. Real vulnerabilities only — no false positives.
- CRITICAL: Self-check every finding before emitting it. After writing the description, re-read it. If your own analysis concludes the code is actually safe (e.g., "on closer inspection this is not an issue", "fields are explicitly specified", "this is handled"), then DELETE that finding from the vulnerabilities array — do NOT emit it. A finding that contradicts its own description destroys trust in the tool.
- CRITICAL: Only flag code that is actually exploitable. Do not flag defensive code patterns (in_array checks with fallbacks, explicit field lists, manual whitelists) as vulnerabilities. If the code handles the case safely — even without formal validation — it is not a vulnerability. At most, flag it as Low severity code quality suggestion, never Medium or above.
- Severity calibration: Critical = RCE, full DB dump, account takeover. High = data breach, privilege escalation. Medium = exploitable issue requiring specific conditions. Low = code quality, defense-in-depth suggestion, not directly exploitable. Do NOT inflate severity. A missing formal validation on a field that already has an in_array check is Low at most.
- overall_score: 100 = perfectly secure, 0 = critically vulnerable.
- If no vulnerabilities found, return empty vulnerabilities array and score 100.
- Every fix must be a real, working Laravel code patch — not pseudocode.
- line numbers must be accurate based on the provided code.
- IMPORTANT: If a "Route Middleware Context" section is provided, you MUST use it to determine which middleware is already applied. Do NOT report "Missing Rate Limiting" if any throttle middleware (throttle:*, api) is present on the route — even if the throttle parameters seem permissive. Do NOT report "Authentication Bypass" or "Missing Auth" if auth middleware (auth, auth:sanctum, auth:jwt, auth:api) is present on the route. Routes inside middleware groups inherit the group's middleware — trust the context provided. Re-read the route context for EVERY finding before including it.
- IMPORTANT: If a "Routed Methods" section is provided, ONLY analyze the methods listed there. Controller methods that are NOT listed have no registered routes — they are dead code and cannot be reached by attackers. Do NOT flag vulnerabilities on unrouted methods.
- IMPORTANT: Before flagging IDOR (Insecure Direct Object Reference), check whether the controller method type-hints a FormRequest class. If a "FormRequest Context" section is provided, read the authorize() method of each FormRequest. If authorize() performs ownership or permission checks (e.g., comparing $this->user()->id against a model's owner_id, using Gate/Policy, or any non-trivial authorization logic), do NOT flag the method for IDOR — the authorization is handled by the FormRequest. In Laravel, FormRequest::authorize() runs BEFORE the controller method and will abort with 403 if it returns false.
- IMPORTANT: Before flagging "Mass Assignment", check if the controller uses $request->validated(), $request->only([...]), $request->safe(), or explicitly enumerates fields (e.g., ['name' => $request->name, 'email' => $request->email]). All of these are explicit whitelists and are NOT mass assignment vulnerabilities. Only flag mass assignment when $request->all() or unfiltered input is passed directly to create()/update()/fill().
- IMPORTANT: Before flagging "Sensitive Data Exposure", check the Model's $hidden property if provided. Fields listed in $hidden are automatically excluded from JSON/array serialization. Do NOT flag exposure of fields that are in $hidden.
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
        $prompt = "Analyze the following Laravel application files for security vulnerabilities:\n\n";

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
