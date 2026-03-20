<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\AI;

final class PromptBuilder
{
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
- overall_score: 100 = perfectly secure, 0 = critically vulnerable.
- If no vulnerabilities found, return empty vulnerabilities array and score 100.
- Every fix must be a real, working Laravel code patch — not pseudocode.
- line numbers must be accurate based on the provided code.
PROMPT;
    }

    /**
     * Build the user prompt containing file contents for analysis.
     *
     * Formats each file's path and content into a structured prompt that the
     * AI can parse and analyze for security vulnerabilities.
     *
     * @param  array<int, array{path: string, content: string, type: string}>  $files
     */
    public function userPrompt(array $files): string
    {
        $prompt = "Analyze the following Laravel application files for security vulnerabilities:\n\n";

        foreach ($files as $file) {
            $prompt .= "### File: {$file['path']}\n```php\n{$file['content']}\n```\n\n";
        }

        return $prompt;
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
