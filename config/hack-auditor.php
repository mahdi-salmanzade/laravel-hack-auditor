<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Hack Auditor Configuration
|--------------------------------------------------------------------------
|
| SECURITY WARNING: This package sends your application's source code to
| AI providers for security analysis. Ensure you understand your AI
| provider's data handling policies before running scans. Never run scans
| against production environments with sensitive code that should not be
| shared with third-party AI services.
|
| Sensitive files (.env, *.key, *.pem, logs) are excluded by default.
| Review the 'scan.sensitive_patterns' setting to ensure your secrets
| are protected.
|
*/

return [

    /*
    |--------------------------------------------------------------------------
    | AI Provider Settings
    |--------------------------------------------------------------------------
    |
    | Configure which AI provider and model to use for security analysis.
    | When set to null, the package will use whatever provider and model
    | you have configured as the default in your laravel/ai configuration.
    |
    */

    'ai' => [
        'provider' => env('HACK_AUDITOR_AI_PROVIDER', null),
        'model' => env('HACK_AUDITOR_AI_MODEL', null),
        'temperature' => 0.3,
        'max_tokens' => 4096,
        'timeout' => 120,
    ],

    /*
    |--------------------------------------------------------------------------
    | Scan Settings
    |--------------------------------------------------------------------------
    |
    | Control which files and directories are included in security scans.
    | Paths are relative to base_path(). The chunk_size determines how
    | many files are sent per AI request to stay within token limits.
    |
    */

    'scan' => [
        'paths' => [
            'app/Http/Controllers',
            'app/Models',
            'app/Http/Requests',
            'app/Http/Middleware',
            'routes',
        ],

        'exclude' => [
            '*/vendor/*',
            '*/node_modules/*',
            '*/tests/*',
        ],

        'file_extensions' => ['.php'],

        'max_file_size_kb' => 500,

        'chunk_size' => 10,

        /*
        |----------------------------------------------------------------------
        | Cost Guardrails
        |----------------------------------------------------------------------
        |
        | When true, the scan command will prompt for confirmation before
        | proceeding if the file count exceeds the threshold below. This
        | prevents accidental large API bills on big codebases. Use --force
        | on the command to skip the confirmation prompt.
        |
        */

        'confirm_above_files' => 20,

        /*
        |----------------------------------------------------------------------
        | Sensitive Patterns (Always Excluded)
        |----------------------------------------------------------------------
        |
        | These patterns are ALWAYS excluded from scans regardless of other
        | settings. This is a safety net to prevent accidental exposure of
        | secrets, keys, and certificates to AI providers.
        |
        */

        'sensitive_patterns' => [
            '.env*',
            '*.key',
            '*.pem',
            'storage/logs/*',
        ],

        /*
        |----------------------------------------------------------------------
        | Git Diff Base Branch
        |----------------------------------------------------------------------
        |
        | The base branch used when scanning with --diff. When null, the
        | package auto-detects main or master. Set this if your default
        | branch has a different name.
        |
        */

        'diff_base_branch' => null,

        /*
        |----------------------------------------------------------------------
        | Baseline File Path
        |----------------------------------------------------------------------
        |
        | Path to the baseline JSON file for suppressing known findings.
        | Use --update-baseline to save current findings, --no-baseline
        | to ignore the baseline file during scans.
        |
        */

        'baseline_path' => base_path('hack-auditor-baseline.json'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Context-Aware Scanning
    |--------------------------------------------------------------------------
    |
    | When enabled, the scanner collects security-relevant context from your
    | application (routes, middleware, policies, form requests, models) before
    | sending code to the AI. This dramatically reduces false positives by
    | giving the AI full visibility into your security architecture.
    |
    */

    'context' => [
        'enabled' => true,
        'max_context_tokens' => 8000,
        'include_routes' => true,
        'include_middleware' => true,
        'include_policies' => true,
        'include_form_requests' => true,
        'include_models' => true,
        'extra_context_paths' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Severity Settings
    |--------------------------------------------------------------------------
    |
    | Control the minimum severity level to include in scan reports.
    | Available levels: Critical, High, Medium, Low, Info
    |
    */

    'severity' => [
        'minimum_report' => 'Low',
    ],

    /*
    |--------------------------------------------------------------------------
    | CTF (Capture The Flag) Settings
    |--------------------------------------------------------------------------
    |
    | Configure the output path for generated CTF challenges.
    | Challenges are generated based on real vulnerabilities found
    | in your application, providing hands-on security training.
    |
    */

    'ctf' => [
        'output_path' => 'hack-auditor/ctf',
    ],

    /*
    |--------------------------------------------------------------------------
    | Report Settings
    |--------------------------------------------------------------------------
    |
    | Configure the output path for generated HTML security reports.
    | Reports are self-contained single-file HTML documents.
    |
    */

    'report' => [
        'output_path' => 'hack-auditor/reports',
    ],

    /*
    |--------------------------------------------------------------------------
    | Sharing Settings
    |--------------------------------------------------------------------------
    |
    | Default hashtags appended when sharing scan results or CTF challenges.
    |
    */

    'share' => [
        'default_hashtags' => [
            '#LaravelSecurity',
            '#HackAuditor',
            '#CTF',
        ],
        'ai_tweets' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Token Usage & Cost Tracking
    |--------------------------------------------------------------------------
    |
    | Track token consumption and estimated costs for AI scan requests.
    | The default limit of 0 means unlimited. Use --limit on the command
    | or set HACK_AUDITOR_TOKEN_LIMIT in .env to enforce a budget.
    |
    | Cost rates are per 1M tokens and default to Claude Sonnet pricing.
    | Adjust to match your AI provider's rates.
    |
    */

    'usage' => [
        'default_limit' => (int) env('HACK_AUDITOR_TOKEN_LIMIT', 0),
        'cost_per_1m_input' => (float) env('HACK_AUDITOR_COST_INPUT', 3.00),
        'cost_per_1m_output' => (float) env('HACK_AUDITOR_COST_OUTPUT', 15.00),
        'show_usage' => true,
        'log_enabled' => true,
    ],

];
