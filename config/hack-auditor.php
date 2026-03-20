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
        'output_path' => 'storage/hack-auditor/ctf',
    ],

    /*
    |--------------------------------------------------------------------------
    | Scan History Settings
    |--------------------------------------------------------------------------
    |
    | Control whether scan results are persisted and how long they are kept.
    | History allows you to track security improvements over time.
    |
    */

    'history' => [
        'enabled' => false,
        'keep_days' => 30,
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
    ],

];
