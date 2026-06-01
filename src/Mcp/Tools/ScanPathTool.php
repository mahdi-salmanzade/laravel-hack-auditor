<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Mcp\Tools;

use Illuminate\Contracts\JsonSchema\JsonSchema;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\ResponseFactory;
use Laravel\Mcp\Server\Attributes\Description;
use Laravel\Mcp\Server\Attributes\Name;
use Laravel\Mcp\Server\Tool;
use Mahdi\HackAuditor\HackAuditorManager;
use Mahdi\HackAuditor\Mcp\Support\FindingFormatter;

#[Name('scan_path')]
#[Description('Run an AI-assisted Laravel security audit on a single file or directory and return structured findings (type, severity, file, line, description, proof, fix). Pass a path relative to the Laravel app root (e.g. "app/Http/Controllers/UserController.php"). Detects SQL injection, XSS, IDOR, mass assignment, missing authorization, auth bypass, SSRF, open redirect, and other OWASP issues using contextual analysis of routes, middleware, FormRequests and Eloquent models — not a regex SAST. Use this when the user asks to audit, review, or scan specific Laravel code for vulnerabilities.')]
class ScanPathTool extends Tool
{
    /**
     * Create a new tool instance.
     */
    public function __construct(private readonly HackAuditorManager $auditor) {}

    /**
     * Define the tool's input schema.
     *
     * @return array<string, mixed>
     */
    public function schema(JsonSchema $schema): array
    {
        return [
            'path' => $schema->string()
                ->description('A file or directory path relative to the Laravel application root (e.g. "app/Http/Controllers/UserController.php" or "app/Models"). Absolute paths inside the project are also accepted. Omit to scan the application\'s configured scan paths.'),
        ];
    }

    /**
     * Handle the tool request.
     */
    public function handle(Request $request): Response|ResponseFactory
    {
        $rawPath = $request->get('path');
        $path = is_string($rawPath) && trim($rawPath) !== '' ? trim($rawPath) : null;

        if ($path !== null && ($error = $this->rejectUnsafePath($path)) !== null) {
            return $error;
        }

        $report = $this->auditor->scan($path);

        return FindingFormatter::report($report, $path ?? '(application scan paths)');
    }

    /**
     * Reject absolute paths and `..` traversal before the scanner reads anything.
     *
     * Defense in depth on top of the scanner-level guard: callers may only
     * reference files relative to the Laravel application root, so an attacker
     * cannot point the tool at `/etc/passwd` or climb out with `../../.env`.
     */
    private function rejectUnsafePath(string $path): ?Response
    {
        $normalized = str_replace('\\', '/', $path);

        if (str_starts_with($normalized, '/') || preg_match('#^[A-Za-z]:/#', $normalized) === 1) {
            return Response::error(
                'Absolute paths are not allowed. Pass a path relative to the Laravel application root, for example "app/Http/Controllers/UserController.php".'
            );
        }

        $segments = explode('/', $normalized);

        if (in_array('..', $segments, true)) {
            return Response::error(
                'Path traversal ("..") is not allowed. Pass a path relative to the Laravel application root, for example "app/Http/Controllers/UserController.php".'
            );
        }

        return null;
    }
}
