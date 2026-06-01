<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\AccessControl;

use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * Flags controller actions that issue an OUTBOUND request to a URL derived from
 * user input without any allow-list validation (Server-Side Request Forgery).
 *
 * Laravel-specific reasoning: Http::get($request->input('url')) (or
 * file_get_contents / fopen / cURL / a Guzzle client) lets a client steer the
 * server's own outbound request. An attacker can pivot to internal services,
 * cloud metadata endpoints (169.254.169.254), or localhost-only admin panels.
 * This is CWE-918 (SSRF, OWASP A10).
 *
 * Conservative, low-false-positive design: only flags when an outbound-request
 * SINK receives a URL argument that is unambiguously user-controlled — either
 * request input inline, or a local variable that was assigned from request
 * input earlier in the same method (the assignment is traced the same way the
 * UnauthorizedModelFetchDetector traces a request-sourced id). Constant strings,
 * config()/route()/url() values, env-derived URLs, and values that are
 * validated or allow-listed (in_array / a visible Validator|FormRequest `url`
 * rule) are deliberately NOT flagged.
 */
final class SsrfDetector implements AccessControlDetector
{
    private MethodScanner $methods;

    public function __construct(?MethodScanner $methods = null)
    {
        $this->methods = $methods ?? new MethodScanner;
    }

    /**
     * Outbound-request sink patterns. Each captures the URL argument expression
     * as the first group so it can be checked for user control.
     *
     * @var array<int, string>
     */
    private const SINK_PATTERNS = [
        // Http::get/post/... including a chained Http::withToken(...)->get(...)
        '/\bHttp\s*::\s*(?:[a-zA-Z]+\s*\([^()]*\)\s*->\s*)*(?:get|post|put|patch|delete|head|request|send)\s*\(\s*([^),]+)/',
        // file_get_contents($url) / fopen($url, ...)
        '/\b(?:file_get_contents|fopen)\s*\(\s*([^),]+)/',
        // curl_init($url)
        '/\bcurl_init\s*\(\s*([^),]+)/',
        // curl_setopt($ch, CURLOPT_URL, $url)
        '/\bcurl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*([^),]+)/',
        // $client->request('GET', $url) — Guzzle request() (URL is the 2nd arg)
        '/->\s*request\s*\(\s*[^,]+,\s*([^),]+)/',
        // $client->get($url) / ->post($url) — Guzzle verb helpers
        '/->\s*(?:get|post|put|patch|delete|head)\s*\(\s*([^),]+)/',
    ];

    public function detect(array $files, AccessControlContext $context): array
    {
        $findings = [];

        foreach ($files as $file) {
            if (! $this->looksLikeController($file)) {
                continue;
            }

            foreach ($this->methods->publicMethods($file->content) as $method) {
                $body = $method['body'];
                $sink = $this->findUserControlledSink($body);

                if ($sink === null) {
                    continue;
                }

                if ($this->hasUrlAllowlist($body)) {
                    continue;
                }

                $bodyStart = strpos($file->content, $body, $method['offset']);
                $offsetInBody = (int) strpos($body, $sink['snippet']);
                $absoluteOffset = ($bodyStart === false ? $method['offset'] : $bodyStart) + $offsetInBody;
                $line = $file->lineForOffset($absoluteOffset);

                $findings[] = new Vulnerability(
                    type: VulnerabilityType::Ssrf,
                    location: $file->path,
                    line: $line,
                    severity: SeverityLevel::High,
                    description: sprintf(
                        '%s::%s() makes an outbound request (%s) to a URL taken from user input (%s) with no allow-list. An attacker can point the server at internal services or the cloud metadata endpoint (SSRF, CWE-918).',
                        $file->className() ?? 'Controller',
                        $method['name'],
                        trim($sink['snippet']),
                        $sink['source'],
                    ),
                    proof: sprintf(
                        "The URL argument of '%s' resolves to client-controlled input (%s) with no in_array() allow-list or validated url rule before the request is dispatched.",
                        trim($sink['snippet']),
                        $sink['source'],
                    ),
                    fix: 'Validate the destination against an explicit allow-list of trusted hosts before requesting it, e.g. reject any URL whose host is not in a configured set, and block private/link-local ranges.',
                );
            }
        }

        return $findings;
    }

    /**
     * Locate the first outbound-request sink whose URL argument is user
     * controlled, returning the matched snippet and the tainting source token.
     *
     * @return array{snippet: string, source: string}|null
     */
    private function findUserControlledSink(string $body): ?array
    {
        $requestVariables = $this->requestSourcedVariables($body);

        foreach (self::SINK_PATTERNS as $pattern) {
            if (! preg_match_all($pattern, $body, $matches, PREG_SET_ORDER)) {
                continue;
            }

            foreach ($matches as $match) {
                $argument = trim($match[1]);
                $source = $this->taintSource($argument, $requestVariables);

                if ($source !== null) {
                    return [
                        'snippet' => trim($match[0]),
                        'source' => $source,
                    ];
                }
            }
        }

        return null;
    }

    /**
     * Determine whether a URL argument expression is user-controlled, returning
     * the source description (the inline request expression or the variable that
     * was assigned from request input), or null when it is safe/constant.
     *
     * @param  array<int, string>  $requestVariables  Local vars assigned from request input
     */
    private function taintSource(string $argument, array $requestVariables): ?string
    {
        if ($this->isInlineRequestInput($argument)) {
            return $argument;
        }

        if (preg_match('/^\$\w+$/', $argument) === 1 && in_array($argument, $requestVariables, true)) {
            return $argument;
        }

        return null;
    }

    /**
     * Whether the expression is request input read inline.
     */
    private function isInlineRequestInput(string $expression): bool
    {
        return (bool) preg_match('/\$request\s*->/', $expression)
            || (bool) preg_match('/\brequest\s*\(/', $expression)
            || (bool) preg_match('/\$request\s*\[/', $expression)
            || (bool) preg_match('/\$_(?:GET|POST|REQUEST)\b/', $expression)
            || (bool) preg_match('/\bInput\s*::/', $expression);
    }

    /**
     * Collect local variables assigned from request input earlier in the method,
     * e.g. `$url = $request->input('url');` → ['$url']. Variables assigned from a
     * safe source (config/route/url/env/constant) are deliberately excluded so a
     * later reassignment to a safe value is not treated as tainted.
     *
     * @return array<int, string>
     */
    private function requestSourcedVariables(string $body): array
    {
        $variables = [];

        if (! preg_match_all('/(\$\w+)\s*=\s*([^;]+);/', $body, $matches, PREG_SET_ORDER)) {
            return [];
        }

        foreach ($matches as $match) {
            $variable = $match[1];
            $rhs = trim($match[2]);

            if ($this->isInlineRequestInput($rhs)) {
                $variables[] = $variable;
            }
        }

        return array_values(array_unique($variables));
    }

    /**
     * Whether the method validates or allow-lists the URL before requesting it.
     */
    private function hasUrlAllowlist(string $body): bool
    {
        return (bool) preg_match('/\bin_array\s*\(/', $body)
            || (bool) preg_match('/\bValidator\s*::\s*make\s*\(/', $body)
            || (bool) preg_match('/->\s*validate\s*\([^)]*[\'"]url[\'"]/s', $body)
            || (bool) preg_match('/[\'"]url[\'"]\s*=>\s*[\'"][^\'"]*\b(?:url|active_url)\b/', $body);
    }

    /**
     * Heuristic: a file is a controller if typed as such or named *Controller.
     */
    private function looksLikeController(SourceFile $file): bool
    {
        if ($file->type === 'controller') {
            return true;
        }

        $class = $file->className();

        return $class !== null && str_ends_with($class, 'Controller');
    }
}
