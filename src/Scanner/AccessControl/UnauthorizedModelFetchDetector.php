<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\AccessControl;

use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * Flags controller actions that fetch a model by a request-supplied id and
 * then expose it without any ownership or authorization check (classic IDOR).
 *
 * Laravel-specific reasoning: Model::find($request->id) or
 * Model::findOrFail($id) resolves a record purely from a client-controlled
 * identifier. If the action then returns/renders that record without an
 * ownership scope (->where('user_id', auth()->id())), a policy/gate call
 * ($this->authorize, Gate::, ->can()), or scoped route-model binding, any
 * authenticated user can read or mutate another user's record by changing the
 * id. This is CWE-639 (IDOR / Broken Access Control, OWASP A01).
 *
 * Conservative design: only flags when ALL of these hold for a method:
 *  - a fetch-by-id sourced from $request/route input is present, AND
 *  - the fetched value is exposed (returned, passed to a view, or json'd), AND
 *  - the method contains NO recognised authorization/ownership guard.
 * Route-model-bound parameters with a matching Policy are treated as guarded
 * (Laravel auto-authorizes via the `can` middleware only when applied — but to
 * stay low-FP we do not flag bound params at all here; the policy/route
 * mismatch detector owns that case).
 */
final class UnauthorizedModelFetchDetector implements AccessControlDetector
{
    private MethodScanner $methods;

    public function __construct(?MethodScanner $methods = null)
    {
        $this->methods = $methods ?? new MethodScanner;
    }

    public function detect(array $files, AccessControlContext $context): array
    {
        $findings = [];

        foreach ($files as $file) {
            if (! $this->looksLikeController($file)) {
                continue;
            }

            foreach ($this->methods->publicMethods($file->content) as $method) {
                $body = $method['body'];

                $parameters = $this->parametersFor($file->content, $method['offset']);

                $requestFetch = $this->findRequestSourcedFetch($body);
                $fetch = $requestFetch ?? $this->findParameterSourcedFetch($body, $parameters);

                if ($fetch === null) {
                    continue;
                }

                if ($this->hasAuthorizationGuard($body) || $this->hasOwnershipScope($body)) {
                    continue;
                }

                // For the request-sourced path the source taint is unambiguous, so
                // any exposure (including destructured fields) is reported. For the
                // method-parameter path we stay stricter and require the model to
                // be exposed DIRECTLY (returned/passed as the object), so that a
                // handler which only reads specific fields — a sensitive-data
                // concern, not an IDOR — does not trigger a duplicate finding.
                $exposed = $requestFetch !== null
                    ? $this->exposesFetchedModel($body, $fetch['variable'])
                    : $this->exposesModelDirectly($body, $fetch['variable']);

                if (! $exposed) {
                    continue;
                }

                $line = $file->lineForOffset($method['offset'] + (int) strpos($body, $fetch['snippet']) + strlen($method['name']));

                $findings[] = new Vulnerability(
                    type: VulnerabilityType::Idor,
                    location: $file->path,
                    line: $line,
                    severity: SeverityLevel::High,
                    description: sprintf(
                        "%s::%s() fetches a %s record using a request-supplied identifier (%s) and then exposes it, with no ownership scope or authorization check in the method. Any authenticated user can access another user's record by changing the id (IDOR).",
                        $file->className() ?? 'Controller',
                        $method['name'],
                        $fetch['model'] ?? 'model',
                        $fetch['snippet'],
                    ),
                    proof: sprintf(
                        "Fetch '%s' is keyed on client input with no \$this->authorize()/Gate/->can() call and no ->where('user_id', auth()->id()) scope before the record is returned.",
                        trim($fetch['snippet']),
                    ),
                    fix: "Authorize the lookup before exposing the record: call \$this->authorize('view', \$model) against a Policy, or scope the query to the owner, e.g. ".'$model = '.($fetch['model'] ?? 'Model')."::where('id', \$id)->where('user_id', auth()->id())->firstOrFail();",
                );
            }
        }

        return $findings;
    }

    /**
     * Locate a fetch-by-id whose identifier comes from request/route input.
     *
     * @return array{snippet: string, variable: string|null, model: string|null}|null
     */
    private function findRequestSourcedFetch(string $body): ?array
    {
        $finders = [
            // Model::find($request->...) / findOrFail(request('id')) / find($request->input(...))
            '/(\$?\w+)\s*=\s*(\w+)::(find|findOrFail)\s*\(\s*(\$request\b[^)]*|request\s*\([^)]*\)|\$request->[^)]*)\)/',
            // where('id', $request->..)->first()
            '/(\$?\w+)\s*=\s*(\w+)::where\s*\(\s*[\'"]id[\'"]\s*,\s*(\$request\b[^)]*|request\s*\([^)]*\))\s*\)\s*->\s*(first|firstOrFail|get)/',
        ];

        foreach ($finders as $pattern) {
            if (preg_match($pattern, $body, $m, PREG_OFFSET_CAPTURE)) {
                return [
                    'snippet' => trim($m[0][0]),
                    'variable' => isset($m[1][0]) && str_starts_with($m[1][0], '$') ? $m[1][0] : null,
                    'model' => $m[2][0] ?? null,
                ];
            }
        }

        // Fetch where the id flows through a local $id assigned from request/route.
        $idFromRequest = (bool) preg_match('/\$id\s*=\s*(\$request->|request\s*\(|\$request\[)/', $body);

        if ($idFromRequest && preg_match('/(\$?\w+)\s*=\s*(\w+)::(find|findOrFail)\s*\(\s*\$id\s*\)/', $body, $m, PREG_OFFSET_CAPTURE)) {
            return [
                'snippet' => trim($m[0][0]),
                'variable' => str_starts_with($m[1][0], '$') ? $m[1][0] : null,
                'model' => $m[2][0] ?? null,
            ];
        }

        return null;
    }

    /**
     * Locate a fetch-by-id whose identifier is a controller/route METHOD
     * PARAMETER (the most common Laravel IDOR shape: `Model::findOrFail($id)`
     * where `show(int $id)`). This is the headline false-negative case.
     *
     * Conservative: the id variable must be a declared method parameter, and we
     * deliberately ignore parameters typed as a Request or as a route-model-bound
     * Eloquent model (those are handled elsewhere / auto-scoped).
     *
     * @param  array<int, array{type: string|null, name: string}>  $parameters
     * @return array{snippet: string, variable: string|null, model: string|null}|null
     */
    private function findParameterSourcedFetch(string $body, array $parameters): ?array
    {
        $idParameters = $this->scalarIdParameters($parameters);

        if ($idParameters === []) {
            return null;
        }

        foreach ($idParameters as $param) {
            $var = preg_quote('$'.$param, '/');

            $patterns = [
                '/(\$?\w+)\s*=\s*(\w+)::(find|findOrFail)\s*\(\s*'.$var.'\s*\)/',
                '/(\$?\w+)\s*=\s*(\w+)::where\s*\(\s*[\'"]id[\'"]\s*,\s*'.$var.'\s*\)\s*->\s*(first|firstOrFail|get)/',
            ];

            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $body, $m, PREG_OFFSET_CAPTURE)) {
                    return [
                        'snippet' => trim($m[0][0]),
                        'variable' => isset($m[1][0]) && str_starts_with($m[1][0], '$') ? $m[1][0] : null,
                        'model' => $m[2][0] ?? null,
                    ];
                }
            }
        }

        return null;
    }

    /**
     * Parameter names that look like a scalar identifier (int/string $id,
     * $postId, $invoice_id) rather than a Request or route-model-bound model.
     *
     * @param  array<int, array{type: string|null, name: string}>  $parameters
     * @return array<int, string>
     */
    private function scalarIdParameters(array $parameters): array
    {
        $ids = [];

        foreach ($parameters as $param) {
            $type = $param['type'] !== null ? strtolower($param['type']) : null;

            if ($type !== null && $type !== 'int' && $type !== 'string' && $type !== '?int' && $type !== '?string') {
                continue;
            }

            $name = strtolower($param['name']);

            if ($name === 'id' || str_ends_with($name, '_id') || str_ends_with($name, 'id')) {
                $ids[] = $param['name'];
            }
        }

        return $ids;
    }

    /**
     * Recover the parameter list (type + name) for a method given its signature
     * offset in the file content.
     *
     * @return array<int, array{type: string|null, name: string}>
     */
    private function parametersFor(string $content, int $signatureOffset): array
    {
        $tail = substr($content, $signatureOffset, 400);

        if (! preg_match('/function\s+\w+\s*\(([^)]*)\)/s', $tail, $m)) {
            return [];
        }

        $raw = trim($m[1]);

        if ($raw === '') {
            return [];
        }

        $parameters = [];

        foreach (explode(',', $raw) as $segment) {
            $segment = trim($segment);

            if ($segment === '') {
                continue;
            }

            if (! preg_match('/^(?:(\??[\\\\\w]+)\s+)?(?:&|\.\.\.)?\$(\w+)/', $segment, $parts)) {
                continue;
            }

            $type = $parts[1] !== '' ? $parts[1] : null;

            if ($type !== null && str_contains($type, '\\')) {
                $pieces = explode('\\', $type);
                $type = end($pieces);
            }

            $parameters[] = [
                'type' => $type,
                'name' => $parts[2],
            ];
        }

        return $parameters;
    }

    /**
     * Whether the method body contains a recognised authorization guard.
     */
    private function hasAuthorizationGuard(string $body): bool
    {
        return (bool) preg_match('/\$this\s*->\s*authorize\s*\(/', $body)
            || (bool) preg_match('/\bGate\s*::\s*(authorize|allows|denies|forbids|any)\s*\(/', $body)
            || (bool) preg_match('/->\s*can(not|t)?\s*\(/', $body)
            || (bool) preg_match('/\bauthorizeResource\b/', $body)
            || (bool) preg_match('/\babort_(if|unless)\s*\([^)]*(auth\(\)|->user\(\)|user->id)/', $body);
    }

    /**
     * Whether the fetch is scoped to the authenticated owner.
     */
    private function hasOwnershipScope(string $body): bool
    {
        return (bool) preg_match('/->\s*where\s*\(\s*[\'"](user_id|owner_id|author_id|account_id|team_id|tenant_id)[\'"]\s*,/', $body)
            || (bool) preg_match('/auth\(\)\s*->\s*user\(\)\s*->\s*\w+\s*\(\)\s*->\s*(find|findOrFail|where)/', $body)
            || (bool) preg_match('/\$request\s*->\s*user\(\)\s*->\s*\w+\s*\(\)\s*->\s*(find|findOrFail|where)/', $body)
            || (bool) preg_match('/(auth\(\)->user\(\)|\$request->user\(\)|\$user)\s*->\s*\w+\(\)\s*->\s*(find|findOrFail|where|firstOrFail)/', $body);
    }

    /**
     * Whether the fetched model variable is exposed to the caller.
     *
     * If we could not capture the assignment variable (e.g. inlined return),
     * treat any return/response that references the fetch as exposure.
     */
    private function exposesFetchedModel(string $body, ?string $variable): bool
    {
        if ($variable === null) {
            return (bool) preg_match('/\breturn\b.*::(find|findOrFail)/s', $body)
                || (bool) preg_match('/(response\(\)->json|view\s*\()/', $body);
        }

        $var = preg_quote($variable, '/');

        return (bool) preg_match('/\breturn\b[^;]*'.$var.'\b/', $body)
            || (bool) preg_match('/(response\(\)\s*->\s*json|view\s*\(|->\s*with|JsonResource|new\s+\w+Resource)\s*\([^;]*'.$var.'\b/', $body)
            || (bool) preg_match('/compact\s*\([^)]*[\'"]'.preg_quote(ltrim($variable, '$'), '/').'[\'"]/', $body);
    }

    /**
     * Stricter exposure test for the method-parameter path: the model object
     * itself must be returned or handed to a view/json/resource — NOT merely
     * read field-by-field. Returning `$user->name` inside an array is a
     * sensitive-data concern handled elsewhere, not an IDOR exposure of the
     * whole record, so we deliberately do not treat it as exposure here.
     */
    private function exposesModelDirectly(string $body, ?string $variable): bool
    {
        if ($variable === null) {
            return (bool) preg_match('/\breturn\b[^;]*::(find|findOrFail)/s', $body);
        }

        $var = preg_quote($variable, '/');

        // return $model;  (optionally wrapped in response()->json($model) etc.)
        if (preg_match('/\breturn\b[^;]*'.$var.'\s*(?![\w>-])/', $body)
            && ! preg_match('/\breturn\b[^;]*'.$var.'\s*->/', $body)) {
            return true;
        }

        // Passed as the whole object to a view / resource / json helper.
        return (bool) preg_match(
            '/(response\(\)\s*->\s*json|view\s*\(|->\s*with|JsonResource|new\s+\w+Resource)\s*\(\s*[^;]*'.$var.'\s*(?![\w>-])/',
            $body,
        ) || (bool) preg_match('/compact\s*\([^)]*[\'"]'.preg_quote(ltrim($variable, '$'), '/').'[\'"]/', $body);
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
