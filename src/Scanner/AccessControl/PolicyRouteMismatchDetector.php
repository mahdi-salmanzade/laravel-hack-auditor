<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\AccessControl;

use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * Flags controller actions on sensitive verbs (store/update/destroy/edit) that
 * operate on a model which HAS a Policy, yet neither call authorize()/can() in
 * the method nor sit behind `can:`/auth-style authorization middleware.
 *
 * Laravel-specific reasoning: declaring a Policy does not enforce it. Laravel
 * only runs the policy when the developer wires it up — via $this->authorize(),
 * Gate::authorize(), $user->can(), authorizeResource() in the constructor, or
 * the `can:ability,model` route middleware. When a Policy exists for a model
 * but a mutating action invokes none of these, the protection is present but
 * unapplied, leaving the endpoint effectively unauthorized (CWE-862 / OWASP
 * A01 Broken Access Control). This is exactly the gap generic SAST/AI miss
 * because it requires correlating Policy existence with route + method wiring.
 *
 * Conservative design: requires (a) a Policy to exist for the model the action
 * touches, (b) the action to be a recognised state-changing verb, and (c) the
 * absence of every known authorization mechanism (in-method call,
 * authorizeResource() in the controller, or `can:` middleware on the route).
 */
final class PolicyRouteMismatchDetector implements AccessControlDetector
{
    private MethodScanner $methods;

    /**
     * Action names that mutate state and therefore warrant authorization.
     *
     * @var array<int, string>
     */
    private const SENSITIVE_ACTIONS = [
        'store', 'update', 'destroy', 'delete', 'edit', 'create',
    ];

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

            $usesAuthorizeResource = $this->controllerAuthorizesResource($file->content);

            $shortClass = $file->className() ?? 'Controller';

            foreach ($this->methods->publicMethods($file->content) as $method) {
                if (! in_array($method['name'], self::SENSITIVE_ACTIONS, true)) {
                    continue;
                }

                $model = $this->modelTouchedBy($method['body'], $file->content, $context, $shortClass);

                if ($model === null || ! $context->hasPolicyFor($model)) {
                    continue;
                }

                if ($usesAuthorizeResource || $this->methodAuthorizes($method['body'])) {
                    continue;
                }

                if ($this->routeHasAuthorizationMiddleware($context, $shortClass, $method['name'])) {
                    continue;
                }

                $findings[] = new Vulnerability(
                    type: VulnerabilityType::AuthBypass,
                    location: $file->path,
                    line: $file->lineForOffset($method['offset']),
                    severity: SeverityLevel::High,
                    description: sprintf(
                        '%s::%s() is a state-changing action on %s, and a %sPolicy exists for that model, but the policy is never applied: the method does not call $this->authorize()/Gate/can(), the controller does not call authorizeResource(), and the route has no `can:`/authorization middleware. The defined Policy is bypassed.',
                        $shortClass,
                        $method['name'],
                        $model,
                        $model,
                    ),
                    proof: sprintf(
                        '%sPolicy exists and defines abilities, but %s::%s() reaches the model without invoking it.',
                        $model,
                        $shortClass,
                        $method['name'],
                    ),
                    fix: sprintf(
                        "Apply the existing policy: add \$this->authorize('%s', \$%s) at the top of %s(), call \$this->authorizeResource(%s::class) in the constructor, or attach the `can:%s,%s` middleware to the route.",
                        $method['name'],
                        strtolower($model),
                        $method['name'],
                        $model,
                        $method['name'],
                        strtolower($model),
                    ),
                );
            }
        }

        return $findings;
    }

    /**
     * Determine which model short-name a method primarily operates on.
     *
     * Collects every candidate model (static Model:: calls and route-model-bound
     * typed parameters) rather than blindly returning the first match, then
     * resolves attribution conservatively to avoid blaming the wrong model:
     *
     *  1. If exactly one distinct candidate is touched, use it.
     *  2. Otherwise prefer the candidate that BOTH has a Policy AND matches the
     *     controller's resource name (PostController -> Post).
     *  3. Otherwise, if exactly one candidate has a Policy, use it.
     *  4. Otherwise attribution is ambiguous -> return null (no finding).
     */
    private function modelTouchedBy(string $body, string $fileContent, AccessControlContext $context, string $shortClass): ?string
    {
        $candidates = $this->candidateModels($body, $fileContent);

        if ($candidates === []) {
            return null;
        }

        if (count($candidates) === 1) {
            return $candidates[0];
        }

        $resource = $this->resourceModelFor($shortClass);

        if ($resource !== null
            && in_array($resource, $candidates, true)
            && $context->hasPolicyFor($resource)) {
            return $resource;
        }

        $withPolicy = array_values(array_filter(
            $candidates,
            static fn (string $model): bool => $context->hasPolicyFor($model),
        ));

        if (count($withPolicy) === 1) {
            return $withPolicy[0];
        }

        return null;
    }

    /**
     * Collect distinct candidate model short-names a method touches.
     *
     * @return array<int, string>
     */
    private function candidateModels(string $body, string $fileContent): array
    {
        $candidates = [];

        if (preg_match_all('/\b([A-Z]\w+)::(find|findOrFail|create|destroy|where|update|firstOrFail)\b/', $body, $matches)) {
            foreach ($matches[1] as $model) {
                $candidates[] = $model;
            }
        }

        if (preg_match('/->\s*(update|delete|save|forceDelete)\s*\(/', $body)) {
            if (preg_match_all('/\(\s*([A-Z]\w+)\s+\$\w+/', $this->signatureFor($body, $fileContent), $sig)) {
                foreach ($sig[1] as $model) {
                    $candidates[] = $model;
                }
            }
        }

        return array_values(array_unique($candidates));
    }

    /**
     * Best-effort resource model name derived from a *Controller class name,
     * e.g. PostController -> Post, AdminPostController -> AdminPost.
     */
    private function resourceModelFor(string $shortClass): ?string
    {
        if (! str_ends_with($shortClass, 'Controller')) {
            return null;
        }

        $resource = substr($shortClass, 0, -strlen('Controller'));

        return $resource !== '' ? $resource : null;
    }

    /**
     * Best-effort: recover a method's parameter signature from the controller
     * source by locating the body within it. Falls back to empty string.
     */
    private function signatureFor(string $body, string $fileContent): string
    {
        $pos = strpos($fileContent, $body);

        if ($pos === false) {
            return '';
        }

        $before = substr($fileContent, max(0, $pos - 200), min(200, $pos));

        if (preg_match('/function\s+\w+\s*\(([^)]*)\)\s*(?::[^{]+)?\{?\s*$/', $before, $m)) {
            return '('.$m[1].')';
        }

        return $before;
    }

    /**
     * Whether the method body invokes any authorization mechanism.
     */
    private function methodAuthorizes(string $body): bool
    {
        return (bool) preg_match('/\$this\s*->\s*authorize\s*\(/', $body)
            || (bool) preg_match('/\bGate\s*::\s*(authorize|allows|denies|forbids|any)\s*\(/', $body)
            || (bool) preg_match('/->\s*can(not|t)?\s*\(/', $body)
            || (bool) preg_match('/abort_(if|unless)\s*\(/', $body)
            || (bool) preg_match('/\$this\s*->\s*authorizeForUser\s*\(/', $body);
    }

    /**
     * Whether the controller wires authorizeResource() (auto-authorizes CRUD).
     */
    private function controllerAuthorizesResource(string $content): bool
    {
        return (bool) preg_match('/\$this\s*->\s*authorizeResource\s*\(/', $content);
    }

    /**
     * Whether the route for this action carries authorization middleware.
     */
    private function routeHasAuthorizationMiddleware(AccessControlContext $context, string $shortClass, string $method): bool
    {
        $route = $context->routeFor($shortClass, $method);

        if ($route === null) {
            return false;
        }

        foreach ($route['middleware'] as $middleware) {
            if (str_starts_with($middleware, 'can:') || str_contains($middleware, 'Authorize')) {
                return true;
            }
        }

        return false;
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
