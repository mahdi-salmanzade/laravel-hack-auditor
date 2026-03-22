<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner;

class ContextCollector
{
    private readonly bool $enabled;

    private readonly bool $includeRoutes;

    private readonly bool $includeMiddleware;

    private readonly bool $includeRateLimiters;

    private readonly bool $includePolicies;

    private readonly bool $includeFormRequests;

    private readonly bool $includeModels;

    private readonly bool $includeConfig;

    private readonly bool $includeEnvironment;

    private readonly int $maxContextTokens;

    /**
     * Create a new ContextCollector instance, reading settings from config.
     */
    public function __construct()
    {
        $this->enabled = (bool) config('hack-auditor.context.enabled', true);
        $this->includeRoutes = (bool) config('hack-auditor.context.include_routes', true);
        $this->includeMiddleware = (bool) config('hack-auditor.context.include_middleware', true);
        $this->includeRateLimiters = (bool) config('hack-auditor.context.include_rate_limiters', true);
        $this->includePolicies = (bool) config('hack-auditor.context.include_policies', true);
        $this->includeFormRequests = (bool) config('hack-auditor.context.include_form_requests', true);
        $this->includeModels = (bool) config('hack-auditor.context.include_models', true);
        $this->includeConfig = (bool) config('hack-auditor.context.include_config', true);
        $this->includeEnvironment = (bool) config('hack-auditor.context.include_environment', true);
        $this->maxContextTokens = (int) config('hack-auditor.context.max_context_tokens', 8000);
    }

    /**
     * Collect security-relevant application context for AI analysis.
     *
     * Gathers routes, middleware, rate limiters, policies, form requests,
     * models, config, and environment info. Returns AppContext::empty()
     * when context collection is disabled via config.
     *
     * @param  array<int, array{path: string, content: string, type: string}>  $controllerFiles
     */
    public function collect(array $controllerFiles = []): AppContext
    {
        if (! $this->enabled) {
            return AppContext::empty();
        }

        $controllerClasses = $this->extractControllerClasses($controllerFiles);
        $controllerContents = array_map(
            fn (array $file): string => $file['content'],
            array_filter($controllerFiles, fn (array $file): bool => $file['type'] === 'controller'),
        );

        $modelClasses = [];
        foreach ($controllerContents as $content) {
            $modelClasses = array_merge($modelClasses, $this->extractModelReferences($content));
        }
        $modelClasses = array_values(array_unique($modelClasses));

        $context = new AppContext(
            routes: $this->includeRoutes ? $this->collectRoutes($controllerClasses) : [],
            middlewareDefinitions: $this->includeMiddleware ? $this->collectMiddlewareDefinitions() : [],
            globalMiddleware: $this->includeMiddleware ? $this->collectGlobalMiddleware() : [],
            rateLimiters: $this->includeRateLimiters ? $this->collectRateLimiters() : [],
            policies: $this->includePolicies ? $this->collectPolicies($modelClasses) : [],
            formRequests: $this->includeFormRequests ? $this->collectFormRequests($controllerContents) : [],
            models: $this->includeModels ? $this->collectModels($modelClasses) : [],
            configContext: $this->includeConfig ? $this->collectConfigContext() : [],
            baseControllerMiddleware: $this->includeMiddleware ? $this->collectBaseControllerMiddleware() : [],
            environment: $this->includeEnvironment ? $this->collectEnvironment() : [],
        );

        return $context->truncateToTokenBudget($this->maxContextTokens);
    }

    /**
     * Collect route definitions that reference the given controller classes.
     *
     * Reads all PHP files in the routes/ directory and uses regex to parse
     * route definitions without booting Laravel's router.
     *
     * @param  array<int, string>  $controllerClasses
     * @return array<string, array{method: string, uri: string, middleware: array<int, string>}>
     */
    private function collectRoutes(array $controllerClasses): array
    {
        $routesPath = base_path('routes');

        if (! is_dir($routesPath)) {
            return [];
        }

        $files = glob($routesPath.DIRECTORY_SEPARATOR.'*.php');

        if ($files === false || $files === []) {
            return [];
        }

        $shortClassMap = [];
        foreach ($controllerClasses as $fqcn) {
            $parts = explode('\\', $fqcn);
            $shortClassMap[end($parts)] = $fqcn;
        }

        if ($shortClassMap === []) {
            return [];
        }

        $results = [];

        foreach ($files as $filePath) {
            $content = $this->readFile($filePath);

            if ($content === '') {
                continue;
            }

            $groupBoundaries = $this->findRouteGroupBoundaries($content);

            $this->parseExplicitRoutes($content, $shortClassMap, $groupBoundaries, $results);
            $this->parseResourceRoutes($content, $shortClassMap, $groupBoundaries, $results);
            $this->parseApiResourceRoutes($content, $shortClassMap, $groupBoundaries, $results);
            $this->parseControllerGroupRoutes($content, $shortClassMap, $groupBoundaries, $results);
        }

        return $results;
    }

    /**
     * Parse explicit route definitions (Route::get, Route::post, etc.).
     *
     * @param  array<string, string>  $shortClassMap
     * @param  array<int, array{middleware: array<int, string>, start: int, end: int}>  $groupBoundaries
     * @param  array<string, array{method: string, uri: string, middleware: array<int, string>}>  $results
     */
    private function parseExplicitRoutes(string $content, array $shortClassMap, array $groupBoundaries, array &$results): void
    {
        $httpMethods = 'get|post|put|patch|delete|options|any';

        foreach ($shortClassMap as $shortClass => $fqcn) {
            $controllerPattern = preg_quote($shortClass, '/');

            // Array syntax: Route::get('/path', [Controller::class, 'method'])
            $pattern = '/Route\s*::\s*('.$httpMethods.')\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*\['
                .'\s*'.$controllerPattern.'\s*::\s*class\s*,\s*[\'"]([^\'"]+)[\'"]\s*'
                .'\]\s*\)([^;]*);/i';

            if (preg_match_all($pattern, $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
                foreach ($matches as $match) {
                    $httpMethod = strtoupper($match[1][0]);
                    $uri = '/'.ltrim($match[2][0], '/');
                    $methodName = $match[3][0];
                    $chain = $match[4][0];
                    $position = $match[0][1];

                    $routeMiddleware = $this->parseChainedMiddleware($chain);
                    $groupMiddleware = $this->getMiddlewareForPosition($position, $groupBoundaries);
                    $allMiddleware = array_values(array_unique(array_merge($groupMiddleware, $routeMiddleware)));

                    $results["{$fqcn}@{$methodName}"] = [
                        'method' => $httpMethod,
                        'uri' => $uri,
                        'middleware' => $allMiddleware,
                    ];
                }
            }

            // String syntax: Route::get('/path', 'Controller@method')
            $stringPattern = '/Route\s*::\s*('.$httpMethods.')\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*[\'"]'
                .'[^\'"]*(\\\\)?'.$controllerPattern.'@([^\'"]+)[\'"]\s*\)([^;]*);/i';

            if (preg_match_all($stringPattern, $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
                foreach ($matches as $match) {
                    $httpMethod = strtoupper($match[1][0]);
                    $uri = '/'.ltrim($match[2][0], '/');
                    $methodName = $match[4][0];
                    $chain = $match[5][0] ?? '';
                    $position = $match[0][1];

                    $routeMiddleware = $this->parseChainedMiddleware($chain);
                    $groupMiddleware = $this->getMiddlewareForPosition($position, $groupBoundaries);
                    $allMiddleware = array_values(array_unique(array_merge($groupMiddleware, $routeMiddleware)));

                    $results["{$fqcn}@{$methodName}"] = [
                        'method' => $httpMethod,
                        'uri' => $uri,
                        'middleware' => $allMiddleware,
                    ];
                }
            }
        }
    }

    /**
     * Parse Route::resource() definitions.
     *
     * @param  array<string, string>  $shortClassMap
     * @param  array<int, array{middleware: array<int, string>, start: int, end: int}>  $groupBoundaries
     * @param  array<string, array{method: string, uri: string, middleware: array<int, string>}>  $results
     */
    private function parseResourceRoutes(string $content, array $shortClassMap, array $groupBoundaries, array &$results): void
    {
        foreach ($shortClassMap as $shortClass => $fqcn) {
            $controllerPattern = preg_quote($shortClass, '/');

            $pattern = '/Route\s*::\s*resource\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*'
                .$controllerPattern.'\s*::\s*class\s*\)([^;]*);/i';

            if (! preg_match_all($pattern, $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
                continue;
            }

            foreach ($matches as $match) {
                $uri = '/'.ltrim($match[1][0], '/');
                $chain = $match[2][0];
                $position = $match[0][1];
                $param = $this->resourceParam($uri);

                $routeMiddleware = $this->parseChainedMiddleware($chain);
                $groupMiddleware = $this->getMiddlewareForPosition($position, $groupBoundaries);
                $allMiddleware = array_values(array_unique(array_merge($groupMiddleware, $routeMiddleware)));

                $resourceMethods = [
                    'index' => ['GET', $uri],
                    'create' => ['GET', "{$uri}/create"],
                    'store' => ['POST', $uri],
                    'show' => ['GET', "{$uri}/{{$param}}"],
                    'edit' => ['GET', "{$uri}/{{$param}}/edit"],
                    'update' => ['PUT', "{$uri}/{{$param}}"],
                    'destroy' => ['DELETE', "{$uri}/{{$param}}"],
                ];

                foreach ($resourceMethods as $method => [$httpMethod, $routeUri]) {
                    $results["{$fqcn}@{$method}"] = [
                        'method' => $httpMethod,
                        'uri' => $routeUri,
                        'middleware' => $allMiddleware,
                    ];
                }
            }
        }
    }

    /**
     * Parse Route::apiResource() definitions.
     *
     * @param  array<string, string>  $shortClassMap
     * @param  array<int, array{middleware: array<int, string>, start: int, end: int}>  $groupBoundaries
     * @param  array<string, array{method: string, uri: string, middleware: array<int, string>}>  $results
     */
    private function parseApiResourceRoutes(string $content, array $shortClassMap, array $groupBoundaries, array &$results): void
    {
        foreach ($shortClassMap as $shortClass => $fqcn) {
            $controllerPattern = preg_quote($shortClass, '/');

            $pattern = '/Route\s*::\s*apiResource\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*'
                .$controllerPattern.'\s*::\s*class\s*\)([^;]*);/i';

            if (! preg_match_all($pattern, $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
                continue;
            }

            foreach ($matches as $match) {
                $uri = '/'.ltrim($match[1][0], '/');
                $chain = $match[2][0];
                $position = $match[0][1];
                $param = $this->resourceParam($uri);

                $routeMiddleware = $this->parseChainedMiddleware($chain);
                $groupMiddleware = $this->getMiddlewareForPosition($position, $groupBoundaries);
                $allMiddleware = array_values(array_unique(array_merge($groupMiddleware, $routeMiddleware)));

                $resourceMethods = [
                    'index' => ['GET', $uri],
                    'store' => ['POST', $uri],
                    'show' => ['GET', "{$uri}/{{$param}}"],
                    'update' => ['PUT', "{$uri}/{{$param}}"],
                    'destroy' => ['DELETE', "{$uri}/{{$param}}"],
                ];

                foreach ($resourceMethods as $method => [$httpMethod, $routeUri]) {
                    $results["{$fqcn}@{$method}"] = [
                        'method' => $httpMethod,
                        'uri' => $routeUri,
                        'middleware' => $allMiddleware,
                    ];
                }
            }
        }
    }

    /**
     * Parse Route::controller(Controller::class)->group() definitions.
     *
     * @param  array<string, string>  $shortClassMap
     * @param  array<int, array{middleware: array<int, string>, start: int, end: int}>  $groupBoundaries
     * @param  array<string, array{method: string, uri: string, middleware: array<int, string>}>  $results
     */
    private function parseControllerGroupRoutes(string $content, array $shortClassMap, array $groupBoundaries, array &$results): void
    {
        $httpMethods = 'get|post|put|patch|delete|options|any';

        foreach ($shortClassMap as $shortClass => $fqcn) {
            $controllerPattern = preg_quote($shortClass, '/');

            $pattern = '/Route\s*::\s*controller\s*\(\s*'.$controllerPattern.'\s*::\s*class\s*\)/s';

            if (! preg_match_all($pattern, $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
                continue;
            }

            foreach ($matches as $match) {
                $matchEnd = $match[0][1] + strlen($match[0][0]);

                $groupOpenBrace = $this->findGroupCallAfter($content, $matchEnd);

                if ($groupOpenBrace === null) {
                    continue;
                }

                $closingBrace = $this->findMatchingBrace($content, $groupOpenBrace);

                if ($closingBrace === null) {
                    continue;
                }

                $chainBetween = substr($content, $matchEnd, $groupOpenBrace - $matchEnd);
                $controllerGroupMiddleware = $this->parseChainedMiddleware($chainBetween);

                $parentGroupMiddleware = $this->getMiddlewareForPosition($match[0][1], $groupBoundaries);
                $combinedGroupMiddleware = array_values(array_unique(
                    array_merge($parentGroupMiddleware, $controllerGroupMiddleware)
                ));

                $groupBody = substr($content, $groupOpenBrace + 1, $closingBrace - $groupOpenBrace - 1);

                $routePattern = '/Route\s*::\s*('.$httpMethods.')\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)([^;]*);/i';

                if (preg_match_all($routePattern, $groupBody, $routeMatches, PREG_SET_ORDER)) {
                    foreach ($routeMatches as $routeMatch) {
                        $httpMethod = strtoupper($routeMatch[1]);
                        $uri = '/'.ltrim($routeMatch[2], '/');
                        $methodName = $routeMatch[3];
                        $chain = $routeMatch[4] ?? '';

                        $routeMiddleware = $this->parseChainedMiddleware($chain);
                        $allMiddleware = array_values(array_unique(
                            array_merge($combinedGroupMiddleware, $routeMiddleware)
                        ));

                        $results["{$fqcn}@{$methodName}"] = [
                            'method' => $httpMethod,
                            'uri' => $uri,
                            'middleware' => $allMiddleware,
                        ];
                    }
                }
            }
        }
    }

    /**
     * Collect middleware definitions from Kernel.php or bootstrap/app.php.
     *
     * @return array<string, string>
     */
    private function collectMiddlewareDefinitions(): array
    {
        $definitions = [];

        // Laravel 11+ bootstrap/app.php
        if ($this->fileExists('bootstrap/app.php')) {
            $content = $this->readFile(base_path('bootstrap/app.php'));

            if (str_contains($content, '->withMiddleware(')) {
                $this->parseBootstrapMiddlewareDefinitions($content, $definitions);
            }
        }

        // Laravel 10- Kernel.php
        if ($this->fileExists('app/Http/Kernel.php')) {
            $content = $this->readFile(base_path('app/Http/Kernel.php'));
            $this->parseKernelMiddlewareDefinitions($content, $definitions);
        }

        // Custom middleware files
        $middlewarePath = base_path('app/Http/Middleware');

        if (is_dir($middlewarePath)) {
            $files = glob($middlewarePath.DIRECTORY_SEPARATOR.'*.php');

            if ($files !== false) {
                foreach ($files as $file) {
                    $content = $this->readFile($file);

                    if ($content === '') {
                        continue;
                    }

                    $className = $this->extractClassNameFromContent($content);

                    if ($className === null) {
                        continue;
                    }

                    $summary = $this->summarizeMiddlewareHandle($content);
                    $definitions[$className] = $summary;
                }
            }
        }

        return $definitions;
    }

    /**
     * Parse middleware definitions from Kernel.php arrays.
     *
     * @param  array<string, string>  $definitions
     */
    private function parseKernelMiddlewareDefinitions(string $content, array &$definitions): void
    {
        // $middlewareAliases or $routeMiddleware
        foreach (['middlewareAliases', 'routeMiddleware'] as $property) {
            if (preg_match('/\$'.$property.'\s*=\s*\[(.*?)\];/s', $content, $match)) {
                if (preg_match_all("/['\"]([^'\"]+)['\"]\s*=>\s*([^,\]]+)/", $match[1], $aliasMatches, PREG_SET_ORDER)) {
                    foreach ($aliasMatches as $aliasMatch) {
                        $alias = $aliasMatch[1];
                        $class = trim($aliasMatch[2]);
                        $class = preg_replace('/::class$/', '', $class) ?? $class;
                        $parts = explode('\\', $class);
                        $definitions[$alias] = end($parts).' middleware';
                    }
                }
            }
        }

        // $middlewareGroups
        if (preg_match('/\$middlewareGroups\s*=\s*\[(.*?)\];/s', $content, $match)) {
            if (preg_match_all("/['\"]([^'\"]+)['\"]\s*=>\s*\[([^\]]*)\]/s", $match[1], $groupMatches, PREG_SET_ORDER)) {
                foreach ($groupMatches as $groupMatch) {
                    $groupName = $groupMatch[1];
                    $groupContent = $groupMatch[2];
                    $middlewareCount = substr_count($groupContent, '::class') + preg_match_all("/['\"][^'\"]+['\"]/", $groupContent);
                    $definitions[$groupName] = "Middleware group ({$middlewareCount} items)";
                }
            }
        }
    }

    /**
     * Parse middleware definitions from bootstrap/app.php withMiddleware() closure.
     *
     * @param  array<string, string>  $definitions
     */
    private function parseBootstrapMiddlewareDefinitions(string $content, array &$definitions): void
    {
        if (preg_match('/->withMiddleware\s*\(\s*function\s*\([^)]*\)\s*\{(.*?)\}\s*\)/s', $content, $match)) {
            $middlewareBody = $match[1];

            // Look for ->alias() calls
            if (preg_match_all("/->alias\s*\(\s*\[(.*?)\]\s*\)/s", $middlewareBody, $aliasMatches)) {
                foreach ($aliasMatches[1] as $aliasContent) {
                    if (preg_match_all("/['\"]([^'\"]+)['\"]\s*=>\s*([^,\]]+)/", $aliasContent, $pairs, PREG_SET_ORDER)) {
                        foreach ($pairs as $pair) {
                            $alias = $pair[1];
                            $class = trim($pair[2]);
                            $class = preg_replace('/::class$/', '', $class) ?? $class;
                            $parts = explode('\\', $class);
                            $definitions[$alias] = end($parts).' middleware';
                        }
                    }
                }
            }

            // Look for ->append() or ->prepend() or ->use() calls
            foreach (['append', 'prepend', 'use'] as $method) {
                if (preg_match_all('/->'.$method.'\s*\(\s*\[([^\]]*)\]/s', $middlewareBody, $appendMatches)) {
                    foreach ($appendMatches[1] as $appendContent) {
                        if (preg_match_all('/([A-Z][\w\\\\]+)::class/', $appendContent, $classMatches)) {
                            foreach ($classMatches[1] as $class) {
                                $parts = explode('\\', $class);
                                $shortName = end($parts);
                                $definitions[$shortName] = "{$shortName} middleware (global)";
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Collect global middleware from Kernel.php or bootstrap/app.php.
     *
     * @return array<int, string>
     */
    private function collectGlobalMiddleware(): array
    {
        $middleware = [];

        // Laravel 10- Kernel.php
        if ($this->fileExists('app/Http/Kernel.php')) {
            $content = $this->readFile(base_path('app/Http/Kernel.php'));

            if (preg_match('/\$middleware\s*=\s*\[(.*?)\];/s', $content, $match)) {
                if (preg_match_all('/([A-Z][\w\\\\]+)::class/', $match[1], $classMatches)) {
                    foreach ($classMatches[1] as $class) {
                        $parts = explode('\\', $class);
                        $middleware[] = end($parts);
                    }
                }
            }
        }

        // Laravel 11+ bootstrap/app.php
        if ($this->fileExists('bootstrap/app.php')) {
            $content = $this->readFile(base_path('bootstrap/app.php'));

            if (preg_match('/->withMiddleware\s*\(\s*function\s*\([^)]*\)\s*\{(.*?)\}\s*\)/s', $content, $match)) {
                $body = $match[1];

                // ->use([...]) replaces global middleware
                if (preg_match_all('/->use\s*\(\s*\[([^\]]*)\]/s', $body, $useMatches)) {
                    foreach ($useMatches[1] as $useContent) {
                        if (preg_match_all('/([A-Z][\w\\\\]+)::class/', $useContent, $classMatches)) {
                            foreach ($classMatches[1] as $class) {
                                $parts = explode('\\', $class);
                                $middleware[] = end($parts);
                            }
                        }
                    }
                }

                // ->append() adds to global middleware
                if (preg_match_all('/->append\s*\(\s*\[([^\]]*)\]/s', $body, $appendMatches)) {
                    foreach ($appendMatches[1] as $appendContent) {
                        if (preg_match_all('/([A-Z][\w\\\\]+)::class/', $appendContent, $classMatches)) {
                            foreach ($classMatches[1] as $class) {
                                $parts = explode('\\', $class);
                                $middleware[] = end($parts);
                            }
                        }
                    }
                }

                // ->prepend() adds to start of global middleware
                if (preg_match_all('/->prepend\s*\(\s*\[([^\]]*)\]/s', $body, $prependMatches)) {
                    foreach ($prependMatches[1] as $prependContent) {
                        if (preg_match_all('/([A-Z][\w\\\\]+)::class/', $prependContent, $classMatches)) {
                            foreach ($classMatches[1] as $class) {
                                $parts = explode('\\', $class);
                                $middleware[] = end($parts);
                            }
                        }
                    }
                }
            }
        }

        return array_values(array_unique($middleware));
    }

    /**
     * Collect rate limiter definitions from service providers.
     *
     * @return array<string, string>
     */
    private function collectRateLimiters(): array
    {
        $providersPath = base_path('app/Providers');

        if (! is_dir($providersPath)) {
            return [];
        }

        $files = glob($providersPath.DIRECTORY_SEPARATOR.'*.php');

        if ($files === false || $files === []) {
            return [];
        }

        $limiters = [];

        foreach ($files as $file) {
            $content = $this->readFile($file);

            if ($content === '' || ! str_contains($content, 'RateLimiter::for(')) {
                continue;
            }

            // Match RateLimiter::for('name', function (...) { ... })
            if (preg_match_all("/RateLimiter\s*::\s*for\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*function\s*\([^)]*\)\s*\{([^}]+)\}/s", $content, $matches, PREG_SET_ORDER)) {
                foreach ($matches as $match) {
                    $name = $match[1];
                    $body = $match[2];
                    $description = $this->describeRateLimiter($body);
                    $limiters[$name] = $description;
                }
            }

            // Also handle arrow function syntax: RateLimiter::for('name', fn ($request) => Limit::perMinute(60))
            if (preg_match_all("/RateLimiter\s*::\s*for\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*fn\s*\([^)]*\)\s*=>\s*([^;)]+)/s", $content, $matches, PREG_SET_ORDER)) {
                foreach ($matches as $match) {
                    $name = $match[1];
                    $body = $match[2];

                    if (! isset($limiters[$name])) {
                        $description = $this->describeRateLimiter($body);
                        $limiters[$name] = $description;
                    }
                }
            }
        }

        return $limiters;
    }

    /**
     * Describe a rate limiter from its closure body.
     */
    private function describeRateLimiter(string $body): string
    {
        // Try to find Limit::perMinute(N), Limit::perHour(N), etc.
        if (preg_match('/Limit\s*::\s*per(Minute|Hour|Day)\s*\(\s*(\d+)\s*\)/', $body, $match)) {
            $period = strtolower($match[1]);

            return "{$match[2]} per {$period}";
        }

        // Try to find Limit::none()
        if (str_contains($body, 'Limit::none()')) {
            return 'unlimited';
        }

        // Check for ->by() to see if it's per-IP or per-user
        $suffix = '';

        if (preg_match('/->by\s*\(\s*\$\w+->ip\s*\(\s*\)\s*\)/', $body)) {
            $suffix = ' per IP';
        } elseif (preg_match('/->by\s*\(\s*\$\w+->user\s*\(\s*\)/', $body)) {
            $suffix = ' per user';
        }

        if (preg_match('/Limit\s*::\s*per(Minute|Hour|Day)\s*\(\s*(\d+)\s*\)/', $body, $match)) {
            $period = strtolower($match[1]);

            return "{$match[2]} per {$period}{$suffix}";
        }

        return 'custom rate limit';
    }

    /**
     * Collect policy information for the given model classes.
     *
     * @param  array<int, string>  $modelClasses
     * @return array<string, array{policy: string, methods: array<int, string>, ownership_check: bool}>
     */
    private function collectPolicies(array $modelClasses): array
    {
        $policiesPath = base_path('app/Policies');

        if (! is_dir($policiesPath) || $modelClasses === []) {
            return [];
        }

        $files = glob($policiesPath.DIRECTORY_SEPARATOR.'*.php');

        if ($files === false || $files === []) {
            return [];
        }

        // Build mapping of short model name to FQCN
        $modelShortMap = [];
        foreach ($modelClasses as $fqcn) {
            $parts = explode('\\', $fqcn);
            $modelShortMap[end($parts)] = $fqcn;
        }

        $policies = [];

        // Check AuthServiceProvider for explicit policy mappings
        $explicitMappings = $this->parseExplicitPolicyMappings();

        foreach ($files as $file) {
            $content = $this->readFile($file);

            if ($content === '') {
                continue;
            }

            $policyClass = $this->extractClassNameFromContent($content);

            if ($policyClass === null) {
                continue;
            }

            // Determine which model this policy is for
            $modelFqcn = $this->resolvePolicyModel($policyClass, $content, $modelShortMap, $explicitMappings);

            if ($modelFqcn === null) {
                continue;
            }

            // Extract policy methods
            $methods = [];

            if (preg_match_all('/public\s+function\s+(\w+)\s*\(/', $content, $methodMatches)) {
                $methods = $methodMatches[1];
            }

            // Check for ownership patterns
            $ownershipCheck = (bool) preg_match('/\$user->id\s*===?\s*\$\w+->user_id/', $content)
                || (bool) preg_match('/\$\w+->user_id\s*===?\s*\$user->id/', $content)
                || str_contains($content, '->is($')
                || str_contains($content, 'Gate::');

            $policies[$modelFqcn] = [
                'policy' => $policyClass,
                'methods' => $methods,
                'ownership_check' => $ownershipCheck,
            ];
        }

        return $policies;
    }

    /**
     * Resolve which model a policy class belongs to.
     *
     * @param  array<string, string>  $modelShortMap
     * @param  array<string, string>  $explicitMappings
     */
    private function resolvePolicyModel(string $policyClass, string $content, array $modelShortMap, array $explicitMappings): ?string
    {
        // Check explicit mappings first
        foreach ($explicitMappings as $modelFqcn => $mappedPolicy) {
            if (str_contains($mappedPolicy, $policyClass)) {
                if (isset($modelShortMap[class_basename($modelFqcn)]) || in_array($modelFqcn, $modelShortMap, true)) {
                    return $modelFqcn;
                }
            }
        }

        // Convention: PostPolicy => Post model
        $inferredModel = preg_replace('/Policy$/', '', $policyClass);

        if ($inferredModel !== null && isset($modelShortMap[$inferredModel])) {
            return $modelShortMap[$inferredModel];
        }

        // Check use statements for model imports
        if (preg_match_all('/use\s+([\w\\\\]+);/', $content, $useMatches)) {
            foreach ($useMatches[1] as $use) {
                if (str_contains($use, 'Models\\')) {
                    $parts = explode('\\', $use);
                    $shortName = end($parts);

                    if (isset($modelShortMap[$shortName])) {
                        return $modelShortMap[$shortName];
                    }
                }
            }
        }

        return null;
    }

    /**
     * Parse explicit policy mappings from AuthServiceProvider or Gate::define().
     *
     * @return array<string, string>
     */
    private function parseExplicitPolicyMappings(): array
    {
        $mappings = [];

        // Check AuthServiceProvider
        $authProviderPath = base_path('app/Providers/AuthServiceProvider.php');

        if (file_exists($authProviderPath)) {
            $content = $this->readFile($authProviderPath);

            if (preg_match('/\$policies\s*=\s*\[(.*?)\];/s', $content, $match)) {
                if (preg_match_all('/([A-Z][\w\\\\]+)::class\s*=>\s*([A-Z][\w\\\\]+)::class/', $match[1], $policyMatches, PREG_SET_ORDER)) {
                    foreach ($policyMatches as $policyMatch) {
                        $mappings[$policyMatch[1]] = $policyMatch[2];
                    }
                }
            }
        }

        // Check for Gate::policy() in service providers
        $providersPath = base_path('app/Providers');

        if (is_dir($providersPath)) {
            $files = glob($providersPath.DIRECTORY_SEPARATOR.'*.php');

            if ($files !== false) {
                foreach ($files as $file) {
                    $content = $this->readFile($file);

                    if (preg_match_all('/Gate\s*::\s*policy\s*\(\s*([A-Z][\w\\\\]+)::class\s*,\s*([A-Z][\w\\\\]+)::class\s*\)/', $content, $gateMatches, PREG_SET_ORDER)) {
                        foreach ($gateMatches as $gateMatch) {
                            $mappings[$gateMatch[1]] = $gateMatch[2];
                        }
                    }
                }
            }
        }

        return $mappings;
    }

    /**
     * Collect FormRequest information referenced by controller files.
     *
     * @param  array<int, string>  $controllerContents
     * @return array<string, array{authorize: string, rules: array<string, string>}>
     */
    private function collectFormRequests(array $controllerContents): array
    {
        $formRequests = [];
        $seen = [];

        foreach ($controllerContents as $content) {
            $requestClasses = $this->extractFormRequestTypeHints($content);

            foreach ($requestClasses as $fqcn) {
                if (isset($seen[$fqcn])) {
                    continue;
                }

                $seen[$fqcn] = true;
                $filePath = $this->resolveClassPath($fqcn);

                if ($filePath === null || ! file_exists($filePath)) {
                    continue;
                }

                $requestContent = $this->readFile($filePath);

                if ($requestContent === '') {
                    continue;
                }

                $authorize = $this->parseAuthorizeMethod($requestContent);
                $rules = $this->parseRulesMethod($requestContent);

                $formRequests[$fqcn] = [
                    'authorize' => $authorize,
                    'rules' => $rules,
                ];
            }
        }

        return $formRequests;
    }

    /**
     * Parse the authorize() method from a FormRequest file.
     */
    private function parseAuthorizeMethod(string $content): string
    {
        // Match authorize() method body
        if (preg_match('/function\s+authorize\s*\(\s*\)\s*(?::\s*bool\s*)?\{(.*?)\}/s', $content, $match)) {
            $body = trim($match[1]);

            if (preg_match('/return\s+true\s*;/', $body)) {
                return 'returns true';
            }

            if (preg_match('/return\s+false\s*;/', $body)) {
                return 'returns false';
            }

            // Summarize the logic
            $body = preg_replace('/\s+/', ' ', $body) ?? $body;

            if (strlen($body) > 200) {
                $body = substr($body, 0, 200).'...';
            }

            return $body;
        }

        return 'not defined (defaults to false)';
    }

    /**
     * Parse the rules() method from a FormRequest file.
     *
     * @return array<string, string>
     */
    private function parseRulesMethod(string $content): array
    {
        // Match rules() method body
        if (! preg_match('/function\s+rules\s*\(\s*\)\s*(?::\s*array\s*)?\{(.*?)\}/s', $content, $match)) {
            return [];
        }

        $body = $match[1];

        // Try to extract the return array
        if (! preg_match('/return\s*\[(.*)\]\s*;/s', $body, $arrayMatch)) {
            return [];
        }

        $rules = [];
        $arrayContent = $arrayMatch[1];

        // Parse 'field' => 'rules' or 'field' => ['rule1', 'rule2']
        if (preg_match_all("/['\"]([^'\"]+)['\"]\s*=>\s*(?:['\"]([^'\"]+)['\"]|\[([^\]]+)\])/", $arrayContent, $ruleMatches, PREG_SET_ORDER)) {
            foreach ($ruleMatches as $ruleMatch) {
                $field = $ruleMatch[1];
                $rule = ! empty($ruleMatch[2]) ? $ruleMatch[2] : trim($ruleMatch[3]);
                $rules[$field] = $rule;
            }
        }

        return $rules;
    }

    /**
     * Collect model metadata for models referenced by scanned controllers.
     *
     * @param  array<int, string>  $modelClasses
     * @return array<string, array{fillable: array<int, string>, hidden: array<int, string>, guarded: array<int, string>, casts: array<string, string>, traits: array<int, string>, global_scopes: array<int, string>}>
     */
    private function collectModels(array $modelClasses): array
    {
        $modelsPath = base_path('app/Models');

        if (! is_dir($modelsPath) || $modelClasses === []) {
            return [];
        }

        // Build short name => FQCN map
        $modelShortMap = [];
        foreach ($modelClasses as $fqcn) {
            $parts = explode('\\', $fqcn);
            $modelShortMap[end($parts)] = $fqcn;
        }

        $models = [];

        $files = glob($modelsPath.DIRECTORY_SEPARATOR.'*.php');

        if ($files === false || $files === []) {
            return [];
        }

        foreach ($files as $file) {
            $content = $this->readFile($file);

            if ($content === '') {
                continue;
            }

            $className = $this->extractClassNameFromContent($content);

            if ($className === null || ! isset($modelShortMap[$className])) {
                continue;
            }

            $fqcn = $modelShortMap[$className];

            $fillable = $this->parsePhpArray($content, 'fillable');
            $hidden = $this->parsePhpArray($content, 'hidden');
            $guarded = $this->parsePhpArray($content, 'guarded');
            $casts = $this->parsePhpAssociativeArray($content, 'casts');
            $traits = $this->extractTraits($content);
            $globalScopes = $this->extractGlobalScopes($content);

            $models[$fqcn] = [
                'fillable' => $fillable,
                'hidden' => $hidden,
                'guarded' => $guarded,
                'casts' => $casts,
                'traits' => $traits,
                'global_scopes' => $globalScopes,
            ];
        }

        return $models;
    }

    /**
     * Collect security-relevant configuration values.
     *
     * @return array<string, mixed>
     */
    private function collectConfigContext(): array
    {
        $context = [];

        // auth.php
        $authPath = base_path('config/auth.php');

        if (file_exists($authPath)) {
            $content = $this->readFile($authPath);

            if ($content !== '') {
                $guards = [];

                if (preg_match_all("/['\"](\w+)['\"]\s*=>\s*\[[\s\S]*?['\"]driver['\"]\s*=>\s*['\"](\w+)['\"]/", $content, $guardMatches, PREG_SET_ORDER)) {
                    foreach ($guardMatches as $guardMatch) {
                        $guards[$guardMatch[1]] = $guardMatch[2];
                    }
                }

                if ($guards !== []) {
                    $context['auth_guards'] = $guards;
                }
            }
        }

        // cors.php
        $corsPath = base_path('config/cors.php');

        if (file_exists($corsPath)) {
            $content = $this->readFile($corsPath);

            if ($content !== '') {
                if (preg_match("/['\"]allowed_origins['\"]\s*=>\s*\[([^\]]*)\]/", $content, $corsMatch)) {
                    $origins = [];

                    if (preg_match_all("/['\"]([^'\"]+)['\"]/", $corsMatch[1], $originMatches)) {
                        $origins = $originMatches[1];
                    }

                    if ($origins !== []) {
                        $context['cors_allowed_origins'] = $origins;
                    }
                }
            }
        }

        // session.php
        $sessionPath = base_path('config/session.php');

        if (file_exists($sessionPath)) {
            $content = $this->readFile($sessionPath);

            if ($content !== '') {
                $sessionConfig = [];

                if (preg_match("/['\"]secure['\"]\s*=>\s*(true|false|null|env\([^)]+\))/", $content, $secureMatch)) {
                    $sessionConfig['secure'] = $secureMatch[1];
                }

                if (preg_match("/['\"]http_only['\"]\s*=>\s*(true|false)/", $content, $httpOnlyMatch)) {
                    $sessionConfig['http_only'] = $httpOnlyMatch[1];
                }

                if (preg_match("/['\"]same_site['\"]\s*=>\s*['\"]?(\w+)['\"]?/", $content, $sameSiteMatch)) {
                    $sessionConfig['same_site'] = $sameSiteMatch[1];
                }

                if ($sessionConfig !== []) {
                    $context['session'] = $sessionConfig;
                }
            }
        }

        // sanctum.php
        $sanctumPath = base_path('config/sanctum.php');

        if (file_exists($sanctumPath)) {
            $content = $this->readFile($sanctumPath);

            if ($content !== '') {
                $sanctumConfig = [];

                if (preg_match("/['\"]expiration['\"]\s*=>\s*(\d+|null)/", $content, $expirationMatch)) {
                    $sanctumConfig['token_expiration'] = $expirationMatch[1];
                }

                if (preg_match("/['\"]stateful['\"]\s*=>\s*\[?\s*([^\]]*)\]?/", $content, $statefulMatch)) {
                    $sanctumConfig['stateful_configured'] = true;
                }

                if ($sanctumConfig !== []) {
                    $context['sanctum'] = $sanctumConfig;
                }
            }
        }

        return $context;
    }

    /**
     * Collect middleware defined in the base Controller constructor.
     *
     * @return array<string, array<int, string>>
     */
    private function collectBaseControllerMiddleware(): array
    {
        $controllerPath = base_path('app/Http/Controllers/Controller.php');

        if (! file_exists($controllerPath)) {
            return [];
        }

        $content = $this->readFile($controllerPath);

        if ($content === '') {
            return [];
        }

        $middleware = [];

        // Look for $this->middleware(...) calls
        if (preg_match_all('/\$this\s*->\s*middleware\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)/', $content, $matches)) {
            foreach ($matches[1] as $mw) {
                $middleware[] = $mw;
            }
        }

        // Also check for array syntax: $this->middleware(['auth', 'verified'])
        if (preg_match_all('/\$this\s*->\s*middleware\s*\(\s*\[([^\]]+)\]\s*\)/', $content, $matches)) {
            foreach ($matches[1] as $arrayContent) {
                if (preg_match_all("/['\"]([^'\"]+)['\"]/", $arrayContent, $mwMatches)) {
                    $middleware = array_merge($middleware, $mwMatches[1]);
                }
            }
        }

        if ($middleware === []) {
            return [];
        }

        return ['Controller' => array_values(array_unique($middleware))];
    }

    /**
     * Collect environment information from .env file.
     *
     * @return array<string, string>
     */
    private function collectEnvironment(): array
    {
        $envPath = base_path('.env');

        if (! file_exists($envPath)) {
            return [];
        }

        $content = $this->readFile($envPath);

        if ($content === '') {
            return [];
        }

        $environment = [];

        if (preg_match('/^APP_ENV\s*=\s*(.+)$/m', $content, $match)) {
            $environment['app_env'] = trim($match[1]);
        }

        if (preg_match('/^APP_DEBUG\s*=\s*(.+)$/m', $content, $match)) {
            $value = trim(strtolower($match[1]));
            $environment['app_debug'] = $value === 'true' ? 'true' : 'false';
        }

        return $environment;
    }

    /**
     * Extract fully-qualified controller class names from file data.
     *
     * @param  array<int, array{path: string, content: string, type: string}>  $files
     * @return array<int, string>
     */
    private function extractControllerClasses(array $files): array
    {
        $classes = [];

        foreach ($files as $file) {
            if ($file['type'] !== 'controller') {
                continue;
            }

            $fqcn = $this->extractFqcn($file['content']);

            if ($fqcn !== null) {
                $classes[] = $fqcn;
            }
        }

        return array_values(array_unique($classes));
    }

    /**
     * Extract model FQCNs from use statements in PHP content.
     *
     * @return array<int, string>
     */
    private function extractModelReferences(string $content): array
    {
        $models = [];

        if (preg_match_all('/use\s+([\w\\\\]+);/', $content, $matches)) {
            foreach ($matches[1] as $use) {
                if (str_contains($use, 'Models\\')) {
                    $models[] = $use;
                }
            }
        }

        return array_values(array_unique($models));
    }

    /**
     * Safely read a file's contents, returning empty string on failure.
     */
    private function readFile(string $path): string
    {
        if (! is_file($path) || ! is_readable($path)) {
            return '';
        }

        $content = file_get_contents($path);

        return $content === false ? '' : $content;
    }

    /**
     * Extract a PHP array property's string values using regex.
     *
     * @return array<int, string>
     */
    private function parsePhpArray(string $content, string $propertyName): array
    {
        $escapedName = preg_quote($propertyName, '/');

        if (! preg_match('/\$'.$escapedName.'\s*=\s*\[(.*?)\];/s', $content, $match)) {
            return [];
        }

        $values = [];

        if (preg_match_all("/['\"]([^'\"]+)['\"]/", $match[1], $valueMatches)) {
            $values = $valueMatches[1];
        }

        return $values;
    }

    /**
     * Extract a PHP associative array property's key-value pairs using regex.
     *
     * @return array<string, string>
     */
    private function parsePhpAssociativeArray(string $content, string $propertyName): array
    {
        $escapedName = preg_quote($propertyName, '/');

        if (! preg_match('/\$'.$escapedName.'\s*=\s*\[(.*?)\];/s', $content, $match)) {
            return [];
        }

        $values = [];

        if (preg_match_all("/['\"]([^'\"]+)['\"]\s*=>\s*['\"]?([^'\",\]\s]+)['\"]?/", $match[1], $valueMatches, PREG_SET_ORDER)) {
            foreach ($valueMatches as $valueMatch) {
                $values[$valueMatch[1]] = rtrim($valueMatch[2], ',');
            }
        }

        return $values;
    }

    /**
     * Check if a file exists relative to base_path().
     */
    private function fileExists(string $relativePath): bool
    {
        return file_exists(base_path($relativePath));
    }

    /**
     * Extract the fully-qualified class name from PHP source content.
     */
    private function extractFqcn(string $content): ?string
    {
        $namespace = null;
        $class = null;

        if (preg_match('/namespace\s+([^;]+);/', $content, $match)) {
            $namespace = trim($match[1]);
        }

        if (preg_match('/class\s+(\w+)/', $content, $match)) {
            $class = $match[1];
        }

        if ($class === null) {
            return null;
        }

        return $namespace !== null ? "{$namespace}\\{$class}" : $class;
    }

    /**
     * Extract just the short class name from PHP source content.
     */
    private function extractClassNameFromContent(string $content): ?string
    {
        if (preg_match('/class\s+(\w+)/', $content, $match)) {
            return $match[1];
        }

        return null;
    }

    /**
     * Extract FormRequest class FQCNs from controller type hints.
     *
     * @return array<int, string>
     */
    private function extractFormRequestTypeHints(string $content): array
    {
        $uses = [];

        if (preg_match_all('/use\s+([\w\\\\]+);/', $content, $matches)) {
            foreach ($matches[1] as $use) {
                $parts = explode('\\', $use);
                $short = end($parts);
                $uses[$short] = $use;
            }
        }

        $formRequests = [];

        if (preg_match_all('/function\s+\w+\s*\(([^)]*)\)/s', $content, $matches)) {
            foreach ($matches[1] as $params) {
                if (preg_match_all('/(\w+)\s+\$\w+/', $params, $paramMatches)) {
                    foreach ($paramMatches[1] as $typeHint) {
                        if (isset($uses[$typeHint]) && str_contains($uses[$typeHint], 'Requests\\')) {
                            $formRequests[] = $uses[$typeHint];
                        }
                    }
                }
            }
        }

        return array_values(array_unique($formRequests));
    }

    /**
     * Resolve a fully-qualified class name to an absolute file path.
     */
    private function resolveClassPath(string $fqcn): ?string
    {
        if (! str_starts_with($fqcn, 'App\\')) {
            return null;
        }

        $relativePath = str_replace('\\', DIRECTORY_SEPARATOR, $fqcn);
        $relativePath = 'app'.substr($relativePath, 3);

        return base_path($relativePath.'.php');
    }

    /**
     * Extract trait names used by a class.
     *
     * @return array<int, string>
     */
    private function extractTraits(string $content): array
    {
        $traits = [];

        if (preg_match_all('/use\s+([\w\\\\]+)\s*[;,{]/', $content, $matches)) {
            foreach ($matches[1] as $trait) {
                // Only include trait usage inside class body (not namespace imports)
                $parts = explode('\\', $trait);
                $shortName = end($parts);

                // Common Eloquent traits
                $knownTraits = [
                    'SoftDeletes', 'HasFactory', 'HasApiTokens', 'Notifiable',
                    'HasRoles', 'HasPermissions', 'Authenticatable', 'Authorizable',
                    'MustVerifyEmail', 'HasUuids', 'HasUlids',
                ];

                if (in_array($shortName, $knownTraits, true)) {
                    $traits[] = $shortName;
                }
            }
        }

        // Also check for use statements within class body
        if (preg_match('/class\s+\w+[^{]*\{(.*)\}/s', $content, $classBody)) {
            if (preg_match_all('/use\s+([\w\\\\,\s]+)\s*;/', $classBody[1], $traitMatches)) {
                foreach ($traitMatches[1] as $traitList) {
                    $traitNames = array_map('trim', explode(',', $traitList));

                    foreach ($traitNames as $traitName) {
                        $parts = explode('\\', $traitName);
                        $shortName = end($parts);

                        if ($shortName !== '' && ! in_array($shortName, $traits, true)) {
                            $traits[] = $shortName;
                        }
                    }
                }
            }
        }

        return array_values(array_unique($traits));
    }

    /**
     * Extract global scopes registered in the model's booted() method.
     *
     * @return array<int, string>
     */
    private function extractGlobalScopes(string $content): array
    {
        $scopes = [];

        // Match static::addGlobalScope('name', ...) or static::addGlobalScope(new ScopeClass)
        if (preg_match('/function\s+booted\s*\(\s*\)\s*(?::\s*void\s*)?\{(.*?)\}/s', $content, $match)) {
            $body = $match[1];

            // Named scope: static::addGlobalScope('name', function ...)
            if (preg_match_all("/addGlobalScope\s*\(\s*['\"]([^'\"]+)['\"]/", $body, $scopeMatches)) {
                $scopes = array_merge($scopes, $scopeMatches[1]);
            }

            // Class scope: static::addGlobalScope(new ScopeClass)
            if (preg_match_all('/addGlobalScope\s*\(\s*new\s+(\w+)/', $body, $scopeMatches)) {
                $scopes = array_merge($scopes, $scopeMatches[1]);
            }
        }

        return array_values(array_unique($scopes));
    }

    /**
     * Summarize what a middleware's handle() method does.
     */
    private function summarizeMiddlewareHandle(string $content): string
    {
        if (! preg_match('/function\s+handle\s*\([^)]*\)\s*(?::\s*\w+\s*)?\{(.*?)\n\s*\}/s', $content, $match)) {
            return 'custom middleware';
        }

        $body = trim($match[1]);

        // Common patterns
        if (str_contains($body, 'abort(403') || str_contains($body, 'abort(401')) {
            return 'Authorization check middleware';
        }

        if (str_contains($body, 'RateLimiter') || str_contains($body, 'throttle')) {
            return 'Rate limiting middleware';
        }

        if (str_contains($body, 'Auth::check') || str_contains($body, 'auth()->check')) {
            return 'Authentication check middleware';
        }

        if (str_contains($body, 'redirect(')) {
            return 'Redirect middleware';
        }

        if (str_contains($body, '$request->header') || str_contains($body, 'hasHeader')) {
            return 'Header validation middleware';
        }

        if (str_contains($body, 'encrypt') || str_contains($body, 'decrypt')) {
            return 'Encryption middleware';
        }

        if (str_contains($body, 'log') || str_contains($body, 'Log::')) {
            return 'Logging middleware';
        }

        // Fallback: first meaningful line
        $lines = array_filter(explode("\n", $body), fn (string $line): bool => trim($line) !== '');
        $firstLine = trim(array_values($lines)[0] ?? '');

        if (strlen($firstLine) > 80) {
            $firstLine = substr($firstLine, 0, 80).'...';
        }

        return $firstLine !== '' ? $firstLine : 'custom middleware';
    }

    /**
     * Find all middleware group boundaries in route file content.
     *
     * @return array<int, array{middleware: array<int, string>, start: int, end: int}>
     */
    private function findRouteGroupBoundaries(string $content): array
    {
        $boundaries = [];

        // Route::middleware(...)->...->group(function () { ... })
        $pattern = '/Route\s*::\s*middleware\s*\(\s*('.$this->middlewareValuePattern().')\s*\)/s';

        if (preg_match_all($pattern, $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
            foreach ($matches as $match) {
                $middlewareRaw = $match[1][0];
                $matchEnd = $match[0][1] + strlen($match[0][0]);

                $groupOpenBrace = $this->findGroupCallAfter($content, $matchEnd);

                if ($groupOpenBrace === null) {
                    continue;
                }

                $closingBrace = $this->findMatchingBrace($content, $groupOpenBrace);

                if ($closingBrace === null) {
                    continue;
                }

                $middleware = $this->parseMiddlewareValue($middlewareRaw);

                $boundaries[] = [
                    'middleware' => $middleware,
                    'start' => $groupOpenBrace,
                    'end' => $closingBrace,
                ];
            }
        }

        // Route::group(['middleware' => ...], function () { ... })
        $arrayPattern = '/Route\s*::\s*group\s*\(\s*\[([^\]]*)\]\s*,/s';

        if (preg_match_all($arrayPattern, $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
            foreach ($matches as $match) {
                $arrayContent = $match[1][0];
                $matchEnd = $match[0][1] + strlen($match[0][0]);

                if (preg_match('/[\'"]middleware[\'"]\s*=>\s*('.$this->middlewareValuePattern().')/s', $arrayContent, $mwMatch)) {
                    $middleware = $this->parseMiddlewareValue($mwMatch[1]);
                } else {
                    continue;
                }

                $openBrace = $this->findNextOpenBrace($content, $matchEnd);

                if ($openBrace === null) {
                    continue;
                }

                $closingBrace = $this->findMatchingBrace($content, $openBrace);

                if ($closingBrace === null) {
                    continue;
                }

                $boundaries[] = [
                    'middleware' => $middleware,
                    'start' => $openBrace,
                    'end' => $closingBrace,
                ];
            }
        }

        return $boundaries;
    }

    /**
     * Determine which group middleware applies to a given byte position.
     *
     * @param  array<int, array{middleware: array<int, string>, start: int, end: int}>  $groupBoundaries
     * @return array<int, string>
     */
    private function getMiddlewareForPosition(int $position, array $groupBoundaries): array
    {
        $middleware = [];

        foreach ($groupBoundaries as $group) {
            if ($position > $group['start'] && $position < $group['end']) {
                $middleware = array_merge($middleware, $group['middleware']);
            }
        }

        return array_values(array_unique($middleware));
    }

    /**
     * Parse middleware from a ->middleware() call in a method chain.
     *
     * @return array<int, string>
     */
    private function parseChainedMiddleware(string $chain): array
    {
        $middleware = [];

        $pattern = '/->middleware\s*\(\s*('.$this->middlewareValuePattern().')\s*\)/';

        if (preg_match_all($pattern, $chain, $matches)) {
            foreach ($matches[1] as $value) {
                $parsed = $this->parseMiddlewareValue($value);
                $middleware = array_merge($middleware, $parsed);
            }
        }

        return $middleware;
    }

    /**
     * Regex pattern fragment matching a middleware value.
     */
    private function middlewareValuePattern(): string
    {
        return '(?:\'[^\']+\'|"[^"]+"|\\[[^\\]]+\\])';
    }

    /**
     * Parse a middleware value string into an array of middleware names.
     *
     * @return array<int, string>
     */
    private function parseMiddlewareValue(string $value): array
    {
        $value = trim($value);

        if (str_starts_with($value, '[')) {
            $inner = substr($value, 1, -1);

            if (preg_match_all('/[\'"]([^\'"]+)[\'"]/', $inner, $matches)) {
                return $matches[1];
            }

            return [];
        }

        if (preg_match('/^[\'"]([^\'"]+)[\'"]$/', $value, $match)) {
            return [$match[1]];
        }

        return [];
    }

    /**
     * Look for a ->group( call followed by an opening brace after the given offset.
     */
    private function findGroupCallAfter(string $content, int $offset): ?int
    {
        $searchWindow = substr($content, $offset, 500);

        if (! preg_match('/((?:\s*->\s*\w+\s*\([^)]*\)\s*)*->\s*group\s*\()/s', $searchWindow, $groupMatch, PREG_OFFSET_CAPTURE)) {
            return null;
        }

        $groupCallEnd = $offset + $groupMatch[0][1] + strlen($groupMatch[0][0]);

        return $this->findNextOpenBrace($content, $groupCallEnd);
    }

    /**
     * Find the next '{' character after the given offset.
     */
    private function findNextOpenBrace(string $content, int $offset): ?int
    {
        $length = strlen($content);

        for ($i = $offset; $i < $length; $i++) {
            if ($content[$i] === '{') {
                return $i;
            }

            if ($content[$i] === ';') {
                return null;
            }
        }

        return null;
    }

    /**
     * Find the matching closing brace using brace counting.
     */
    private function findMatchingBrace(string $content, int $openPos): ?int
    {
        $length = strlen($content);
        $depth = 0;

        for ($i = $openPos; $i < $length; $i++) {
            if ($content[$i] === '{') {
                $depth++;
            } elseif ($content[$i] === '}') {
                $depth--;

                if ($depth === 0) {
                    return $i;
                }
            }
        }

        return null;
    }

    /**
     * Determine the resource parameter name from a resource URI.
     */
    private function resourceParam(string $uri): string
    {
        $segments = explode('/', trim($uri, '/'));
        $last = end($segments);

        if (str_ends_with($last, 's') && strlen($last) > 1) {
            return substr($last, 0, -1);
        }

        return $last;
    }
}
