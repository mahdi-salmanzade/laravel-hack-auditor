<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner;

class RouteAnalyzer
{
    /**
     * Analyze route files to extract middleware applied to the given controller.
     *
     * Reads all PHP files in the routes/ directory, parses route definitions
     * that reference the given controller class, and returns a map of
     * "METHOD /uri" to middleware arrays. Handles group middleware, controller
     * groups, resource routes, and API resource routes.
     *
     * @return array<string, array<int, string>>
     */
    public function analyze(string $controllerClass): array
    {
        $routeFiles = $this->getRouteFiles();

        if ($routeFiles === []) {
            return [];
        }

        $results = [];

        foreach ($routeFiles as $filePath) {
            $content = $this->readFile($filePath);

            if ($content === '') {
                continue;
            }

            $parsed = $this->parseRoutes($content, $controllerClass);

            foreach ($parsed as $key => $middleware) {
                $results[$key] = $middleware;
            }
        }

        return $results;
    }

    /**
     * Get controller method names that have registered routes.
     *
     * Returns a map of method name => route description (e.g. 'update' => 'PUT /rooms/{room}').
     *
     * @return array<string, string>
     */
    public function getRoutedMethods(string $controllerClass): array
    {
        $routeFiles = $this->getRouteFiles();

        if ($routeFiles === []) {
            return [];
        }

        $methods = [];

        foreach ($routeFiles as $filePath) {
            $content = $this->readFile($filePath);

            if ($content === '') {
                continue;
            }

            $parsed = $this->parseRoutedMethods($content, $controllerClass);

            foreach ($parsed as $method => $route) {
                $methods[$method] = $route;
            }
        }

        return $methods;
    }

    /**
     * Parse route definitions to extract which controller methods have routes.
     *
     * @return array<string, string>
     */
    private function parseRoutedMethods(string $content, string $controllerClass): array
    {
        $methods = [];
        $shortClass = $this->shortClassName($controllerClass);
        $controllerPattern = preg_quote($shortClass, '/');
        $httpMethods = 'get|post|put|patch|delete|options|any|match';

        // Explicit routes: Route::get('/path', [Controller::class, 'method'])
        $pattern = '/Route\s*::\s*('.$httpMethods.')\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*\['
            .'\s*'.$controllerPattern.'\s*::\s*class\s*,\s*[\'"]([^\'"]+)[\'"]\s*'
            .'\]\s*\)/i';

        if (preg_match_all($pattern, $content, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $httpMethod = strtoupper($match[1]);
                $uri = '/'.ltrim($match[2], '/');
                $methods[$match[3]] = "{$httpMethod} {$uri}";
            }
        }

        // String syntax: Route::get('/path', 'Controller@method')
        $stringPattern = '/Route\s*::\s*('.$httpMethods.')\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*[\'"]'
            .'[^\'"]*(\\\\)?'.$controllerPattern.'@([^\'"]+)[\'"]\s*\)/i';

        if (preg_match_all($stringPattern, $content, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $httpMethod = strtoupper($match[1]);
                $uri = '/'.ltrim($match[2], '/');
                $methods[$match[4]] = "{$httpMethod} {$uri}";
            }
        }

        // Resource routes: Route::resource('name', Controller::class)
        $resourcePattern = '/Route\s*::\s*(apiResource|resource)\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*'
            .$controllerPattern.'\s*::\s*class\s*\)/i';

        if (preg_match_all($resourcePattern, $content, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $isApi = strtolower($match[1]) === 'apiresource';
                $uri = '/'.ltrim($match[2], '/');
                $param = $this->resourceParam($uri);

                $methods['index'] = "GET {$uri}";
                $methods['store'] = "POST {$uri}";
                $methods['show'] = "GET {$uri}/{{$param}}";
                $methods['update'] = "PUT/PATCH {$uri}/{{$param}}";
                $methods['destroy'] = "DELETE {$uri}/{{$param}}";

                if (! $isApi) {
                    $methods['create'] = "GET {$uri}/create";
                    $methods['edit'] = "GET {$uri}/{{$param}}/edit";
                }
            }
        }

        // Controller group routes: Route::controller(Controller::class)->group(fn() => Route::get('/path', 'method'))
        $controllerGroupPattern = '/Route\s*::\s*controller\s*\(\s*'.$controllerPattern.'\s*::\s*class\s*\)/s';

        if (preg_match_all($controllerGroupPattern, $content, $cgMatches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
            foreach ($cgMatches as $match) {
                $matchEnd = $match[0][1] + strlen($match[0][0]);
                $groupOpenBrace = $this->findGroupCallAfter($content, $matchEnd);

                if ($groupOpenBrace === null) {
                    continue;
                }

                $closingBrace = $this->findMatchingBrace($content, $groupOpenBrace);

                if ($closingBrace === null) {
                    continue;
                }

                $groupBody = substr($content, $groupOpenBrace + 1, $closingBrace - $groupOpenBrace - 1);

                $routePattern = '/Route\s*::\s*('.$httpMethods.')\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)/i';

                if (preg_match_all($routePattern, $groupBody, $routeMatches, PREG_SET_ORDER)) {
                    foreach ($routeMatches as $routeMatch) {
                        $httpMethod = strtoupper($routeMatch[1]);
                        $uri = '/'.ltrim($routeMatch[2], '/');
                        $methods[$routeMatch[3]] = "{$httpMethod} {$uri}";
                    }
                }
            }
        }

        return $methods;
    }

    /**
     * Get all PHP files from the routes/ directory.
     *
     * @return array<int, string>
     */
    private function getRouteFiles(): array
    {
        $routesPath = base_path('routes');

        if (! is_dir($routesPath)) {
            return [];
        }

        $files = glob($routesPath.DIRECTORY_SEPARATOR.'*.php');

        if ($files === false) {
            return [];
        }

        return $files;
    }

    /**
     * Safely read a file's contents, returning an empty string on failure.
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
     * Parse route definitions from file content for a specific controller.
     *
     * @return array<string, array<int, string>>
     */
    private function parseRoutes(string $content, string $controllerClass): array
    {
        $results = [];
        $shortClass = $this->shortClassName($controllerClass);

        $groupBoundaries = $this->findGroupBoundaries($content);

        $this->extractExplicitRoutes($content, $controllerClass, $shortClass, $groupBoundaries, $results);
        $this->extractResourceRoutes($content, $controllerClass, $shortClass, $groupBoundaries, $results);
        $this->extractControllerGroupRoutes($content, $controllerClass, $shortClass, $groupBoundaries, $results);

        return $results;
    }

    /**
     * Get the short (unqualified) class name from a fully-qualified class name.
     */
    private function shortClassName(string $fqcn): string
    {
        $parts = explode('\\', $fqcn);

        return end($parts);
    }

    /**
     * Find all middleware group boundaries in the file content using brace counting.
     *
     * Pass 1: Scans for Route::middleware(...)->...->group(...) and
     * Route::group(['middleware' => ...], ...) patterns, then uses brace
     * counting to find the matching closing brace for each group closure.
     *
     * Returns an array of groups, each with 'middleware', 'start', and 'end'
     * byte offsets representing the body of the group closure.
     *
     * @return array<int, array{middleware: array<int, string>, start: int, end: int}>
     */
    private function findGroupBoundaries(string $content): array
    {
        $boundaries = [];

        $this->findChainedMiddlewareGroups($content, $boundaries);
        $this->findArraySyntaxGroups($content, $boundaries);
        $this->findControllerMiddlewareGroups($content, $boundaries);

        return $boundaries;
    }

    /**
     * Find Route::middleware(...)->...->group(...) patterns.
     *
     * Handles chained methods between middleware() and group() such as
     * ->prefix(), ->name(), etc.
     *
     * @param  array<int, array{middleware: array<int, string>, start: int, end: int}>  $boundaries
     */
    private function findChainedMiddlewareGroups(string $content, array &$boundaries): void
    {
        $pattern = '/Route\s*::\s*middleware\s*\(\s*('
            .$this->middlewareValuePattern()
            .')\s*\)/s';

        if (! preg_match_all($pattern, $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
            return;
        }

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

    /**
     * Find Route::group(['middleware' => ...], function () {...}) array syntax patterns.
     *
     * @param  array<int, array{middleware: array<int, string>, start: int, end: int}>  $boundaries
     */
    private function findArraySyntaxGroups(string $content, array &$boundaries): void
    {
        $pattern = '/Route\s*::\s*group\s*\(\s*\[([^\]]*)\]\s*,/s';

        if (! preg_match_all($pattern, $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
            return;
        }

        foreach ($matches as $match) {
            $arrayContent = $match[1][0];
            $matchEnd = $match[0][1] + strlen($match[0][0]);

            $middleware = $this->parseArrayMiddleware($arrayContent);

            if ($middleware === []) {
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

    /**
     * Find Route::controller(X)->middleware(...)->group(...) patterns.
     *
     * @param  array<int, array{middleware: array<int, string>, start: int, end: int}>  $boundaries
     */
    private function findControllerMiddlewareGroups(string $content, array &$boundaries): void
    {
        $pattern = '/Route\s*::\s*controller\s*\([^)]+\)\s*/s';

        if (! preg_match_all($pattern, $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
            return;
        }

        foreach ($matches as $match) {
            $matchEnd = $match[0][1] + strlen($match[0][0]);

            $chainMiddleware = $this->extractMiddlewareFromChainBefore($content, $matchEnd);

            if ($chainMiddleware === []) {
                continue;
            }

            $groupOpenBrace = $this->findGroupCallAfter($content, $match[0][1]);

            if ($groupOpenBrace === null) {
                continue;
            }

            $alreadyTracked = false;
            foreach ($boundaries as $b) {
                if ($b['start'] === $groupOpenBrace) {
                    $alreadyTracked = true;

                    break;
                }
            }

            if ($alreadyTracked) {
                continue;
            }

            $closingBrace = $this->findMatchingBrace($content, $groupOpenBrace);

            if ($closingBrace === null) {
                continue;
            }

            $boundaries[] = [
                'middleware' => $chainMiddleware,
                'start' => $groupOpenBrace,
                'end' => $closingBrace,
            ];
        }
    }

    /**
     * Extract middleware from chained ->middleware() calls starting at a position.
     *
     * Scans the chain of method calls after the given position for ->middleware() calls.
     *
     * @return array<int, string>
     */
    private function extractMiddlewareFromChainBefore(string $content, int $offset): array
    {
        $remaining = substr($content, $offset, 500);

        $middleware = [];
        $mwPattern = '/->middleware\s*\(\s*('.$this->middlewareValuePattern().')\s*\)/s';

        if (preg_match_all($mwPattern, $remaining, $mwMatches)) {
            foreach ($mwMatches[1] as $value) {
                $middleware = array_merge($middleware, $this->parseMiddlewareValue($value));
            }
        }

        return $middleware;
    }

    /**
     * Look for a ->group( call followed by an opening brace after the given offset.
     *
     * Scans up to 500 characters ahead for a chained ->...->group( pattern,
     * allowing intermediate chained calls like ->prefix(), ->name(), etc.
     *
     * Returns the byte offset of the opening { of the group closure, or null.
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
     * Find the matching closing brace for an opening brace using brace counting.
     *
     * Starts at the given offset (which must be the position of an opening '{')
     * and counts nested braces to find the matching closing '}'.
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
     * Parse middleware from Route::group(['middleware' => ...], ...) array content.
     *
     * @return array<int, string>
     */
    private function parseArrayMiddleware(string $arrayContent): array
    {
        if (preg_match('/[\'"]middleware[\'"]\s*=>\s*('.$this->middlewareValuePattern().')/s', $arrayContent, $match)) {
            return $this->parseMiddlewareValue($match[1]);
        }

        return [];
    }

    /**
     * Determine which group middleware applies to a given byte position.
     *
     * Checks all group boundaries and merges middleware from all groups
     * that contain the given position (supporting nested groups).
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
     * Extract middleware from explicit route definitions (get, post, put, patch, delete, any, match).
     *
     * Handles patterns like:
     *   Route::get('/path', [Controller::class, 'method'])->middleware('...')
     *   Route::post('/path', [Controller::class, 'method'])->middleware(['...', '...'])
     *
     * @param  array<int, array{middleware: array<int, string>, start: int, end: int}>  $groupBoundaries
     * @param  array<string, array<int, string>>  $results
     */
    private function extractExplicitRoutes(
        string $content,
        string $controllerClass,
        string $shortClass,
        array $groupBoundaries,
        array &$results,
    ): void {
        $methods = 'get|post|put|patch|delete|options|any';

        $controllerPattern = preg_quote($shortClass, '/');

        $pattern = '/Route\s*::\s*('.$methods.')\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*\['
            .'\s*'.$controllerPattern.'\s*::\s*class\s*,\s*[\'"][^\'"]+[\'"]\s*'
            .'\]\s*\)([^;]*);/i';

        if (preg_match_all($pattern, $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
            foreach ($matches as $match) {
                $httpMethod = strtoupper($match[1][0]);
                $uri = '/'.ltrim($match[2][0], '/');
                $chain = $match[3][0];
                $position = $match[0][1];

                $routeMiddleware = $this->parseChainedMiddleware($chain);
                $groupMiddleware = $this->getMiddlewareForPosition($position, $groupBoundaries);
                $allMiddleware = array_values(array_unique(array_merge($groupMiddleware, $routeMiddleware)));

                $results["{$httpMethod} {$uri}"] = $allMiddleware;
            }
        }

        $stringPattern = '/Route\s*::\s*('.$methods.')\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*[\'"]'
            .'[^\'"]*(\\\\)?'.preg_quote($shortClass, '/').'@[^\'"]+[\'"]\s*\)([^;]*);/i';

        if (preg_match_all($stringPattern, $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
            foreach ($matches as $match) {
                $httpMethod = strtoupper($match[1][0]);
                $uri = '/'.ltrim($match[2][0], '/');
                $chain = $match[4][0] ?? '';
                $position = $match[0][1];

                $routeMiddleware = $this->parseChainedMiddleware($chain);
                $groupMiddleware = $this->getMiddlewareForPosition($position, $groupBoundaries);
                $allMiddleware = array_values(array_unique(array_merge($groupMiddleware, $routeMiddleware)));

                $results["{$httpMethod} {$uri}"] = $allMiddleware;
            }
        }
    }

    /**
     * Extract routes from Route::resource() and Route::apiResource() definitions.
     *
     * Generates the standard RESTful route set for the given controller.
     *
     * @param  array<int, array{middleware: array<int, string>, start: int, end: int}>  $groupBoundaries
     * @param  array<string, array<int, string>>  $results
     */
    private function extractResourceRoutes(
        string $content,
        string $controllerClass,
        string $shortClass,
        array $groupBoundaries,
        array &$results,
    ): void {
        $controllerPattern = preg_quote($shortClass, '/');

        $pattern = '/Route\s*::\s*(apiResource|resource)\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*'
            .$controllerPattern.'\s*::\s*class\s*\)([^;]*);/i';

        if (! preg_match_all($pattern, $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
            return;
        }

        foreach ($matches as $match) {
            $isApi = strtolower($match[1][0]) === 'apiresource';
            $uri = '/'.ltrim($match[2][0], '/');
            $chain = $match[3][0];
            $position = $match[0][1];

            $routeMiddleware = $this->parseChainedMiddleware($chain);
            $groupMiddleware = $this->getMiddlewareForPosition($position, $groupBoundaries);
            $allMiddleware = array_values(array_unique(array_merge($groupMiddleware, $routeMiddleware)));

            $results["GET {$uri}"] = $allMiddleware;
            $results["POST {$uri}"] = $allMiddleware;
            $results["GET {$uri}/{".$this->resourceParam($uri).'}'] = $allMiddleware;
            $results["PUT {$uri}/{".$this->resourceParam($uri).'}'] = $allMiddleware;
            $results["PATCH {$uri}/{".$this->resourceParam($uri).'}'] = $allMiddleware;
            $results["DELETE {$uri}/{".$this->resourceParam($uri).'}'] = $allMiddleware;

            if (! $isApi) {
                $results["GET {$uri}/create"] = $allMiddleware;
                $results["GET {$uri}/{".$this->resourceParam($uri).'}/edit'] = $allMiddleware;
            }
        }
    }

    /**
     * Extract routes from Route::controller(Controller::class)->group() blocks.
     *
     * @param  array<int, array{middleware: array<int, string>, start: int, end: int}>  $groupBoundaries
     * @param  array<string, array<int, string>>  $results
     */
    private function extractControllerGroupRoutes(
        string $content,
        string $controllerClass,
        string $shortClass,
        array $groupBoundaries,
        array &$results,
    ): void {
        $controllerPattern = preg_quote($shortClass, '/');
        $methods = 'get|post|put|patch|delete|options|any';

        $pattern = '/Route\s*::\s*controller\s*\(\s*'.$controllerPattern.'\s*::\s*class\s*\)/s';

        if (! preg_match_all($pattern, $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
            return;
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

            $groupBody = substr($content, $groupOpenBrace + 1, $closingBrace - $groupOpenBrace - 1);
            $groupBodyOffset = $groupOpenBrace + 1;

            $parentGroupMiddleware = $this->getMiddlewareForPosition($match[0][1], $groupBoundaries);
            $combinedGroupMiddleware = array_values(array_unique(
                array_merge($parentGroupMiddleware, $controllerGroupMiddleware)
            ));

            $routePattern = '/Route\s*::\s*('.$methods.')\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)([^;]*);/i';

            if (preg_match_all($routePattern, $groupBody, $routeMatches, PREG_SET_ORDER)) {
                foreach ($routeMatches as $routeMatch) {
                    $httpMethod = strtoupper($routeMatch[1]);
                    $uri = '/'.ltrim($routeMatch[2], '/');
                    $chain = $routeMatch[4] ?? '';

                    $routeMiddleware = $this->parseChainedMiddleware($chain);
                    $allMiddleware = array_values(array_unique(
                        array_merge($combinedGroupMiddleware, $routeMiddleware)
                    ));

                    $results["{$httpMethod} {$uri}"] = $allMiddleware;
                }
            }
        }
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
     * Regex pattern fragment matching a middleware value: single-quoted string,
     * double-quoted string, or an array of strings.
     */
    private function middlewareValuePattern(): string
    {
        return '(?:\'[^\']+\'|"[^"]+"|\\[[^\\]]+\\])';
    }

    /**
     * Parse a middleware value string into an array of middleware names.
     *
     * Handles both single string values ('auth') and array values (['auth', 'throttle']).
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
     * Determine the resource parameter name from a resource URI.
     *
     * Converts "/users" to "user" by taking the last segment and singularizing it
     * with a simple trailing-s removal.
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

    /**
     * Check if a group body contains references to the given controller.
     */
    private function bodyReferencesController(string $body, string $controllerClass, string $shortClass): bool
    {
        if (str_contains($body, $shortClass.'::class')) {
            return true;
        }

        if (str_contains($body, $shortClass.'@')) {
            return true;
        }

        return str_contains($body, $controllerClass);
    }
}
