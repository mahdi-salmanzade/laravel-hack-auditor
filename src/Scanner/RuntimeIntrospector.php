<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Throwable;

final class RuntimeIntrospector
{
    /**
     * Create a new RuntimeIntrospector instance.
     */
    public function __construct(private Router $router) {}

    /**
     * Get middleware applied to routes for a given controller class.
     *
     * Uses Laravel's runtime Router to iterate all registered routes and
     * return a map of "METHOD /uri" to middleware arrays for routes that
     * reference the specified controller.
     *
     * @return array<string, array<int, string>>
     */
    public function getRouteMiddleware(string $controllerClass): array
    {
        $results = [];

        foreach ($this->router->getRoutes() as $route) {
            /** @var Route $route */
            $action = $route->getAction('uses');

            if (! is_string($action) || ! $this->matchesController($action, $controllerClass)) {
                continue;
            }

            $middleware = $this->resolveMiddleware($route);
            $methods = array_filter($route->methods(), fn (string $method): bool => $method !== 'HEAD');
            $uri = $route->uri();

            foreach ($methods as $method) {
                $results["{$method} /{$uri}"] = $middleware;
            }
        }

        return $results;
    }

    /**
     * Get controller method names that have registered routes.
     *
     * Returns a map of method name to route description (e.g. 'update' => 'PUT /rooms/{room}').
     *
     * @return array<string, string>
     */
    public function getRoutedMethods(string $controllerClass): array
    {
        $methods = [];

        foreach ($this->router->getRoutes() as $route) {
            /** @var Route $route */
            $action = $route->getAction('uses');

            if (! is_string($action) || ! $this->matchesController($action, $controllerClass)) {
                continue;
            }

            $methodName = $this->extractMethodName($action);

            if ($methodName === null) {
                continue;
            }

            $httpMethods = array_filter($route->methods(), fn (string $m): bool => $m !== 'HEAD');
            $httpMethod = implode('|', $httpMethods);
            $uri = $route->uri();

            $methods[$methodName] = "{$httpMethod} /{$uri}";
        }

        return $methods;
    }

    /**
     * Get model metadata for a given Eloquent model class.
     *
     * Returns fillable, hidden, guarded, and casts arrays, or null if the
     * class does not exist, is not an Eloquent model, or instantiation fails.
     *
     * @return array{fillable: array<int, string>, hidden: array<int, string>, guarded: array<int, string>, casts: array<string, string>}|null
     */
    public function getModelInfo(string $modelClass): ?array
    {
        try {
            if (! class_exists($modelClass) || ! is_subclass_of($modelClass, Model::class)) {
                return null;
            }

            /** @var Model $model */
            $model = new $modelClass;

            return [
                'fillable' => $model->getFillable(),
                'hidden' => $model->getHidden(),
                'guarded' => $model->getGuarded(),
                'casts' => $model->getCasts(),
            ];
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Check if a route action string references the given controller class.
     *
     * The action format is "App\Http\Controllers\FooController@method".
     */
    private function matchesController(string $action, string $controllerClass): bool
    {
        return str_contains($action, $controllerClass);
    }

    /**
     * Extract the method name from a route action string.
     *
     * The action format is "Controller@method"; this returns the part after "@".
     */
    private function extractMethodName(string $action): ?string
    {
        $atPosition = strrpos($action, '@');

        if ($atPosition === false) {
            return null;
        }

        return substr($action, $atPosition + 1);
    }

    /**
     * Safely resolve the full middleware stack for a route.
     *
     * @return array<int, string>
     */
    private function resolveMiddleware(Route $route): array
    {
        try {
            $middleware = $route->gatherMiddleware();

            return array_values(array_filter($middleware, fn (mixed $m): bool => is_string($m)));
        } catch (Throwable) {
            return [];
        }
    }
}
