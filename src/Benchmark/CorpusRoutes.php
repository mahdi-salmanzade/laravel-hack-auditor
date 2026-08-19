<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Benchmark;

use Illuminate\Routing\Router;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use RuntimeException;

/**
 * The route table the benchmark corpus declares for itself.
 *
 * The corpus is a directory of standalone fixture files with no application
 * around them. The access-control engine refuses to report a record exposure it
 * cannot attribute to a routed entry point — correctly, since that rule is what
 * removed 191 false IDOR reports from a 6,221-file real-code corpus. With no
 * route table in sight, though, every corpus sample resolved to 'unreachable'
 * and was dropped before analysis, so the accuracy gate stopped measuring the
 * very detectors it exists to guard.
 *
 * The fix is not to relax the rule but to give the corpus what a real
 * application has: a route file. tests/Fixtures/benchmark/routes.php names the
 * controller action behind every sample, and this class turns those entries
 * into either
 *
 *   - an {@see AccessControlContext} for driving the deterministic engine
 *     directly (no Laravel app, no AI key), or
 *   - a real {@see Router} the scanner's RuntimeIntrospector can read, so the
 *     full pipeline sees the corpus as a routed application.
 *
 * Route strings are formatted exactly as RuntimeIntrospector formats them
 * ("GET /invoices/{id}"), so a context built here is indistinguishable from one
 * introspected out of a booted application.
 */
final readonly class CorpusRoutes
{
    /**
     * @param  array<int, array{verb: string, uri: string, controller: string, method: string, middleware: array<int, string>}>  $routes
     */
    public function __construct(public array $routes) {}

    /**
     * Build from the manifest packaged alongside the corpus.
     */
    public static function default(): self
    {
        return self::fromFile(self::defaultPath());
    }

    /**
     * Absolute path to the packaged route manifest.
     */
    public static function defaultPath(): string
    {
        return dirname(__DIR__, 2).'/tests/Fixtures/benchmark/routes.php';
    }

    /**
     * Load a route manifest from a PHP file that returns the manifest array.
     */
    public static function fromFile(string $path): self
    {
        if (! is_file($path) || ! is_readable($path)) {
            throw new RuntimeException("Benchmark route manifest not found or unreadable: {$path}");
        }

        /** @var mixed $data */
        $data = require $path;

        if (! is_array($data)) {
            throw new RuntimeException("Benchmark route manifest must return an array: {$path}");
        }

        /** @var array<string, mixed> $data */
        return self::fromArray($data);
    }

    /**
     * Build from a decoded manifest array.
     *
     * Entries missing an action, or whose action is not "Controller@method",
     * are rejected loudly: a silently-dropped route is exactly the failure mode
     * this class exists to prevent.
     *
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        /** @var array<int, mixed> $rawRoutes */
        $rawRoutes = is_array($data['routes'] ?? null) ? $data['routes'] : [];

        $routes = [];

        foreach ($rawRoutes as $index => $rawRoute) {
            if (! is_array($rawRoute)) {
                throw new RuntimeException("Benchmark route manifest entry #{$index} is not an array.");
            }

            $action = trim((string) ($rawRoute['action'] ?? ''));
            $at = strrpos($action, '@');

            if ($action === '' || $at === false || $at === 0 || $at === strlen($action) - 1) {
                throw new RuntimeException(
                    "Benchmark route manifest entry #{$index} needs an action of the form 'Fully\\Qualified\\Controller@method'."
                );
            }

            /** @var array<int, string> $middleware */
            $middleware = array_values(array_map(
                static fn (mixed $name): string => (string) $name,
                is_array($rawRoute['middleware'] ?? null) ? $rawRoute['middleware'] : [],
            ));

            $routes[] = [
                'verb' => strtoupper(trim((string) ($rawRoute['verb'] ?? 'GET'))),
                'uri' => ltrim(trim((string) ($rawRoute['uri'] ?? '')), '/'),
                'controller' => ltrim(substr($action, 0, $at), '\\'),
                'method' => substr($action, $at + 1),
                'middleware' => $middleware,
            ];
        }

        return new self($routes);
    }

    /**
     * The manifest in the shape AccessControlContext consumes.
     *
     * Keyed "Fully\Qualified\Controller@method", with the route rendered the way
     * RuntimeIntrospector renders it.
     *
     * @return array<string, array{route: string, middleware: array<int, string>}>
     */
    public function routedMethods(): array
    {
        $methods = [];

        foreach ($this->routes as $route) {
            $methods[$route['controller'].'@'.$route['method']] = [
                'route' => $route['verb'].' /'.$route['uri'],
                'middleware' => $route['middleware'],
            ];
        }

        return $methods;
    }

    /**
     * The read-only context the deterministic detectors consume for the corpus.
     *
     * The corpus ships no Policy classes, so the policy maps stay empty unless a
     * caller supplies them. Empty is honest here: a detector that needs to know
     * an ability exists will correctly stay silent rather than invent one.
     *
     * @param  array<int, string>  $modelsWithPolicy
     * @param  array<string, array<int, string>>  $policyAbilities
     */
    public function context(array $modelsWithPolicy = [], array $policyAbilities = []): AccessControlContext
    {
        return new AccessControlContext(
            routedMethods: $this->routedMethods(),
            modelsWithPolicy: $modelsWithPolicy,
            policyAbilities: $policyAbilities,
        );
    }

    /**
     * Register every manifest entry on a Router.
     *
     * The controller classes named here do not exist as loadable PHP — they are
     * fixture text in a samples directory — and they deliberately never need to.
     * Laravel resolves a controller only when a request is dispatched; route
     * registration and middleware gathering are pure string work, and the
     * scanner only ever reads the route table.
     */
    public function registerInto(Router $router): void
    {
        foreach ($this->routes as $route) {
            $router->addRoute(
                [$route['verb']],
                $route['uri'],
                $route['controller'].'@'.$route['method'],
            )->middleware($route['middleware']);
        }
    }

    /**
     * Every "Controller@method" the manifest declares, fully qualified.
     *
     * @return array<int, string>
     */
    public function actions(): array
    {
        return array_keys($this->routedMethods());
    }

    /**
     * Whether the manifest routes the given controller action.
     *
     * The class may be given fully qualified or short, matching the way
     * AccessControlContext::routeFor() resolves a parsed class back to a route.
     */
    public function covers(string $controllerClass, string $method): bool
    {
        $wanted = self::shortName($controllerClass);

        foreach ($this->routes as $route) {
            if ($route['method'] === $method && self::shortName($route['controller']) === $wanted) {
                return true;
            }
        }

        return false;
    }

    /**
     * Trailing segment of a (possibly namespaced) class name.
     */
    private static function shortName(string $class): string
    {
        $class = ltrim($class, '\\');
        $position = strrpos($class, '\\');

        return $position === false ? $class : substr($class, $position + 1);
    }
}
