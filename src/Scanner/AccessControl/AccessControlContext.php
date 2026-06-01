<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\AccessControl;

/**
 * Read-only context shared with every access-control detector.
 *
 * Carries optionally-introspected route metadata (controller method => route
 * description + middleware) and the set of models that have a Policy class.
 * All of this is derived without booting the database — route data comes from
 * the Laravel Router, policy presence from the filesystem.
 */
final class AccessControlContext
{
    /**
     * @param  array<string, array{route: string, middleware: array<int, string>}>  $routedMethods
     *                                                                                              Keyed by "FQCN@method" (or "ShortClass@method").
     * @param  array<int, string>  $modelsWithPolicy  Short model names that have a Policy class.
     */
    public function __construct(
        public readonly array $routedMethods = [],
        public readonly array $modelsWithPolicy = [],
    ) {}

    /**
     * Whether a Policy class exists for the given short model name.
     */
    public function hasPolicyFor(string $shortModelName): bool
    {
        return in_array($shortModelName, $this->modelsWithPolicy, true);
    }

    /**
     * Get the route metadata for a controller method by short class + method.
     *
     * Matches on the "@method" suffix and short class name so it works whether
     * the routedMethods map is keyed by FQCN or short class name.
     *
     * @return array{route: string, middleware: array<int, string>}|null
     */
    public function routeFor(string $shortClass, string $method): ?array
    {
        foreach ($this->routedMethods as $key => $meta) {
            if (! str_ends_with($key, '@'.$method)) {
                continue;
            }

            $classPart = substr($key, 0, (int) strrpos($key, '@'));
            $classShort = $classPart;

            if (str_contains($classPart, '\\')) {
                $parts = explode('\\', $classPart);
                $classShort = end($parts);
            }

            if ($classShort === $shortClass) {
                return $meta;
            }
        }

        return null;
    }
}
