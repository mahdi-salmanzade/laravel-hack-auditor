<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\AccessControl;

/**
 * Read-only context shared with every access-control detector.
 *
 * Carries optionally-introspected route metadata (controller method => route
 * description + middleware), the set of models that have a Policy class, and —
 * crucially — the ABILITIES each of those Policy classes actually declares.
 * All of this is derived without booting the database — route data comes from
 * the Laravel Router, policy data from parsing app/Policies on disk.
 *
 * "A Policy class exists for this model" is not on its own actionable. A
 * RoomPolicy that declares view/update/delete/manageImage declares no `create`
 * ability, so a store() action cannot be bypassing a policy that does not
 * exist, and no `$this->authorize('store', $room)` can be advised — that call
 * would throw at runtime and break the endpoint it claimed to protect. Only
 * `policyDefinesAbility()` can justify a finding; `hasPolicyFor()` cannot.
 */
final class AccessControlContext
{
    /**
     * Declared abilities keyed by lowercased short model name.
     *
     * @var array<string, array<int, string>>
     */
    private readonly array $abilitiesByModel;

    /**
     * @param  array<string, array{route: string, middleware: array<int, string>}>  $routedMethods
     *                                                                                              Keyed by "FQCN@method" (or "ShortClass@method").
     * @param  array<int, string>  $modelsWithPolicy  Short model names that have a Policy class.
     * @param  array<string, array<int, string>>  $policyAbilities  Model name (short or fully qualified) => ability
     *                                                              method names its Policy declares. A model absent
     *                                                              from this map has an UNKNOWN ability list, which is
     *                                                              never the same thing as an empty one.
     */
    public function __construct(
        public readonly array $routedMethods = [],
        public readonly array $modelsWithPolicy = [],
        public readonly array $policyAbilities = [],
    ) {
        $normalised = [];

        foreach ($policyAbilities as $model => $abilities) {
            $normalised[self::normaliseModel($model)] = array_values($abilities);
        }

        $this->abilitiesByModel = $normalised;
    }

    /**
     * Whether a Policy class exists for the given short model name.
     *
     * Deliberately NOT sufficient grounds for a finding: it says nothing about
     * which abilities the Policy declares. Use policyDefinesAbility().
     */
    public function hasPolicyFor(string $shortModelName): bool
    {
        return in_array($shortModelName, $this->modelsWithPolicy, true);
    }

    /**
     * Whether the ability list for this model was actually introspected.
     *
     * False means "we did not read the Policy", which a detector must treat as
     * "no evidence" and stay silent about — not as "the Policy is empty".
     */
    public function knowsAbilitiesFor(string $model): bool
    {
        return array_key_exists(self::normaliseModel($model), $this->abilitiesByModel);
    }

    /**
     * Ability method names the model's Policy declares, in declaration order.
     * An empty list means either an unread Policy or one with no abilities;
     * knowsAbilitiesFor() separates the two.
     *
     * @return array<int, string>
     */
    public function abilitiesFor(string $model): array
    {
        return $this->abilitiesByModel[self::normaliseModel($model)] ?? [];
    }

    /**
     * Whether the model's Policy declares a specific ability, compared the way
     * Laravel resolves a Gate ability onto a policy method (case-insensitively).
     */
    public function policyDefinesAbility(string $model, string $ability): bool
    {
        foreach ($this->abilitiesFor($model) as $declared) {
            if (strtolower($declared) === strtolower($ability)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Lowercased short name, so 'App\Models\Room', 'Room' and 'room' agree.
     */
    private static function normaliseModel(string $model): string
    {
        $model = ltrim($model, '\\');
        $position = strrpos($model, '\\');

        return strtolower($position === false ? $model : substr($model, $position + 1));
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
