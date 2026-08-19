<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

/**
 * Reads a Laravel Policy class and reports the abilities it ACTUALLY defines.
 *
 * The existence of a Policy class says nothing about which abilities it
 * defines. A RoomPolicy that declares view/update/delete/manageImage does not
 * define `store` or `create`, so no `store` authorization can be missing from a
 * controller and no `$this->authorize('store', ...)` can be suggested — that
 * call would throw at runtime and break the endpoint it claimed to protect.
 *
 * Advice built on this inspector may only name abilities the Policy declares.
 */
final class PolicyInspector
{
    /**
     * Policy methods that are lifecycle hooks, not abilities.
     *
     * @var array<int, string>
     */
    private const NON_ABILITY_METHODS = ['before', 'after', 'allow', 'deny', 'denyaspublic', 'denyasnotfound', 'denywithstatus'];

    /**
     * Whether the class looks like a Policy: named *Policy, or every public
     * method takes a user-ish first parameter. Only the name convention is
     * asserted here — Laravel itself resolves policies by convention or by an
     * explicit registration we cannot see from source alone.
     */
    public function isPolicy(ClassShape $class): bool
    {
        return str_ends_with($class->shortName(), 'Policy');
    }

    /**
     * Ability names the Policy defines, in declaration order.
     *
     * @return array<int, string>
     */
    public function abilities(ClassShape $class): array
    {
        $abilities = [];

        foreach ($class->publicMethods() as $method) {
            if (in_array(strtolower($method->name()), self::NON_ABILITY_METHODS, true)) {
                continue;
            }

            $abilities[] = $method->name();
        }

        return $abilities;
    }

    /**
     * Whether the Policy defines an ability, compared case-insensitively the
     * way Laravel resolves a Gate ability to a policy method.
     */
    public function hasAbility(ClassShape $class, string $ability): bool
    {
        foreach ($this->abilities($class) as $declared) {
            if (strtolower($declared) === strtolower($ability)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The MethodShape backing an ability, so a finding can cite its real line.
     */
    public function ability(ClassShape $class, string $ability): ?MethodShape
    {
        foreach ($class->publicMethods() as $method) {
            if (strtolower($method->name()) === strtolower($ability)
                && ! in_array(strtolower($method->name()), self::NON_ABILITY_METHODS, true)) {
                return $method;
            }
        }

        return null;
    }

    /**
     * The model class the Policy governs, taken from the type hint that the
     * majority of its abilities declare for the subject parameter, falling back
     * to the FooPolicy => Foo naming convention.
     */
    public function modelFor(ClassShape $class): ?string
    {
        $counts = [];

        foreach ($class->publicMethods() as $method) {
            if (in_array(strtolower($method->name()), self::NON_ABILITY_METHODS, true)) {
                continue;
            }

            $parameters = $method->parameters();

            foreach (array_slice($parameters, 1) as $parameter) {
                $type = $parameter->classType($class->file());

                if ($type === null) {
                    continue;
                }

                $counts[$type] = ($counts[$type] ?? 0) + 1;

                break;
            }
        }

        if ($counts !== []) {
            arsort($counts);

            return array_key_first($counts);
        }

        $short = $class->shortName();

        if (str_ends_with($short, 'Policy')) {
            $model = substr($short, 0, -strlen('Policy'));

            return $model === '' ? null : $model;
        }

        return null;
    }
}
