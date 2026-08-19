<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

use PhpParser\Node;

/**
 * Converts PHP-Parser type nodes into resolved type strings.
 *
 * Class types come back fully qualified (resolved through the file's imports
 * and namespace), builtin types come back lowercased. A union or intersection
 * yields every member, so a caller can require that ALL members satisfy a
 * predicate rather than guessing from the first one.
 */
final class TypeNames
{
    /**
     * Builtin (non-class) type names, lowercased.
     *
     * @var array<int, string>
     */
    private const BUILTIN = [
        'int', 'float', 'string', 'bool', 'array', 'object', 'mixed', 'void',
        'never', 'null', 'false', 'true', 'callable', 'iterable', 'self',
        'static', 'parent',
    ];

    /**
     * Every member type named by a type node, resolved.
     *
     * @return array<int, string>
     */
    public static function toStrings(?Node $type, ParsedFile $file): array
    {
        if ($type === null) {
            return [];
        }

        if ($type instanceof Node\NullableType) {
            return self::toStrings($type->type, $file);
        }

        if ($type instanceof Node\UnionType || $type instanceof Node\IntersectionType) {
            $names = [];

            foreach ($type->types as $member) {
                foreach (self::toStrings($member, $file) as $name) {
                    $names[] = $name;
                }
            }

            return array_values(array_unique($names));
        }

        if ($type instanceof Node\Identifier) {
            return [strtolower($type->toString())];
        }

        if ($type instanceof Node\Name) {
            return [$file->resolveName($type)];
        }

        return [];
    }

    /**
     * The single declared type, or null when the node is absent or a union.
     */
    public static function single(?Node $type, ParsedFile $file): ?string
    {
        $names = self::toStrings($type, $file);

        if (count($names) !== 1) {
            return null;
        }

        $name = $names[0];

        return $name === 'null' ? null : $name;
    }

    public static function isNullable(?Node $type): bool
    {
        if ($type instanceof Node\NullableType) {
            return true;
        }

        if ($type instanceof Node\UnionType) {
            foreach ($type->types as $member) {
                if ($member instanceof Node\Identifier && strtolower($member->toString()) === 'null') {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Whether the resolved name is a PHP builtin rather than a class type.
     */
    public static function isBuiltin(string $name): bool
    {
        return in_array(strtolower($name), self::BUILTIN, true);
    }

    /**
     * Whether the resolved name denotes a class (i.e. is not a builtin).
     */
    public static function isClass(string $name): bool
    {
        return ! self::isBuiltin($name);
    }

    /**
     * Short (unqualified) form of a fully-qualified name.
     */
    public static function shortName(string $fqcn): string
    {
        $position = strrpos($fqcn, '\\');

        return $position === false ? $fqcn : substr($fqcn, $position + 1);
    }
}
