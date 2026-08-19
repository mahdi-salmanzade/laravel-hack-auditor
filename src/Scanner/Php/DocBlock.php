<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

/**
 * Minimal reader for the two docblock tags that carry type information the
 * PHP type system may not: `@param` and `@var`.
 *
 * This is the ONLY place in the semantic layer where a pattern is applied to
 * text, and it is applied to a DOCBLOCK STRING that the parser already isolated
 * for us — never to PHP source. A docblock is prose with a documented grammar;
 * PHP source is not, which is why every other structural question in this
 * package is answered from AST nodes.
 */
final class DocBlock
{
    /**
     * Map of parameter name (without `$`) => declared docblock type.
     *
     * @return array<string, string>
     */
    public static function paramTypes(?string $docComment): array
    {
        if ($docComment === null || $docComment === '') {
            return [];
        }

        if (preg_match_all('/@param\s+([^\s$]+)\s+\$(\w+)/', $docComment, $matches, PREG_SET_ORDER) === 0) {
            return [];
        }

        $types = [];

        foreach ($matches as $match) {
            $types[$match[2]] = trim($match[1]);
        }

        return $types;
    }

    /**
     * The `@var` type declared by a docblock, if any.
     */
    public static function varType(?string $docComment): ?string
    {
        if ($docComment === null || $docComment === '') {
            return null;
        }

        if (preg_match('/@var\s+([^\s*]+)/', $docComment, $match) !== 1) {
            return null;
        }

        $type = trim($match[1]);

        return $type === '' ? null : $type;
    }

    /**
     * Resolve a docblock type expression to a single class name, using the
     * file's imports. Returns null for unions, generics, builtins, and
     * anything else that does not name exactly one class.
     */
    public static function resolveClass(?string $type, ParsedFile $file): ?string
    {
        if ($type === null) {
            return null;
        }

        $type = ltrim(trim($type), '?');

        if ($type === '' || str_contains($type, '|') || str_contains($type, '&') || str_contains($type, '<')) {
            return null;
        }

        if (str_ends_with($type, '[]')) {
            return null;
        }

        if (TypeNames::isBuiltin($type)) {
            return null;
        }

        if (str_starts_with($type, '\\')) {
            return ltrim($type, '\\');
        }

        $imports = $file->useMap();
        $head = explode('\\', $type)[0];

        if (isset($imports[$head])) {
            $tail = substr($type, strlen($head));

            return $imports[$head].$tail;
        }

        $namespace = $file->namespaceName();

        return $namespace === null ? $type : $namespace.'\\'.$type;
    }
}
