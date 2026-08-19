<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

use PhpParser\Modifiers;
use PhpParser\Node;

/**
 * One declared parameter with its resolved type.
 *
 * The type is the whole point: `show(int $id)` and `show(Room $room)` are the
 * same shape to a regex and completely different to an access-control
 * detector. The first is a raw route segment the client chose; the second is a
 * route-model-bound record the framework already resolved.
 */
final class ParameterShape
{
    /**
     * @param  array<int, string>  $types  Resolved declared types (union members included)
     */
    public function __construct(
        private readonly Node\Param $node,
        private readonly string $name,
        private readonly array $types,
        private readonly bool $nullable,
        private readonly ?string $docType,
    ) {}

    public function node(): Node\Param
    {
        return $this->node;
    }

    /**
     * Parameter name without the leading `$`.
     */
    public function name(): string
    {
        return $this->name;
    }

    /**
     * Parameter name with the leading `$`, for quoting in a finding.
     */
    public function variable(): string
    {
        return '$'.$this->name;
    }

    /**
     * Every declared type; empty when the parameter has no type hint.
     *
     * @return array<int, string>
     */
    public function types(): array
    {
        return $this->types;
    }

    /**
     * The single declared type, or null when untyped or a union.
     */
    public function type(): ?string
    {
        return count($this->types) === 1 ? $this->types[0] : null;
    }

    /**
     * The declared class type, falling back to a `@param` docblock type when
     * the signature itself is untyped.
     */
    public function classType(ParsedFile $file): ?string
    {
        $type = $this->type();

        if ($type !== null && TypeNames::isClass($type)) {
            return $type;
        }

        if ($type !== null) {
            return null;
        }

        return DocBlock::resolveClass($this->docType, $file);
    }

    public function docType(): ?string
    {
        return $this->docType;
    }

    public function isNullable(): bool
    {
        return $this->nullable;
    }

    public function isTyped(): bool
    {
        return $this->types !== [];
    }

    /**
     * Whether every declared type is a builtin scalar (int/float/string/bool).
     * An untyped parameter is NOT scalar — it is unknown.
     */
    public function isScalar(): bool
    {
        if ($this->types === []) {
            return false;
        }

        foreach ($this->types as $type) {
            if (! in_array($type, ['int', 'float', 'string', 'bool'], true)) {
                return false;
            }
        }

        return true;
    }

    public function isPromoted(): bool
    {
        return $this->node->flags !== 0;
    }

    public function isVariadic(): bool
    {
        return $this->node->variadic;
    }

    public function hasDefault(): bool
    {
        return $this->node->default !== null;
    }

    public function line(): int
    {
        return $this->node->getStartLine();
    }

    /**
     * Visibility of a constructor-promoted property, or null when the
     * parameter is not promoted.
     */
    public function visibility(): ?string
    {
        if (! $this->isPromoted()) {
            return null;
        }

        if (($this->node->flags & Modifiers::PRIVATE) !== 0) {
            return 'private';
        }

        if (($this->node->flags & Modifiers::PROTECTED) !== 0) {
            return 'protected';
        }

        return 'public';
    }

    /**
     * Build a shape from a Param node, resolving its type against the file.
     */
    public static function fromNode(Node\Param $node, ParsedFile $file, ?string $docType): ?self
    {
        if (! $node->var instanceof Node\Expr\Variable || ! is_string($node->var->name)) {
            return null;
        }

        return new self(
            node: $node,
            name: $node->var->name,
            types: TypeNames::toStrings($node->type, $file),
            nullable: TypeNames::isNullable($node->type),
            docType: $docType,
        );
    }
}
