<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

/**
 * The outcome of resolving an expression's type, together with the evidence
 * for it.
 *
 * `unknown()` is a first-class, expected answer. A detector that receives it
 * must stay silent: not knowing what a receiver is means there is no basis for
 * a finding, and silence is always the correct fallback.
 */
final class ResolvedType
{
    private function __construct(
        public readonly ?string $class,
        public readonly ?string $builtin,
        public readonly string $evidence,
    ) {}

    public static function classType(string $fqcn, string $evidence): self
    {
        return new self(ltrim($fqcn, '\\'), null, $evidence);
    }

    public static function builtinType(string $name, string $evidence): self
    {
        return new self(null, strtolower($name), $evidence);
    }

    public static function unknown(string $evidence = 'the receiver type could not be resolved'): self
    {
        return new self(null, null, $evidence);
    }

    /**
     * Build the right variant from a resolved type name.
     */
    public static function named(string $name, string $evidence): self
    {
        return TypeNames::isBuiltin($name)
            ? self::builtinType($name, $evidence)
            : self::classType($name, $evidence);
    }

    public function isKnown(): bool
    {
        return $this->class !== null || $this->builtin !== null;
    }

    public function isClass(): bool
    {
        return $this->class !== null;
    }

    public function is(string $fqcn): bool
    {
        return $this->class !== null && $this->class === ltrim($fqcn, '\\');
    }

    /**
     * @param  array<int, string>  $fqcns
     */
    public function isAnyOf(array $fqcns): bool
    {
        foreach ($fqcns as $fqcn) {
            if ($this->is($fqcn)) {
                return true;
            }
        }

        return false;
    }

    public function shortName(): ?string
    {
        return $this->class === null ? null : TypeNames::shortName($this->class);
    }

    public function describe(): string
    {
        return $this->class ?? $this->builtin ?? 'unknown';
    }
}
