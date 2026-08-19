<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

/**
 * One class property with a resolved type and the EVIDENCE for that type.
 *
 * The evidence matters as much as the type. When a detector claims
 * `$this->imageUpload` is a local storage service rather than an HTTP client,
 * it must be able to say why — "constructor-promoted property typed
 * App\Services\ImageUploadService" — and that sentence must be true.
 */
final class PropertyShape
{
    public const ORIGIN_PROMOTED = 'promoted';

    public const ORIGIN_DECLARED = 'declared';

    public const ORIGIN_DOCBLOCK = 'docblock';

    /**
     * @param  array<int, string>  $types
     */
    public function __construct(
        private readonly string $name,
        private readonly array $types,
        private readonly string $origin,
        private readonly int $line,
        private readonly ?string $visibility,
    ) {}

    public function name(): string
    {
        return $this->name;
    }

    /**
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
     * The single declared CLASS type, or null when untyped, builtin or a union.
     */
    public function classType(): ?string
    {
        $type = $this->type();

        return $type !== null && TypeNames::isClass($type) ? $type : null;
    }

    /**
     * How the type was established: a promoted constructor parameter, a typed
     * property declaration, or an `@var` docblock.
     */
    public function origin(): string
    {
        return $this->origin;
    }

    public function line(): int
    {
        return $this->line;
    }

    public function visibility(): ?string
    {
        return $this->visibility;
    }

    /**
     * Human-readable justification for the resolved type, quotable in a finding.
     */
    public function evidence(): string
    {
        $type = $this->type() ?? 'an unknown type';

        return match ($this->origin) {
            self::ORIGIN_PROMOTED => sprintf('$this->%s is a constructor-promoted property typed %s (line %d)', $this->name, $type, $this->line),
            self::ORIGIN_DECLARED => sprintf('$this->%s is a typed property declared %s (line %d)', $this->name, $type, $this->line),
            default => sprintf('$this->%s is documented as %s (line %d)', $this->name, $type, $this->line),
        };
    }
}
