<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

use PhpParser\Modifiers;
use PhpParser\Node;

/**
 * One declared class-like: its name, its ancestry, its methods and the typed
 * properties a receiver can be resolved through.
 *
 * Property resolution is deliberately exhaustive over the three ways a Laravel
 * class states what a dependency is — constructor promotion, a typed property
 * declaration, and an `@var` docblock — because that is the only way to tell
 * `$this->http->get(...)` (an outbound HTTP request) from
 * `$this->imageUpload->delete(...)` (a local storage call).
 */
final class ClassShape
{
    /**
     * @var array<string, MethodShape>|null
     */
    private ?array $methods = null;

    /**
     * @var array<string, PropertyShape>|null
     */
    private ?array $properties = null;

    public function __construct(
        private readonly ParsedFile $file,
        private readonly Node\Stmt\ClassLike $node,
    ) {}

    public function file(): ParsedFile
    {
        return $this->file;
    }

    public function node(): Node\Stmt\ClassLike
    {
        return $this->node;
    }

    public function shortName(): string
    {
        return $this->node->name?->toString() ?? '';
    }

    public function fqcn(): string
    {
        $namespaced = $this->node->namespacedName;

        return $namespaced instanceof Node\Name ? $namespaced->toString() : $this->shortName();
    }

    public function startLine(): int
    {
        return $this->node->getStartLine();
    }

    /**
     * Whether the declaration is a plain `class` — not an interface, a trait or
     * an enum.
     */
    public function isClass(): bool
    {
        return $this->node instanceof Node\Stmt\Class_;
    }

    public function isInterface(): bool
    {
        return $this->node instanceof Node\Stmt\Interface_;
    }

    public function isAbstract(): bool
    {
        return $this->node instanceof Node\Stmt\Class_ && $this->node->isAbstract();
    }

    /**
     * Resolved name of the parent class, if the class extends one.
     */
    public function parentClass(): ?string
    {
        if ($this->node instanceof Node\Stmt\Class_ && $this->node->extends instanceof Node\Name) {
            return $this->file->resolveName($this->node->extends);
        }

        return null;
    }

    /**
     * Resolved names of every implemented interface.
     *
     * @return array<int, string>
     */
    public function interfaces(): array
    {
        if (! $this->node instanceof Node\Stmt\Class_) {
            return [];
        }

        return array_map(
            fn (Node\Name $name): string => $this->file->resolveName($name),
            $this->node->implements,
        );
    }

    /**
     * Resolved names of every used trait.
     *
     * @return array<int, string>
     */
    public function traits(): array
    {
        $names = [];

        foreach ($this->node->stmts as $statement) {
            if (! $statement instanceof Node\Stmt\TraitUse) {
                continue;
            }

            foreach ($statement->traits as $trait) {
                $names[] = $this->file->resolveName($trait);
            }
        }

        return $names;
    }

    /**
     * Every declared method, keyed by lowercased name.
     *
     * @return array<string, MethodShape>
     */
    public function methods(): array
    {
        if ($this->methods !== null) {
            return $this->methods;
        }

        $methods = [];

        foreach ($this->node->stmts as $statement) {
            if (! $statement instanceof Node\Stmt\ClassMethod) {
                continue;
            }

            $methods[strtolower($statement->name->toString())] = new MethodShape($this->file, $this, $statement);
        }

        return $this->methods = $methods;
    }

    public function method(string $name): ?MethodShape
    {
        return $this->methods()[strtolower($name)] ?? null;
    }

    /**
     * Public, non-static, non-magic, concrete methods — the set a controller
     * exposes as actions.
     *
     * @return array<int, MethodShape>
     */
    public function publicMethods(): array
    {
        $methods = [];

        foreach ($this->methods() as $method) {
            if (! $method->isPublic() || $method->isStatic() || $method->isMagic() || $method->isAbstract()) {
                continue;
            }

            $methods[] = $method;
        }

        return $methods;
    }

    public function constructor(): ?MethodShape
    {
        return $this->method('__construct');
    }

    /**
     * Every property the class states a type for, keyed by name.
     *
     * @return array<string, PropertyShape>
     */
    public function properties(): array
    {
        if ($this->properties !== null) {
            return $this->properties;
        }

        $properties = [];

        foreach ($this->node->stmts as $statement) {
            if (! $statement instanceof Node\Stmt\Property) {
                continue;
            }

            $declaredTypes = TypeNames::toStrings($statement->type, $this->file);
            $docClass = DocBlock::resolveClass(
                DocBlock::varType($statement->getDocComment()?->getText()),
                $this->file,
            );

            foreach ($statement->props as $item) {
                $name = $item->name->toString();

                if ($declaredTypes !== []) {
                    $properties[$name] = new PropertyShape(
                        name: $name,
                        types: $declaredTypes,
                        origin: PropertyShape::ORIGIN_DECLARED,
                        line: $statement->getStartLine(),
                        visibility: $this->visibilityOf($statement->flags),
                    );

                    continue;
                }

                if ($docClass !== null) {
                    $properties[$name] = new PropertyShape(
                        name: $name,
                        types: [$docClass],
                        origin: PropertyShape::ORIGIN_DOCBLOCK,
                        line: $statement->getStartLine(),
                        visibility: $this->visibilityOf($statement->flags),
                    );
                }
            }
        }

        $constructor = $this->constructor();

        if ($constructor !== null) {
            foreach ($constructor->parameters() as $parameter) {
                if (! $parameter->isPromoted()) {
                    continue;
                }

                $type = $parameter->classType($this->file) ?? $parameter->type();

                if ($type === null) {
                    continue;
                }

                $properties[$parameter->name()] = new PropertyShape(
                    name: $parameter->name(),
                    types: [$type],
                    origin: PropertyShape::ORIGIN_PROMOTED,
                    line: $parameter->line(),
                    visibility: $parameter->visibility(),
                );
            }
        }

        return $this->properties = $properties;
    }

    public function property(string $name): ?PropertyShape
    {
        return $this->properties()[$name] ?? null;
    }

    /**
     * Resolved class type of a property, or null when it is untyped.
     */
    public function propertyClass(string $name): ?string
    {
        return $this->property($name)?->classType();
    }

    private function visibilityOf(int $flags): string
    {
        if (($flags & Modifiers::PRIVATE) !== 0) {
            return 'private';
        }

        if (($flags & Modifiers::PROTECTED) !== 0) {
            return 'protected';
        }

        return 'public';
    }
}
