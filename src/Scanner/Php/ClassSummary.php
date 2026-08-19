<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

/**
 * Everything a CROSS-FILE question needs to know about a declared class, with
 * no AST node attached.
 *
 * This is the object that makes a whole-application scan fit in memory. A
 * ClassShape is a view onto live AST nodes: holding one keeps its ParsedFile,
 * its token stream and every node in the file alive — roughly 0.2 MB. An index
 * built from ClassShapes therefore costs 0.2 MB per file and crossed PHP's
 * default 128M memory_limit at around 640 files, killing the process with a
 * fatal that no try/catch can intercept.
 *
 * A summary is a few hundred bytes and answers every question the index is
 * actually asked: what is this class called, what does it extend, what does it
 * implement, which traits does it use, is it abstract, is it an interface. Only
 * a question about a METHOD BODY needs real nodes, and that is served by
 * re-materialising a ClassShape through the bounded parser
 * (SourceRepository::classShape()) for the one class being examined.
 *
 * `path` is what makes re-materialisation possible: it names the file the class
 * was declared in, so the source can be handed back to the parser on demand.
 */
final class ClassSummary
{
    /**
     * @param  array<int, string>  $interfaces  Resolved interface names
     * @param  array<int, string>  $traits  Resolved trait names
     */
    public function __construct(
        private readonly string $path,
        private readonly string $fqcn,
        private readonly string $shortName,
        private readonly bool $isClass,
        private readonly bool $isInterface,
        private readonly bool $isAbstract,
        private readonly int $startLine,
        private readonly ?string $parentClass,
        private readonly array $interfaces,
        private readonly array $traits,
    ) {}

    /**
     * Capture a shape as a node-free summary. Every value is read here, once,
     * while the AST is still alive — including the start line, so a finding can
     * cite the exact declaration line without the nodes still being around.
     */
    public static function fromShape(ClassShape $class): self
    {
        return new self(
            path: $class->file()->path,
            fqcn: $class->fqcn(),
            shortName: $class->shortName(),
            isClass: $class->isClass(),
            isInterface: $class->isInterface(),
            isAbstract: $class->isAbstract(),
            startLine: $class->startLine(),
            parentClass: $class->parentClass(),
            interfaces: $class->interfaces(),
            traits: $class->traits(),
        );
    }

    /**
     * The file the class was declared in, used to re-open it on demand.
     */
    public function path(): string
    {
        return $this->path;
    }

    public function fqcn(): string
    {
        return $this->fqcn;
    }

    public function shortName(): string
    {
        return $this->shortName;
    }

    /**
     * Whether the declaration is a plain `class` — not an interface, a trait or
     * an enum. Only a class can be bound to a route, which is why pixelfed's
     * `*Controller` TRAITS must not be mistaken for controllers.
     */
    public function isClass(): bool
    {
        return $this->isClass;
    }

    public function isInterface(): bool
    {
        return $this->isInterface;
    }

    public function isAbstract(): bool
    {
        return $this->isAbstract;
    }

    public function startLine(): int
    {
        return $this->startLine;
    }

    public function parentClass(): ?string
    {
        return $this->parentClass;
    }

    /**
     * @return array<int, string>
     */
    public function interfaces(): array
    {
        return $this->interfaces;
    }

    /**
     * @return array<int, string>
     */
    public function traits(): array
    {
        return $this->traits;
    }
}
