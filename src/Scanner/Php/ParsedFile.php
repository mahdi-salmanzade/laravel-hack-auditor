<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\Token;

/**
 * One parsed PHP file: its annotated AST, its token stream, and the structural
 * queries every detector needs.
 *
 * An instance is either ANALYSED (parseError === null, nodes available) or
 * UNANALYSABLE (parseError set, every accessor returns empty). There is no
 * third state and no partial/guessed parse — a detector that receives an
 * unanalysable file must emit nothing.
 */
final class ParsedFile
{
    /**
     * @var array<int, ClassShape>|null
     */
    private ?array $classes = null;

    /**
     * @var array<string, string>|null
     */
    private ?array $useMap = null;

    /**
     * @param  array<int, Node\Stmt>  $statements
     * @param  array<int, Token>  $tokens
     */
    private function __construct(
        public readonly string $path,
        public readonly string $source,
        private readonly array $statements,
        private readonly array $tokens,
        public readonly ?string $parseError,
    ) {}

    /**
     * @param  array<int, Node\Stmt>  $statements
     * @param  array<int, Token>  $tokens
     */
    public static function analysed(string $path, string $source, array $statements, array $tokens): self
    {
        return new self($path, $source, $statements, $tokens, null);
    }

    /**
     * A file we refuse to reason about. Yields no classes and no methods.
     */
    public static function unanalysable(string $path, string $source, string $reason): self
    {
        return new self($path, $source, [], [], $reason);
    }

    public function isAnalysable(): bool
    {
        return $this->parseError === null;
    }

    /**
     * @return array<int, Node\Stmt>
     */
    public function statements(): array
    {
        return $this->statements;
    }

    /**
     * @return array<int, Token>
     */
    public function tokens(): array
    {
        return $this->tokens;
    }

    /**
     * The namespace declared by the file, if any.
     */
    public function namespaceName(): ?string
    {
        foreach ($this->finder()->findInstanceOf($this->statements, Node\Stmt\Namespace_::class) as $namespace) {
            if ($namespace->name !== null) {
                return $namespace->name->toString();
            }
        }

        return null;
    }

    /**
     * Import aliases declared by the file: alias => fully-qualified name.
     *
     * Name resolution already uses these; the map is exposed so a finding can
     * cite the import that proves a type ("imported as `use GuzzleHttp\Client;`").
     *
     * @return array<string, string>
     */
    public function useMap(): array
    {
        if ($this->useMap !== null) {
            return $this->useMap;
        }

        $map = [];

        foreach ($this->finder()->findInstanceOf($this->statements, Node\Stmt\Use_::class) as $use) {
            foreach ($use->uses as $item) {
                $map[$item->getAlias()->toString()] = $item->name->toString();
            }
        }

        foreach ($this->finder()->findInstanceOf($this->statements, Node\Stmt\GroupUse::class) as $group) {
            foreach ($group->uses as $item) {
                $map[$item->getAlias()->toString()] = $group->prefix->toString().'\\'.$item->name->toString();
            }
        }

        return $this->useMap = $map;
    }

    /**
     * Every named class-like declaration in the file (classes, interfaces,
     * traits and enums). Anonymous classes are excluded.
     *
     * @return array<int, ClassShape>
     */
    public function classes(): array
    {
        if ($this->classes !== null) {
            return $this->classes;
        }

        $shapes = [];

        foreach ($this->finder()->findInstanceOf($this->statements, Node\Stmt\ClassLike::class) as $node) {
            if ($node->name === null) {
                continue;
            }

            $shapes[] = new ClassShape($this, $node);
        }

        return $this->classes = $shapes;
    }

    /**
     * The first named class-like declaration, which for PSR-4 source is the
     * class the file is about.
     */
    public function primaryClass(): ?ClassShape
    {
        return $this->classes()[0] ?? null;
    }

    /**
     * Look up a declared class by short name or fully-qualified name.
     */
    public function classNamed(string $name): ?ClassShape
    {
        foreach ($this->classes() as $class) {
            if ($class->shortName() === $name || $class->fqcn() === ltrim($name, '\\')) {
                return $class;
            }
        }

        return null;
    }

    /**
     * Fully-qualified form of a Name node, using the resolution attached at
     * parse time (imports, current namespace, global fallback).
     */
    public function resolveName(Node\Name $name): string
    {
        $resolved = $name->getAttribute('resolvedName');

        if ($resolved instanceof Node\Name) {
            return $resolved->toString();
        }

        return $name->toString();
    }

    /**
     * The 1-based line of the first token of the given id inside a node's own
     * token range — the exact way to locate a keyword such as `function`
     * without ever measuring a byte offset into raw text.
     */
    public function lineOfTokenIn(Node $node, int $tokenId): ?int
    {
        $start = $node->getAttribute('startTokenPos');
        $end = $node->getAttribute('endTokenPos');

        if (! is_int($start) || ! is_int($end)) {
            return null;
        }

        for ($position = $start; $position <= $end; $position++) {
            $token = $this->tokens[$position] ?? null;

            if ($token === null) {
                return null;
            }

            if ($token->id === $tokenId) {
                return $token->line;
            }
        }

        return null;
    }

    private function finder(): NodeFinder
    {
        return new NodeFinder;
    }
}
