<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

use PhpParser\Modifiers;
use PhpParser\Node;

/**
 * One declared method: its exact source lines, its typed parameters, and its
 * body statements.
 *
 * Line numbers come from the AST and the token stream, never from a byte
 * offset into raw text. `declarationLine()` is the line of the `function`
 * keyword itself, so a docblock above the method, an attribute, or a
 * multi-line signature cannot shift it.
 */
final class MethodShape
{
    /**
     * @var array<int, ParameterShape>|null
     */
    private ?array $parameters = null;

    public function __construct(
        private readonly ParsedFile $file,
        private readonly ClassShape $class,
        private readonly Node\Stmt\ClassMethod $node,
    ) {}

    public function node(): Node\Stmt\ClassMethod
    {
        return $this->node;
    }

    public function file(): ParsedFile
    {
        return $this->file;
    }

    public function class(): ClassShape
    {
        return $this->class;
    }

    public function name(): string
    {
        return $this->node->name->toString();
    }

    /**
     * A stable cache key for this method: file, class, name and start line.
     *
     * Deliberately NOT spl_object_id(). Object ids are recycled the moment an
     * object is freed, and freeing ASTs is exactly what a bounded parser cache
     * does — a per-method cache keyed on an id would start answering with
     * another method's analysis as soon as the first eviction happened. A key
     * derived from the source is immune to that; callers still compare the
     * cached MethodShape by identity before trusting an entry, so a re-parsed
     * file can never be served analysis built over a different syntax tree.
     */
    public function identity(): string
    {
        return $this->file->path.'::'.$this->class->fqcn().'::'.$this->name().'@'.$this->node->getStartLine();
    }

    /**
     * The 1-based line of the `function` keyword.
     *
     * This is the line a finding about "the method" must report. It is taken
     * from the method's own token range, so leading docblocks, attributes and
     * multi-line parameter lists are all irrelevant to it.
     */
    public function declarationLine(): int
    {
        return $this->file->lineOfTokenIn($this->node, T_FUNCTION) ?? $this->node->getStartLine();
    }

    /**
     * Start line of the node, which includes any attribute groups.
     */
    public function startLine(): int
    {
        return $this->node->getStartLine();
    }

    public function endLine(): int
    {
        return $this->node->getEndLine();
    }

    public function isPublic(): bool
    {
        return ($this->node->flags & Modifiers::PRIVATE) === 0
            && ($this->node->flags & Modifiers::PROTECTED) === 0;
    }

    public function isStatic(): bool
    {
        return ($this->node->flags & Modifiers::STATIC) !== 0;
    }

    public function isAbstract(): bool
    {
        return ($this->node->flags & Modifiers::ABSTRACT) !== 0 || $this->node->stmts === null;
    }

    public function isMagic(): bool
    {
        return str_starts_with($this->name(), '__');
    }

    public function isConstructor(): bool
    {
        return strtolower($this->name()) === '__construct';
    }

    /**
     * @return array<int, ParameterShape>
     */
    public function parameters(): array
    {
        if ($this->parameters !== null) {
            return $this->parameters;
        }

        $docTypes = DocBlock::paramTypes($this->node->getDocComment()?->getText());
        $shapes = [];

        foreach ($this->node->params as $param) {
            $name = $param->var instanceof Node\Expr\Variable && is_string($param->var->name)
                ? $param->var->name
                : null;

            $shape = ParameterShape::fromNode($param, $this->file, $name === null ? null : ($docTypes[$name] ?? null));

            if ($shape !== null) {
                $shapes[] = $shape;
            }
        }

        return $this->parameters = $shapes;
    }

    public function parameter(string $name): ?ParameterShape
    {
        $name = ltrim($name, '$');

        foreach ($this->parameters() as $parameter) {
            if ($parameter->name() === $name) {
                return $parameter;
            }
        }

        return null;
    }

    /**
     * The declared return type, or null when absent or a union.
     */
    public function returnType(): ?string
    {
        return TypeNames::single($this->node->returnType, $this->file);
    }

    public function docComment(): ?string
    {
        return $this->node->getDocComment()?->getText();
    }

    /**
     * Body statements, or an empty list for an abstract/interface method.
     *
     * @return array<int, Node\Stmt>
     */
    public function statements(): array
    {
        return $this->node->stmts ?? [];
    }
}
