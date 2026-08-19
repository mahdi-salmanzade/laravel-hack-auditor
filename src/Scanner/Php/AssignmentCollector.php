<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

use PhpParser\Node;
use PhpParser\NodeVisitor;
use PhpParser\NodeVisitorAbstract;

/**
 * Collects, in source order, every assignment to a simple local variable
 * inside ONE function scope.
 *
 * Nested scopes (closures, arrow functions, anonymous classes, nested
 * functions) are deliberately not descended into: their variables are a
 * different scope, and pretending otherwise is how a "tainted" variable gets
 * attributed to code that never saw it.
 *
 * @internal
 */
final class AssignmentCollector extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{name: string, line: int, expr: Node\Expr, append: bool, iterated: bool}>
     */
    public array $assignments = [];

    public function enterNode(Node $node): ?int
    {
        if ($node instanceof Node\Expr\Closure
            || $node instanceof Node\Expr\ArrowFunction
            || $node instanceof Node\Stmt\Function_
            || $node instanceof Node\Stmt\ClassLike) {
            return NodeVisitor::DONT_TRAVERSE_CHILDREN;
        }

        if ($node instanceof Node\Expr\Assign) {
            $this->recordTarget($node->var, $node->expr, $node->getStartLine(), false, false);

            return null;
        }

        if ($node instanceof Node\Expr\AssignOp) {
            $this->recordTarget($node->var, $node->expr, $node->getStartLine(), true, false);

            return null;
        }

        if ($node instanceof Node\Stmt\Foreach_) {
            $this->recordTarget($node->valueVar, $node->expr, $node->getStartLine(), false, true);
        }

        return null;
    }

    private function recordTarget(Node\Expr $target, Node\Expr $value, int $line, bool $append, bool $iterated): void
    {
        if ($target instanceof Node\Expr\Variable && is_string($target->name)) {
            $this->assignments[] = [
                'name' => $target->name,
                'line' => $line,
                'expr' => $value,
                'append' => $append,
                'iterated' => $iterated,
            ];

            return;
        }

        if ($target instanceof Node\Expr\List_ || $target instanceof Node\Expr\Array_) {
            foreach ($target->items as $item) {
                if ($item === null) {
                    continue;
                }

                $this->recordTarget($item->value, $value, $line, $append, true);
            }
        }
    }
}
