<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

use PhpParser\Node;

/**
 * Whether a variable a fix wants to quote back is GUARANTEED to hold a value at
 * the point that fix would be inserted.
 *
 * WHY THIS EXISTS
 * ---------------
 * A fix string is executable advice. A reader applies it verbatim. Naming a
 * variable that is not bound at the insertion point does not produce a warning
 * in production — it produces `null`, and `$this->authorize('delete', null)`
 * throws AuthorizationException, so EVERY successful request 403s. That is the
 * incident this class exists to make structurally impossible.
 *
 * Scope-awareness alone is not enough. Refusing variables bound inside a
 * Closure or ArrowFunction (a different variable scope) catches
 * `DB::transaction(function () { $contract = ...; })` and nothing else, because
 * try/catch, match arms, switch cases, loop bodies and if branches do NOT open
 * a new scope in PHP. An assignment in any of those is in the method's own
 * scope and yet only CONDITIONALLY reached:
 *
 *   try { ... } catch (Throwable $e) { $ledger = Ledger::find($id); }
 *       // happy path: $ledger was never assigned
 *   match ($mode) { 'soft' => $voucher = ..., default => null }
 *       // any other mode: $voucher was never assigned
 *   foreach ($ids as $id) { $permit = Permit::find($id); }
 *       // empty array: $permit was never assigned
 *
 * TWO QUESTIONS, NOT ONE
 * ----------------------
 * "Is this variable safe to name" depends on WHERE the advice puts the call:
 *
 *  - holdsThroughout()        — for advice with no anchor ("add it in destroy()").
 *                              The binding must survive to every point after
 *                              the assignment on every path through the method,
 *                              so the assignment must be reached
 *                              unconditionally.
 *  - holdsImmediatelyAfter()  — for advice anchored to the assignment itself
 *                              ("add it immediately after the lookup on line
 *                              N"). A conditional binding is fine there — the
 *                              inserted line sits inside the same branch — but
 *                              only if such an insertion point exists at all,
 *                              i.e. the assignment is a statement rather than a
 *                              match arm, a ternary limb or a call argument,
 *                              where no statement can be written after it.
 *
 * The analysis is deliberately conservative: any construct not proven
 * transparent is treated as conditional. A missing fix is fine; a wrong fix is
 * a catastrophe.
 *
 * Every question is answered against AST node types. No regex is applied to PHP
 * source anywhere in this class.
 */
final class DefiniteAssignment
{
    /**
     * Upper bound on the parent walk, so a malformed or cyclic parent chain
     * cannot spin.
     */
    private const MAX_DEPTH = 256;

    /**
     * Whether a node sits inside a closure, arrow function, nested function or
     * nested class — a scope of its own, whose variables are NOT in scope in
     * the enclosing method body.
     *
     * The walk stops at the first enclosing ClassMethod, which is the method
     * the node belongs to.
     */
    public static function isInsideNestedScope(Node $node): bool
    {
        $current = $node->getAttribute('parent');
        $depth = 0;

        while ($current instanceof Node && $depth++ < self::MAX_DEPTH) {
            if ($current instanceof Node\Stmt\ClassMethod) {
                return false;
            }

            if (self::opensNewScope($current)) {
                return true;
            }

            $current = $current->getAttribute('parent');
        }

        return false;
    }

    /**
     * Whether the binding this assignment makes holds at EVERY point after it,
     * on every path from the enclosing method's entry.
     *
     * True only when the chain of constructs between the assignment and the
     * method body is transparent — a statement, a bare block, or an if/else in
     * which every branch that can fall through binds the same variable. Every
     * other construct (try/catch/finally, match, switch, any loop, an if
     * without an exhaustive else, a short-circuited expression, a call
     * argument) leaves at least one path on which the variable is undefined,
     * and is therefore rejected.
     */
    public static function holdsThroughout(Node\Expr\Assign $assign): bool
    {
        $name = self::assignedName($assign);

        if ($name === null) {
            return false;
        }

        $current = $assign;
        $depth = 0;

        while ($depth++ < self::MAX_DEPTH) {
            $parent = $current->getAttribute('parent');

            if (! $parent instanceof Node) {
                return false;
            }

            // The method body itself: every construct on the way up was
            // unconditional, so the assignment runs on every path.
            if ($parent instanceof Node\Stmt\ClassMethod) {
                return true;
            }

            if (self::opensNewScope($parent)) {
                return false;
            }

            if ($parent instanceof Node\Stmt\Expression || $parent instanceof Node\Stmt\Block) {
                $current = $parent;

                continue;
            }

            // `if ($post = Post::findOrFail($id)) { ... }` — an if condition is
            // always evaluated, so the binding survives the if statement. An
            // elseif condition is not: it runs only when the ones before it
            // were false.
            if ($parent instanceof Node\Stmt\ElseIf_ && $parent->cond === $current) {
                return false;
            }

            // A branch body is judged at the If_ above it, where the sibling
            // branches are visible.
            if ($parent instanceof Node\Stmt\ElseIf_ || $parent instanceof Node\Stmt\Else_) {
                $current = $parent;

                continue;
            }

            if ($parent instanceof Node\Stmt\If_
                && ($parent->cond === $current || self::bindsOnEveryBranch($parent, $name))) {
                $current = $parent;

                continue;
            }

            return false;
        }

        return false;
    }

    /**
     * Whether the binding holds at the statement boundary immediately after the
     * assignment.
     *
     * A conditional assignment qualifies — advice anchored to the assignment is
     * inserted inside the same branch, so the branch that binds the variable is
     * the only branch that reaches the inserted line. What does NOT qualify is
     * an assignment with no statement boundary after it: a match arm, a ternary
     * limb, a `??`/`&&` right-hand side or a call argument, where the advice
     * would have to land after the whole enclosing statement — the exact place
     * the variable may be undefined.
     */
    public static function holdsImmediatelyAfter(Node\Expr\Assign $assign): bool
    {
        if (self::assignedName($assign) === null || self::isInsideNestedScope($assign)) {
            return false;
        }

        return $assign->getAttribute('parent') instanceof Node\Stmt\Expression;
    }

    /**
     * The name of the plain local variable an assignment writes to, or null
     * when the target is anything else (a property, an array offset, a list
     * destructuring, a variable variable).
     */
    public static function assignedName(Node\Expr\Assign $assign): ?string
    {
        return $assign->var instanceof Node\Expr\Variable && is_string($assign->var->name)
            ? $assign->var->name
            : null;
    }

    /**
     * Whether every branch of an if/elseif/else either binds the variable at
     * statement level or cannot fall through to the code after the statement.
     *
     * An `if` with no `else` is never exhaustive: the implicit empty else binds
     * nothing.
     */
    private static function bindsOnEveryBranch(Node\Stmt\If_ $if, string $name): bool
    {
        if ($if->else === null) {
            return false;
        }

        $branches = [$if->stmts];

        foreach ($if->elseifs as $elseif) {
            $branches[] = $elseif->stmts;
        }

        $branches[] = $if->else->stmts;

        foreach ($branches as $branch) {
            if (! self::branchBinds($branch, $name)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether a straight-line branch binds the variable before it can fall
     * through to the statement after the enclosing if.
     *
     * A branch that always returns or throws never reaches that point, so it
     * has nothing to bind. Only statement-level assignments count; anything
     * nested deeper is conditional by the same reasoning applied everywhere
     * else in this class.
     *
     * @param  array<int, Node\Stmt>  $statements
     */
    private static function branchBinds(array $statements, string $name): bool
    {
        foreach ($statements as $statement) {
            if ($statement instanceof Node\Stmt\Return_) {
                return true;
            }

            if ($statement instanceof Node\Stmt\Expression) {
                if ($statement->expr instanceof Node\Expr\Throw_ || $statement->expr instanceof Node\Expr\Exit_) {
                    return true;
                }

                if ($statement->expr instanceof Node\Expr\Assign && self::assignedName($statement->expr) === $name) {
                    return true;
                }

                continue;
            }

            if ($statement instanceof Node\Stmt\Block && self::branchBinds($statement->stmts, $name)) {
                return true;
            }

            if ($statement instanceof Node\Stmt\If_ && self::bindsOnEveryBranch($statement, $name)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a node introduces a variable scope of its own.
     */
    private static function opensNewScope(Node $node): bool
    {
        return $node instanceof Node\Expr\Closure
            || $node instanceof Node\Expr\ArrowFunction
            || $node instanceof Node\Stmt\Function_
            || $node instanceof Node\Stmt\Class_;
    }
}
