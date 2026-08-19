<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

use PhpParser\Node;
use PhpParser\NodeTraverser;

/**
 * The assignments made to local variables inside one method body, indexed so a
 * use site can be matched with the assignment that actually reaches it.
 *
 * Lookups are line-ordered rather than "first match wins", because a variable
 * that is tainted at line 10 and reassigned from config() at line 14 is SAFE at
 * line 16. A first-match reader would report a vulnerability that does not
 * exist.
 */
final class LocalAssignments
{
    /**
     * @param  array<int, array{name: string, line: int, expr: Node\Expr, append: bool, iterated: bool}>  $assignments
     */
    private function __construct(private readonly array $assignments) {}

    public static function collect(MethodShape $method): self
    {
        $statements = $method->statements();

        if ($statements === []) {
            return new self([]);
        }

        $collector = new AssignmentCollector;
        $traverser = new NodeTraverser($collector);
        $traverser->traverse($statements);

        return new self($collector->assignments);
    }

    /**
     * Every assignment to a variable, in source order.
     *
     * @return array<int, array{name: string, line: int, expr: Node\Expr, append: bool, iterated: bool}>
     */
    public function all(): array
    {
        return $this->assignments;
    }

    /**
     * Assignments to one variable, in source order.
     *
     * @return array<int, array{name: string, line: int, expr: Node\Expr, append: bool, iterated: bool}>
     */
    public function forVariable(string $name): array
    {
        $name = ltrim($name, '$');

        return array_values(array_filter(
            $this->assignments,
            static fn (array $assignment): bool => $assignment['name'] === $name,
        ));
    }

    /**
     * The last assignment to a variable at or before the given line, i.e. the
     * one that reaches a use site on that line.
     *
     * @return array{name: string, line: int, expr: Node\Expr, append: bool, iterated: bool}|null
     */
    public function reaching(string $name, ?int $line = null): ?array
    {
        $reaching = null;

        foreach ($this->forVariable($name) as $assignment) {
            if ($line !== null && $assignment['line'] > $line) {
                continue;
            }

            $reaching = $assignment;
        }

        return $reaching;
    }

    /**
     * Names of every locally assigned variable.
     *
     * @return array<int, string>
     */
    public function names(): array
    {
        $names = array_map(
            static fn (array $assignment): string => $assignment['name'],
            $this->assignments,
        );

        return array_values(array_unique($names));
    }
}
