<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

use PhpParser\Node\Expr;

/**
 * Walks a method body over the AST and records where attacker-controlled data
 * flows.
 *
 * Parameters are seeded from their declared types (a route-model-bound model is
 * trusted, a bare scalar on a routed action is not), then each assignment is
 * judged in source order against the state built so far. Appending assignments
 * (`.=`) keep an existing taint; a plain reassignment replaces it, which is how
 * a value that is sanitised or replaced mid-method stops being tainted.
 *
 * Nested closures are not descended into: their scope is not this one.
 */
final class TaintTracker
{
    /**
     * Methods whose walk is remembered at once.
     *
     * A TaintState holds the MethodShape it was built for, which holds the
     * whole file's AST. An unbounded cache therefore pinned every method of
     * every analysed file for the length of a scan — one of the retentions that
     * put a large application over PHP's default memory_limit. Reuse here is
     * local anyway: a detector walks one method, asks about it repeatedly, then
     * moves on, so a small window captures effectively all of the benefit.
     */
    private const MAX_CACHED_METHODS = 8;

    private readonly LaravelSemantics $semantics;

    /**
     * Insertion-ordered, evicted oldest-first.
     *
     * @var array<string, array{method: MethodShape, state: TaintState}>
     */
    private array $cache = [];

    public function __construct(?LaravelSemantics $semantics = null)
    {
        $this->semantics = $semantics ?? new LaravelSemantics;
    }

    public function semantics(): LaravelSemantics
    {
        return $this->semantics;
    }

    public function track(MethodShape $method): TaintState
    {
        $key = $method->identity();
        $entry = $this->cache[$key] ?? null;

        // Identity, not just the key: after an eviction the file is re-parsed
        // into a new syntax tree, and a state built over the old one must not be
        // handed back alongside nodes from the new one.
        if ($entry !== null && $entry['method'] === $method) {
            unset($this->cache[$key]);

            return ($this->cache[$key] = $entry)['state'];
        }

        $state = new TaintState($method);

        foreach ($method->parameters() as $parameter) {
            $state->record(
                $parameter->name(),
                $method->declarationLine(),
                $this->semantics->judgeParameter($parameter, $method),
            );
        }

        foreach (LocalAssignments::collect($method)->all() as $assignment) {
            $state->record(
                $assignment['name'],
                $assignment['line'],
                $this->judgeAssignment($assignment, $method, $state),
            );
        }

        while (count($this->cache) >= self::MAX_CACHED_METHODS) {
            array_shift($this->cache);
        }

        $this->cache[$key] = ['method' => $method, 'state' => $state];

        return $state;
    }

    /**
     * @param  array{name: string, line: int, expr: Expr, append: bool, iterated: bool}  $assignment
     */
    private function judgeAssignment(array $assignment, MethodShape $method, TaintState $state): TaintJudgement
    {
        $judgement = $this->semantics->judge($assignment['expr'], $method, $state);

        if ($assignment['iterated'] && ! $judgement->isTainted()) {
            // An element of an unresolved collection tells us nothing about the
            // element itself; only a tainted source carries through.
            $judgement = $judgement->isTrusted()
                ? $judgement
                : TaintJudgement::unknown(sprintf(
                    '$%s is an element of a value whose origin is unresolved',
                    $assignment['name'],
                ));
        }

        if (! $assignment['append']) {
            return $judgement;
        }

        $previous = $state->at($assignment['name'], $assignment['line']);

        if ($previous === null) {
            return $judgement;
        }

        return TaintJudgement::combine(
            [$previous, $judgement],
            sprintf('$%s accumulates its previous value and the appended expression', $assignment['name']),
        );
    }
}
