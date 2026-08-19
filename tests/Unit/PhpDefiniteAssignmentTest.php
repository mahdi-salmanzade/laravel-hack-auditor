<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\Php\DefiniteAssignment;
use Mahdi\HackAuditor\Scanner\Php\PhpAstParser;
use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * DefiniteAssignment — the guard that decides whether a fix may name a
 * variable.
 *
 * The rule it enforces is not "is this variable in this method's scope". PHP
 * gives try/catch, match arms, switch cases, loop bodies and if branches NO
 * scope of their own, so a variable bound inside any of them is in the method's
 * scope and still undefined on the paths that skip the binding. Advice that
 * names one produces `Gate::authorize('delete', null)` — an
 * AuthorizationException on the happy path, i.e. a 403 on every request the
 * advice was meant to protect.
 *
 * So: assigned on EVERY path, or not nameable.
 */

/**
 * Parse a method body and answer holdsThroughout() for the assignment to
 * $variable.
 *
 * The first assignment to that name is the one asked about, which is the same
 * one the detectors reach first when they walk the method in source order.
 */
function definiteBinding(string $body, string $variable = 'post'): bool
{
    return definiteBindingWith($body, $variable, static fn (Node\Expr\Assign $assign): bool => DefiniteAssignment::holdsThroughout($assign));
}

/**
 * Parse a method body and answer holdsImmediatelyAfter() for the assignment to
 * $variable.
 */
function anchoredBinding(string $body, string $variable = 'post'): bool
{
    return definiteBindingWith($body, $variable, static fn (Node\Expr\Assign $assign): bool => DefiniteAssignment::holdsImmediatelyAfter($assign));
}

/**
 * @param  callable(Node\Expr\Assign): bool  $question
 */
function definiteBindingWith(string $body, string $variable, callable $question): bool
{
    $source = "<?php\n\nnamespace App\\Http\\Controllers;\n\nuse App\\Models\\Post;\n\nclass PostController\n{\n    public function act(\$id, \$request)\n    {\n{$body}\n    }\n}\n";

    $parsed = (new PhpAstParser)->parse('app/Http/Controllers/PostController.php', $source);

    expect($parsed->isAnalysable())->toBeTrue();

    foreach ((new NodeFinder)->findInstanceOf($parsed->statements(), Node\Expr\Assign::class) as $assign) {
        if (DefiniteAssignment::assignedName($assign) === $variable) {
            return $question($assign);
        }
    }

    throw new RuntimeException("no assignment to \${$variable} was parsed out of the fixture");
}

// ---------------------------------------------------------------------------
// Definitely assigned — a fix MAY name these.
// ---------------------------------------------------------------------------

it('treats a statement-level assignment before any branching as definite', function (): void {
    expect(definiteBinding('        $post = Post::findOrFail($id);'."\n".'        $post->delete();'))->toBeTrue();
});

it('treats an assignment inside a bare block as definite', function (): void {
    expect(definiteBinding('        {'."\n".'            $post = Post::findOrFail($id);'."\n".'        }'))->toBeTrue();
});

it('treats an if/else in which EVERY branch assigns as definite', function (): void {
    $body = <<<'PHP'
            if ($request->trashed) {
                $post = Post::withTrashed()->findOrFail($id);
            } else {
                $post = Post::findOrFail($id);
            }
    PHP;

    expect(definiteBinding($body))->toBeTrue();
});

it('treats an if/elseif/else in which every branch assigns as definite', function (): void {
    $body = <<<'PHP'
            if ($request->a) {
                $post = Post::findOrFail($id);
            } elseif ($request->b) {
                $post = Post::withTrashed()->findOrFail($id);
            } else {
                $post = Post::firstOrFail();
            }
    PHP;

    expect(definiteBinding($body))->toBeTrue();
});

it('lets a branch that returns or throws stand in for a binding it cannot need', function (): void {
    $body = <<<'PHP'
            if ($request->missing) {
                throw new RuntimeException('gone');
            } else {
                $post = Post::findOrFail($id);
            }
    PHP;

    expect(definiteBinding($body))->toBeTrue();
});

it('treats an assignment in an if CONDITION as definite, because a condition always runs', function (): void {
    $body = <<<'PHP'
            if ($post = Post::find($id)) {
                $post->delete();
            }
    PHP;

    expect(definiteBinding($body))->toBeTrue();
});

// ---------------------------------------------------------------------------
// Conditionally assigned — a fix may NOT name these.
// ---------------------------------------------------------------------------

it('rejects an assignment made only inside a catch block', function (): void {
    $body = <<<'PHP'
            try {
                Post::where('id', $id)->delete();
            } catch (Throwable $e) {
                $post = Post::withTrashed()->findOrFail($id);
                $post->forceDelete();
            }
    PHP;

    expect(definiteBinding($body))->toBeFalse();
});

it('rejects an assignment made only inside a try block', function (): void {
    $body = <<<'PHP'
            try {
                $post = Post::findOrFail($id);
            } catch (Throwable $e) {
                report($e);
            }
    PHP;

    expect(definiteBinding($body))->toBeFalse();
});

it('rejects an assignment made only inside a finally block', function (): void {
    $body = <<<'PHP'
            try {
                Post::where('id', $id)->delete();
            } finally {
                $post = Post::withTrashed()->findOrFail($id);
            }
    PHP;

    expect(definiteBinding($body))->toBeFalse();
});

it('rejects an assignment made in a match arm', function (): void {
    $body = <<<'PHP'
            match ($request->mode) {
                'soft' => $post = Post::findOrFail($id),
                'hard' => $post = Post::withTrashed()->findOrFail($id),
                default => null,
            };
    PHP;

    expect(definiteBinding($body))->toBeFalse();
});

it('rejects an assignment made in a switch case', function (): void {
    $body = <<<'PHP'
            switch ($request->mode) {
                case 'soft':
                    $post = Post::findOrFail($id);
                    break;
                default:
                    break;
            }
    PHP;

    expect(definiteBinding($body))->toBeFalse();
});

it('rejects an assignment made only inside a foreach body', function (): void {
    $body = <<<'PHP'
            foreach ($request->input('ids', []) as $key) {
                $post = Post::findOrFail($key);
                $post->delete();
            }
    PHP;

    expect(definiteBinding($body))->toBeFalse();
});

it('rejects an assignment made only inside a for body', function (): void {
    $body = <<<'PHP'
            for ($i = 0; $i < 3; $i++) {
                $post = Post::findOrFail($id);
            }
    PHP;

    expect(definiteBinding($body))->toBeFalse();
});

it('rejects an assignment made only inside a while body', function (): void {
    $body = <<<'PHP'
            while ($request->more) {
                $post = Post::findOrFail($id);
            }
    PHP;

    expect(definiteBinding($body))->toBeFalse();
});

it('rejects an assignment made only inside a do-while body', function (): void {
    $body = <<<'PHP'
            do {
                $post = Post::findOrFail($id);
            } while ($request->more);
    PHP;

    expect(definiteBinding($body))->toBeFalse();
});

it('rejects an if with no else, however much the branch assigns', function (): void {
    $body = <<<'PHP'
            if ($request->wants) {
                $post = Post::findOrFail($id);
            }
    PHP;

    expect(definiteBinding($body))->toBeFalse();
});

it('rejects an if/else in which only one branch assigns', function (): void {
    $body = <<<'PHP'
            if ($request->wants) {
                $post = Post::findOrFail($id);
            } else {
                $other = Post::firstOrFail();
            }
    PHP;

    expect(definiteBinding($body))->toBeFalse();
});

it('rejects an assignment in an elseif CONDITION, which runs only when the ones before it failed', function (): void {
    $body = <<<'PHP'
            if ($request->a) {
                $other = Post::firstOrFail();
            } elseif ($post = Post::find($id)) {
                $post->delete();
            } else {
                $other = Post::firstOrFail();
            }
    PHP;

    expect(definiteBinding($body))->toBeFalse();
});

it('rejects the right-hand side of a ternary', function (): void {
    expect(definiteBinding('        $flag = $request->wants ? $post = Post::findOrFail($id) : null;'))->toBeFalse();
});

it('rejects the right-hand side of a null coalesce', function (): void {
    expect(definiteBinding('        $flag = $request->cached ?? $post = Post::findOrFail($id);'))->toBeFalse();
});

it('rejects the right-hand side of a short-circuiting boolean AND', function (): void {
    expect(definiteBinding('        $flag = $request->wants && $post = Post::findOrFail($id);'))->toBeFalse();
});

it('rejects the right-hand side of a short-circuiting boolean OR', function (): void {
    expect(definiteBinding('        $flag = $request->cached || $post = Post::findOrFail($id);'))->toBeFalse();
});

it('rejects an assignment inside a closure, which is another scope entirely', function (): void {
    $body = <<<'PHP'
            DB::transaction(function () use ($id) {
                $post = Post::findOrFail($id);
                $post->delete();
            });
    PHP;

    expect(definiteBinding($body))->toBeFalse();
});

it('rejects an assignment inside an arrow function', function (): void {
    expect(definiteBinding('        $resolve = fn ($key) => $post = Post::findOrFail($key);'))->toBeFalse();
});

// ---------------------------------------------------------------------------
// The anchored question: is there a statement boundary right after the binding?
// ---------------------------------------------------------------------------

it('accepts a conditional binding when the advice is anchored to the assignment', function (): void {
    $body = <<<'PHP'
            if ($request->wants) {
                $post = Post::findOrFail($id);
                return $post;
            }
    PHP;

    // Not definite from method entry, but a line written immediately after the
    // lookup sits inside the same branch — the only path that reaches it is the
    // one that made the binding.
    expect(definiteBinding($body))->toBeFalse()
        ->and(anchoredBinding($body))->toBeTrue();
});

it('refuses an anchored binding with no statement boundary after it', function (): void {
    $body = <<<'PHP'
            match ($request->mode) {
                'soft' => $post = Post::findOrFail($id),
                default => null,
            };
    PHP;

    // "add the call immediately after the lookup" cannot be obeyed inside a
    // match arm: the reader can only place it after the whole statement, where
    // $post may never have been assigned.
    expect(anchoredBinding($body))->toBeFalse();
});

it('refuses an anchored binding inside a closure', function (): void {
    $body = <<<'PHP'
            DB::transaction(function () use ($id) {
                $post = Post::findOrFail($id);
            });
    PHP;

    expect(anchoredBinding($body))->toBeFalse();
});

// ---------------------------------------------------------------------------
// Targets that are not plain local variables.
// ---------------------------------------------------------------------------

it('names no variable for a property or offset assignment', function (): void {
    $source = "<?php\nclass C\n{\n    public function act(\$id)\n    {\n        \$this->post = Post::findOrFail(\$id);\n        \$bag['post'] = Post::findOrFail(\$id);\n    }\n}\n";

    $parsed = (new PhpAstParser)->parse('C.php', $source);
    $assigns = (new NodeFinder)->findInstanceOf($parsed->statements(), Node\Expr\Assign::class);

    expect($assigns)->toHaveCount(2);

    foreach ($assigns as $assign) {
        expect(DefiniteAssignment::assignedName($assign))->toBeNull()
            ->and(DefiniteAssignment::holdsThroughout($assign))->toBeFalse()
            ->and(DefiniteAssignment::holdsImmediatelyAfter($assign))->toBeFalse();
    }
});
