<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

use PhpParser\Node;

/**
 * Answers "what is the receiver of this call?" from the code's own type
 * declarations.
 *
 * This is the fix for the defect class where `->get(` and `->delete(` were
 * treated as HTTP verbs regardless of what they were called on, so an Eloquent
 * builder and a local storage service both read as Guzzle. A verb name tells
 * you nothing. The receiver does.
 *
 * Resolution sources, in order of strength:
 *  1. `$this`                       -> the enclosing class
 *  2. `$this->foo`                  -> promoted / typed / documented property
 *  3. a method parameter            -> its type hint, else its @param docblock
 *  4. a local variable              -> the assignment that reaches this line
 *  5. `Foo::bar()`                  -> the import that `Foo` resolves to
 *  6. `new Foo`, `app(Foo::class)`  -> the named class
 *
 * When none of these apply the answer is ResolvedType::unknown(), and callers
 * must treat that as "no finding" rather than "probably dangerous".
 */
final class ReceiverResolver
{
    private const MAX_DEPTH = 6;

    /**
     * Methods whose local assignments are remembered at once.
     *
     * LocalAssignments holds the assignment EXPRESSIONS, which are AST nodes,
     * which pin the whole file. Unbounded, that retained every method of every
     * analysed file for the length of a scan. Reuse is local — resolution
     * re-asks about the method it is currently inside — so a small window keeps
     * the speed without the retention.
     */
    private const MAX_CACHED_METHODS = 8;

    /**
     * Insertion-ordered, evicted oldest-first.
     *
     * @var array<string, array{method: MethodShape, assignments: LocalAssignments}>
     */
    private array $assignmentCache = [];

    /**
     * The expression a call chain ultimately starts from.
     *
     * `User::query()->whereIn(...)->lockForUpdate()->get()` has the static call
     * `User::query()` at its root; `$this->imageUpload->delete($x)` has the
     * property fetch `$this->imageUpload`.
     */
    public function chainRoot(Node\Expr $expr): Node\Expr
    {
        $depth = 0;

        while ($depth++ < 32) {
            if ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\NullsafeMethodCall) {
                $expr = $expr->var;

                continue;
            }

            return $expr;
        }

        return $expr;
    }

    /**
     * Method names in a call chain, ordered from the root outwards.
     *
     * For `User::query()->whereIn('id', $ids)->lockForUpdate()->get()` this is
     * ['query', 'whereIn', 'lockForUpdate', 'get'] — enough to see that the
     * chain is a query builder long before the verb at the end is reached.
     *
     * @return array<int, string>
     */
    public function chainMethods(Node\Expr $expr): array
    {
        $names = [];
        $current = $expr;
        $depth = 0;

        while ($depth++ < 32) {
            if ($current instanceof Node\Expr\MethodCall || $current instanceof Node\Expr\NullsafeMethodCall) {
                if ($current->name instanceof Node\Identifier) {
                    $names[] = $current->name->toString();
                }

                $current = $current->var;

                continue;
            }

            if ($current instanceof Node\Expr\StaticCall && $current->name instanceof Node\Identifier) {
                $names[] = $current->name->toString();
            }

            break;
        }

        return array_reverse($names);
    }

    /**
     * The root of a call chain and every method name along it, following local
     * variables so a chain split across statements still reads as one chain:
     *
     *   $query = User::query()->whereIn('id', $ids);
     *   $users = $query->lockForUpdate()->get();
     *
     * resolves to root `User::query()` with chain
     * ['query', 'whereIn', 'lockForUpdate', 'get'].
     *
     * @return array{root: Node\Expr, chain: array<int, string>}
     */
    public function resolveChain(Node\Expr $call, MethodShape $method, int $depth = 0): array
    {
        $chain = $this->chainMethods($call);
        $root = $this->chainRoot($call);

        if ($depth >= self::MAX_DEPTH
            || ! $root instanceof Node\Expr\Variable
            || ! is_string($root->name)
            || $method->parameter($root->name) !== null) {
            return ['root' => $root, 'chain' => $chain];
        }

        $assignment = $this->assignments($method)->reaching($root->name, $root->getStartLine());

        if ($assignment === null || $assignment['append'] || $assignment['iterated']) {
            return ['root' => $root, 'chain' => $chain];
        }

        $inner = $this->resolveChain($assignment['expr'], $method, $depth + 1);

        return [
            'root' => $inner['root'],
            'chain' => [...$inner['chain'], ...$chain],
        ];
    }

    /**
     * Local assignments made inside a method body, cached per method node.
     */
    public function assignmentsFor(MethodShape $method): LocalAssignments
    {
        return $this->assignments($method);
    }

    /**
     * Resolve the type of an expression within a method.
     */
    public function resolve(Node\Expr $expr, MethodShape $method, int $depth = 0): ResolvedType
    {
        if ($depth > self::MAX_DEPTH) {
            return ResolvedType::unknown('type resolution exceeded its depth limit');
        }

        $file = $method->file();
        $class = $method->class();

        if ($expr instanceof Node\Expr\Variable && $expr->name === 'this') {
            return ResolvedType::classType($class->fqcn(), sprintf('$this is an instance of %s', $class->fqcn()));
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return $this->resolveVariable($expr, $method, $depth);
        }

        if ($expr instanceof Node\Expr\PropertyFetch || $expr instanceof Node\Expr\NullsafePropertyFetch) {
            return $this->resolveProperty($expr, $method, $depth);
        }

        if ($expr instanceof Node\Expr\StaticCall) {
            return $this->resolveClassName($expr->class, $file, 'static call');
        }

        if ($expr instanceof Node\Expr\StaticPropertyFetch) {
            return ResolvedType::unknown('static property fetches are not resolved');
        }

        if ($expr instanceof Node\Expr\New_) {
            return $this->resolveClassName($expr->class, $file, 'instantiation');
        }

        if ($expr instanceof Node\Expr\ClassConstFetch) {
            return $this->resolveClassName($expr->class, $file, 'class constant');
        }

        if ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\NullsafeMethodCall) {
            // The RETURN type of an instance call is not inferred. Reporting the
            // chain root's type here would make `$user = $request->user()` look
            // like a Request, and every `$user->...` read like request input —
            // which is precisely how the authenticated user object was once
            // mistaken for attacker-controlled data.
            return ResolvedType::unknown('the return type of an instance method call is not inferred');
        }

        if ($expr instanceof Node\Expr\FuncCall) {
            return $this->resolveFuncCall($expr, $method, $depth);
        }

        if ($expr instanceof Node\Scalar\String_ || $expr instanceof Node\Scalar\InterpolatedString) {
            return ResolvedType::builtinType('string', 'string literal');
        }

        if ($expr instanceof Node\Scalar\Int_) {
            return ResolvedType::builtinType('int', 'integer literal');
        }

        if ($expr instanceof Node\Expr\Array_) {
            return ResolvedType::builtinType('array', 'array literal');
        }

        return ResolvedType::unknown('no type declaration reaches this expression');
    }

    /**
     * Resolve a `$this->property` receiver from the class's declarations.
     */
    private function resolveProperty(Node\Expr\PropertyFetch|Node\Expr\NullsafePropertyFetch $expr, MethodShape $method, int $depth): ResolvedType
    {
        if (! $expr->name instanceof Node\Identifier) {
            return ResolvedType::unknown('dynamic property name');
        }

        $name = $expr->name->toString();

        if ($expr->var instanceof Node\Expr\Variable && $expr->var->name === 'this') {
            $property = $method->class()->property($name);

            if ($property === null) {
                return ResolvedType::unknown(sprintf('$this->%s has no declared type', $name));
            }

            $type = $property->type();

            if ($type === null) {
                return ResolvedType::unknown(sprintf('$this->%s has no single declared type', $name));
            }

            return ResolvedType::named($type, $property->evidence());
        }

        $owner = $this->resolve($expr->var, $method, $depth + 1);

        return ResolvedType::unknown(sprintf(
            'property `%s` on %s is not resolved across classes',
            $name,
            $owner->describe(),
        ));
    }

    /**
     * Resolve a local variable: a declared parameter first, then the assignment
     * that reaches the use site.
     */
    private function resolveVariable(Node\Expr\Variable $expr, MethodShape $method, int $depth): ResolvedType
    {
        if (! is_string($expr->name)) {
            return ResolvedType::unknown('variable variable');
        }

        $name = $expr->name;
        $parameter = $method->parameter($name);

        if ($parameter !== null) {
            $class = $parameter->classType($method->file());

            if ($class !== null) {
                return ResolvedType::classType($class, sprintf(
                    'parameter $%s of %s() is type-hinted %s',
                    $name,
                    $method->name(),
                    $class,
                ));
            }

            $type = $parameter->type();

            if ($type !== null) {
                return ResolvedType::builtinType($type, sprintf(
                    'parameter $%s of %s() is declared %s',
                    $name,
                    $method->name(),
                    $type,
                ));
            }
        }

        $assignment = $this->assignments($method)->reaching($name, $expr->getStartLine());

        if ($assignment === null) {
            return ResolvedType::unknown(sprintf('$%s has no type hint and no local assignment', $name));
        }

        $resolved = $this->resolve($assignment['expr'], $method, $depth + 1);

        if (! $resolved->isKnown()) {
            return $resolved;
        }

        return ResolvedType::named($resolved->describe(), sprintf(
            '$%s is assigned on line %d from %s',
            $name,
            $assignment['line'],
            $resolved->evidence,
        ));
    }

    /**
     * Resolve the handful of Laravel container/helper calls whose return type
     * is stated by their argument.
     */
    private function resolveFuncCall(Node\Expr\FuncCall $expr, MethodShape $method, int $depth): ResolvedType
    {
        if (! $expr->name instanceof Node\Name) {
            return ResolvedType::unknown('dynamic function name');
        }

        $name = strtolower($method->file()->resolveName($expr->name));
        $name = TypeNames::shortName($name);

        if (($name === 'app' || $name === 'resolve') && isset($expr->args[0])) {
            $argument = $expr->args[0];

            if ($argument instanceof Node\Arg
                && $argument->value instanceof Node\Expr\ClassConstFetch) {
                return $this->resolveClassName($argument->value->class, $method->file(), sprintf('%s() container resolution', $name));
            }
        }

        return match ($name) {
            'collect' => ResolvedType::classType('Illuminate\Support\Collection', 'collect() returns a Collection'),
            'request' => ResolvedType::classType('Illuminate\Http\Request', 'request() returns the current Request'),
            'auth' => ResolvedType::classType('Illuminate\Contracts\Auth\Factory', 'auth() returns the auth factory'),
            'config' => ResolvedType::unknown('config() returns configuration data'),
            default => ResolvedType::unknown(sprintf('%s() has no known return type', $name)),
        };
    }

    private function resolveClassName(Node\Name|Node\Expr|Node\Stmt\Class_ $class, ParsedFile $file, string $context): ResolvedType
    {
        if ($class instanceof Node\Name) {
            $resolved = $file->resolveName($class);

            if (in_array(strtolower($resolved), ['self', 'static', 'parent'], true)) {
                return ResolvedType::unknown(sprintf('%s uses a relative class reference', $context));
            }

            return ResolvedType::classType($resolved, sprintf('%s on %s', $context, $resolved));
        }

        return ResolvedType::unknown(sprintf('%s targets a dynamic class', $context));
    }

    private function assignments(MethodShape $method): LocalAssignments
    {
        $key = $method->identity();
        $entry = $this->assignmentCache[$key] ?? null;

        // Identity, not just the key: a re-parsed file is a different syntax
        // tree, and assignments collected from the old one must never be mixed
        // with nodes from the new one.
        if ($entry !== null && $entry['method'] === $method) {
            unset($this->assignmentCache[$key]);

            return ($this->assignmentCache[$key] = $entry)['assignments'];
        }

        $assignments = LocalAssignments::collect($method);

        while (count($this->assignmentCache) >= self::MAX_CACHED_METHODS) {
            array_shift($this->assignmentCache);
        }

        $this->assignmentCache[$key] = ['method' => $method, 'assignments' => $assignments];

        return $assignments;
    }
}
