<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\AccessControl;

use Mahdi\HackAuditor\Scanner\Php\ClassShape;
use Mahdi\HackAuditor\Scanner\Php\SemanticContext;
use Mahdi\HackAuditor\Scanner\Php\TypeNames;

/**
 * Whether `$this->authorize(...)` is a method that exists on a controller.
 *
 * D-3: three fix emitters used to write `$this->authorize('ability', $var)`
 * having proved the policy class, the ability and the variable — and never the
 * receiver. Since Laravel 11 `make:controller` emits
 *
 *     abstract class Controller {}
 *
 * with no parent and no trait, so on a default modern application that advice
 * produces `Error: Call to undefined method PostController::authorize()`:
 * an HTTP 500 on every request to the route, which is strictly worse than the
 * missing check it was meant to repair. Laravel's own
 * `Illuminate\Routing\Controller` is no better — it has no `authorize()` either,
 * and its `__call()` turns the call into a BadMethodCallException.
 *
 * `authorize()` is callable when the controller, ANY ancestor, or ANY trait
 * reachable from either provides the `AuthorizesRequests` trait or declares an
 * `authorize()` method of its own. Anything short of that — including an
 * ancestry this scan cannot fully read — is not a proof, and an unproven
 * prerequisite may not be written into advice.
 *
 * The bias is deliberate and one-directional. Failing to prove a callable
 * `authorize()` costs nothing: `Gate::authorize()` is a facade and runs on any
 * application. Wrongly proving one costs a 500.
 */
final class AuthorizeAvailability
{
    /**
     * The trait that puts `authorize()` on a controller. It lives in the
     * framework, so it is never a class this scan can open — only a NAME the
     * controller's `use` statement resolves to.
     */
    private const AUTHORIZES_REQUESTS = 'Illuminate\Foundation\Auth\Access\AuthorizesRequests';

    /**
     * Framework base classes whose API is fixed, published and known to contain
     * no `authorize()`. Naming them keeps the common
     * `extends Illuminate\Routing\Controller` case on the PROVEN-ABSENT branch
     * — a specific, checkable sentence — instead of collapsing it into "this
     * scan could not read your parent".
     */
    private const BASES_WITHOUT_AUTHORIZE = [
        'Illuminate\Routing\Controller',
    ];

    private const IS_CALLABLE = 'callable';

    private const ABSENT = 'absent';

    private const UNKNOWN = 'unknown';

    private function __construct(
        private readonly string $verdict,
        private readonly string $controller,
        private readonly ?string $base,
        private readonly ?string $unreadable,
    ) {}

    /**
     * Resolve the verdict from the class's whole inheritance surface, walked
     * once by ClassIndex::chain() — the same traversal
     * PolicyRouteMismatchDetector uses to look for authorizeResource() and
     * constructor middleware.
     */
    public static function resolve(ClassShape $class, SemanticContext $semantic): self
    {
        $chain = $semantic->classes()->chain($class->fqcn());

        foreach ($chain['names'] as $name) {
            if (ltrim($name, '\\') === self::AUTHORIZES_REQUESTS) {
                return new self(self::IS_CALLABLE, $class->shortName(), null, null);
            }
        }

        // `use AuthorizesRequests;` written with no import statement resolves to
        // a name in the controller's own namespace that no such trait occupies.
        // Accepted only where the name is unopenable — i.e. it really is a
        // vendor trait — so an application trait that happens to share the short
        // name can never masquerade as proof.
        foreach ($chain['unreadable'] as $name) {
            if (TypeNames::shortName($name) === 'AuthorizesRequests') {
                return new self(self::IS_CALLABLE, $class->shortName(), null, null);
            }
        }

        foreach ($chain['shapes'] as $shape) {
            $authorize = $shape->method('authorize');

            if ($authorize === null) {
                continue;
            }

            // A private method on an ANCESTOR is not inherited, so it is no
            // proof that `$this->authorize()` resolves on the child.
            if ($shape->fqcn() !== $class->fqcn() && ! $authorize->isPublic()) {
                continue;
            }

            return new self(self::IS_CALLABLE, $class->shortName(), null, null);
        }

        $unreadable = array_values(array_filter(
            $chain['unreadable'],
            static fn (string $name): bool => ! in_array($name, self::BASES_WITHOUT_AUTHORIZE, true),
        ));

        if ($unreadable !== []) {
            return new self(self::UNKNOWN, $class->shortName(), null, TypeNames::shortName($unreadable[0]));
        }

        return new self(self::ABSENT, $class->shortName(), self::baseOf($class, $semantic), null);
    }

    /**
     * True only when the receiver is PROVEN. `$this->authorize(...)` may be
     * written into a fix string on this and no other verdict.
     */
    public function isCallable(): bool
    {
        return $this->verdict === self::IS_CALLABLE;
    }

    /**
     * The sentence that says why the `$this->` form was not written, in the
     * house style: name the specific thing that could not be proved rather than
     * hedging over both cases at once.
     *
     * Empty when the receiver is proven and no explanation is owed.
     */
    public function reason(): string
    {
        if ($this->verdict === self::IS_CALLABLE) {
            return '';
        }

        if ($this->verdict === self::UNKNOWN) {
            return sprintf(
                '$this->authorize() is deliberately not the call written here: %s inherits from %s, which this scan could not read, so whether authorize() is callable on this controller is unknown. Gate::authorize() is a facade and resolves on any application.',
                $this->controller,
                $this->unreadable,
            );
        }

        return sprintf(
            '$this->authorize() is deliberately not the call written here: %s does not have that method. This scan read %s and every class and trait it inherits, and none of them uses %s or declares an authorize() of its own — since Laravel 11 the generated base controller no longer includes that trait — so `$this->authorize(...)` would fail at runtime and return a 500 on every request to this action. Adding `use AuthorizesRequests;` to %s restores the $this-> form if you prefer it.',
            $this->controller,
            $this->controller,
            self::AUTHORIZES_REQUESTS,
            $this->base ?? $this->controller,
        );
    }

    /**
     * The topmost ancestor this scan can read: the class a reader would add
     * `use AuthorizesRequests;` to so that every controller under it gains the
     * method at once.
     */
    private static function baseOf(ClassShape $class, SemanticContext $semantic): string
    {
        $base = $class;

        foreach ($semantic->classes()->ancestry($class->fqcn()) as $name) {
            $shape = $semantic->classes()->resolve($name);

            if ($shape !== null) {
                $base = $shape;
            }
        }

        return $base->shortName();
    }
}
