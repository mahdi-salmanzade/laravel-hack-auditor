<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

/**
 * Whether a value is under the attacker's control.
 *
 * Three states, not two. `Unknown` exists so that "we could not tell" is never
 * silently rendered as "attacker controlled" — the mistake that turned
 * `$request->user()`, the AUTHENTICATED USER OBJECT, into a taint source and
 * produced two HIGH-severity false positives.
 */
enum InputTrust: string
{
    /** Provably derived from client-supplied data. */
    case Tainted = 'tainted';

    /** Provably NOT client-supplied (auth state, config, framework-resolved). */
    case Trusted = 'trusted';

    /** Not determinable from the code. Detectors must stay silent. */
    case Unknown = 'unknown';

    public function isTainted(): bool
    {
        return $this === self::Tainted;
    }

    public function isTrusted(): bool
    {
        return $this === self::Trusted;
    }
}
