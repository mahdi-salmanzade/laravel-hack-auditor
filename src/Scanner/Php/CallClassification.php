<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

/**
 * What one call site is: the verb, the receiver's kind, the receiver's resolved
 * type, and the evidence chain that establishes it.
 */
final class CallClassification
{
    /**
     * @param  array<int, string>  $chain  Method names from the chain root outwards
     */
    public function __construct(
        public readonly ReceiverKind $kind,
        public readonly string $method,
        public readonly ResolvedType $receiver,
        public readonly array $chain,
        public readonly string $evidence,
        public readonly int $line,
    ) {}

    public function isOutboundHttp(): bool
    {
        return $this->kind->isOutboundHttp();
    }

    public function isDatabase(): bool
    {
        return $this->kind === ReceiverKind::Eloquent;
    }

    public function isUnknown(): bool
    {
        return $this->kind === ReceiverKind::Unknown;
    }

    /**
     * A quotable one-line description of the call site.
     */
    public function describe(): string
    {
        return sprintf(
            '%s() on %s (%s)',
            $this->method,
            $this->kind->label(),
            $this->evidence,
        );
    }
}
