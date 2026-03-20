<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Contracts;

interface CTFGeneratorInterface
{
    /**
     * Generate a Capture-The-Flag challenge based on a vulnerability type.
     */
    public function generate(string $vulnerabilityType, ?string $sourceCode = null): string;
}
