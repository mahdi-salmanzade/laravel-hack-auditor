<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\AccessControl;

use Mahdi\HackAuditor\Scanner\Vulnerability;

/**
 * Contract for a single deterministic access-control detector.
 *
 * Detectors analyze controller/model source (string + regex/token analysis,
 * not a full AST) and the introspected route/policy/model context, returning
 * a list of high-confidence Vulnerability findings.
 */
interface AccessControlDetector
{
    /**
     * Analyze the given source files and return any access-control findings.
     *
     * @param  array<int, SourceFile>  $files
     * @return array<int, Vulnerability>
     */
    public function detect(array $files, AccessControlContext $context): array;
}
