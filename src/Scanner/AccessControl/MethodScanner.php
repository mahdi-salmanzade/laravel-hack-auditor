<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\AccessControl;

/**
 * Extracts public method bodies from controller source using brace-counting.
 *
 * This is intentionally a robust string/token scanner rather than a full AST
 * parser — it tolerates partial/odd source and never throws.
 */
final class MethodScanner
{
    /**
     * Extract public (non-static) methods with their bodies and byte offsets.
     *
     * Skips the constructor and magic methods. Returns each method's name, the
     * raw body between its braces, and the byte offset where the signature
     * begins (for line-number resolution).
     *
     * @return array<int, array{name: string, body: string, offset: int}>
     */
    public function publicMethods(string $content): array
    {
        $methods = [];
        $pattern = '/public\s+function\s+(\w+)\s*\([^)]*\)\s*(?::\s*[^{]+)?\{/s';

        if (! preg_match_all($pattern, $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
            return $methods;
        }

        $length = strlen($content);

        foreach ($matches as $match) {
            $name = $match[1][0];

            if ($name === '__construct' || str_starts_with($name, '__')) {
                continue;
            }

            $signatureOffset = (int) $match[0][1];
            $openBrace = (int) $match[0][1] + strlen($match[0][0]) - 1;
            $depth = 1;
            $pos = $openBrace + 1;

            while ($pos < $length && $depth > 0) {
                $char = $content[$pos];

                if ($char === '{') {
                    $depth++;
                } elseif ($char === '}') {
                    $depth--;
                }

                $pos++;
            }

            if ($depth !== 0) {
                continue;
            }

            $methods[] = [
                'name' => $name,
                'body' => substr($content, $openBrace + 1, $pos - $openBrace - 2),
                'offset' => $signatureOffset,
            ];
        }

        return $methods;
    }
}
