<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\AccessControl;

/**
 * Lightweight value object wrapping a single source file for access-control
 * analysis. Provides helpers for line-number resolution and class detection
 * that every deterministic detector needs.
 */
final class SourceFile
{
    /**
     * @param  string  $path  Relative or absolute path used as the finding location
     * @param  string  $content  Raw PHP source
     * @param  string  $type  File classification ('controller', 'model', 'route', 'other')
     */
    public function __construct(
        public readonly string $path,
        public readonly string $content,
        public readonly string $type,
    ) {}

    /**
     * Build a SourceFile from the array shape used throughout HackScanner.
     *
     * @param  array{path: string, content: string, type: string}  $file
     */
    public static function fromArray(array $file): self
    {
        return new self(
            path: $file['path'],
            content: $file['content'],
            type: $file['type'],
        );
    }

    /**
     * Resolve the 1-based line number for a byte offset in the content.
     */
    public function lineForOffset(int $offset): int
    {
        if ($offset <= 0) {
            return 1;
        }

        $slice = substr($this->content, 0, $offset);

        return substr_count($slice, "\n") + 1;
    }

    /**
     * Resolve the 1-based line number of the first occurrence of a needle.
     */
    public function lineForNeedle(string $needle): int
    {
        $pos = strpos($this->content, $needle);

        if ($pos === false) {
            return 1;
        }

        return $this->lineForOffset($pos);
    }

    /**
     * Extract the short class name declared in the file, if any.
     */
    public function className(): ?string
    {
        if (preg_match('/\bclass\s+(\w+)/', $this->content, $match)) {
            return $match[1];
        }

        return null;
    }

    /**
     * Extract the fully-qualified class name declared in the file, if any.
     */
    public function fqcn(): ?string
    {
        $class = $this->className();

        if ($class === null) {
            return null;
        }

        if (preg_match('/namespace\s+([^;]+);/', $this->content, $match)) {
            return trim($match[1]).'\\'.$class;
        }

        return $class;
    }
}
