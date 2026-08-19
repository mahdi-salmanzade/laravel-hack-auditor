<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

use Generator;

/**
 * The set of files one scan is allowed to reason about, and the only thing that
 * hands out their ASTs.
 *
 * It holds SOURCE, not syntax trees. A source string is already in memory —
 * the caller read it — and PHP strings are refcounted, so keeping a reference
 * costs nothing beyond what the caller already pays. A parsed file, by
 * contrast, costs ~0.2 MB, which is why an AST is produced on demand and
 * immediately becomes the bounded parser cache's problem rather than this
 * object's.
 *
 * That is the whole memory contract: peak usage is set by
 * PhpAstParser::MAX_CACHED_FILES, never by how many files the application has.
 * A caller that streams — `foreach ($repository->stream() as $parsed)` — holds
 * exactly one AST at a time; a caller that asks for a specific file gets it
 * back from the cache when it is still resident and a fresh parse when it is
 * not. Either way the answer is identical, because the source it is derived
 * from is identical.
 *
 * Insertion order is preserved and duplicate paths are kept, so a file handed
 * in twice is analysed twice — exactly as it was when every file was parsed
 * eagerly into an array.
 */
final class SourceRepository
{
    /**
     * Every file in insertion order, duplicates included.
     *
     * @var array<int, array{path: string, source: string}>
     */
    private array $files = [];

    /**
     * Fast lookup of the LAST source registered for a path.
     *
     * @var array<string, string>
     */
    private array $byPath = [];

    public function __construct(private readonly PhpAstParser $parser = new PhpAstParser) {}

    /**
     * Build from the array shape the scanner passes around.
     *
     * @param  array<int, array{path: string, content: string, type?: string}>  $files
     */
    public static function fromSourceFiles(array $files, ?PhpAstParser $parser = null): self
    {
        $repository = new self($parser ?? new PhpAstParser);

        foreach ($files as $file) {
            $repository->add($file['path'], $file['content']);
        }

        return $repository;
    }

    /**
     * Build from files somebody else has already parsed. Only the path and the
     * source are kept; the ASTs are released to the parser's bounded cache.
     *
     * @param  array<int, ParsedFile>  $parsed
     */
    public static function fromParsedFiles(array $parsed, ?PhpAstParser $parser = null): self
    {
        $repository = new self($parser ?? new PhpAstParser);

        foreach ($parsed as $file) {
            $repository->add($file->path, $file->source);
        }

        return $repository;
    }

    public function add(string $path, string $source): void
    {
        $this->files[] = ['path' => $path, 'source' => $source];
        $this->byPath[$path] = $source;
    }

    /**
     * Every path handed in, in order, duplicates included.
     *
     * @return array<int, string>
     */
    public function paths(): array
    {
        return array_column($this->files, 'path');
    }

    public function count(): int
    {
        return count($this->files);
    }

    public function has(string $path): bool
    {
        return isset($this->byPath[$path]);
    }

    public function parser(): PhpAstParser
    {
        return $this->parser;
    }

    /**
     * The AST of one file, parsed now or served from the bounded cache. Null
     * only when the path was never registered — a file that fails to PARSE
     * still comes back, as an unanalysable ParsedFile.
     */
    public function parsed(string $path): ?ParsedFile
    {
        $source = $this->byPath[$path] ?? null;

        return $source === null ? null : $this->parser->parse($path, $source);
    }

    /**
     * Re-open one declared class. This is how a cross-file lookup gets real
     * nodes without the index ever holding any.
     */
    public function classShape(string $path, string $fqcn): ?ClassShape
    {
        return $this->parsed($path)?->classNamed($fqcn);
    }

    /**
     * Every file, one AST alive at a time.
     *
     * @return Generator<int, ParsedFile>
     */
    public function stream(): Generator
    {
        foreach ($this->files as $file) {
            yield $this->parser->parse($file['path'], $file['source']);
        }
    }
}
