<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

use Generator;

/**
 * The whole semantic layer for one scan, assembled once.
 *
 * A detector asks this object for parsed files, the class index, the policy
 * index, Laravel semantics and taint state; it never parses anything itself and
 * never reads raw source. Files that failed to parse are listed by
 * unanalysable() and are absent from every other accessor, so "we could not
 * read it" can be reported honestly instead of being analysed by guesswork.
 *
 * MEMORY CONTRACT
 *
 * This object holds no syntax trees. It used to: `fromSourceFiles()` parsed
 * every file into an array and kept it for the life of the run, so peak memory
 * scaled linearly with application size — ~0.2 MB per file, past PHP's default
 * 128M memory_limit at around 640 files. That is a FATAL, not a catchable
 * Throwable, so the parser's graceful-degradation path never ran and a scan of
 * any large application produced nothing at all.
 *
 * What is retained now is small and node-free: the source strings (already in
 * the caller's memory, and refcounted, so they cost nothing extra), a
 * ClassSummary per declared class, and a policy's ability names. ASTs are
 * produced on demand by the bounded PhpAstParser and are the parser cache's
 * problem, not this object's. Peak memory is therefore set by
 * PhpAstParser::MAX_CACHED_FILES and is flat regardless of how many files a
 * scan covers.
 *
 * The consequence for callers: `files()` and `analysable()` are GENERATORS.
 * Iterating them holds one AST at a time. Collecting them into an array
 * re-creates the very retention this class exists to prevent, so don't.
 */
final class SemanticContext
{
    /**
     * @param  array<string, string>  $parseErrors  path => reason, from the index pass
     */
    private function __construct(
        private readonly SourceRepository $sources,
        private readonly ClassIndex $classes,
        private readonly PolicyIndex $policies,
        private readonly LaravelSemantics $semantics,
        private readonly TaintTracker $taint,
        private readonly array $parseErrors,
    ) {}

    /**
     * Build from the array shape the scanner already passes around.
     *
     * @param  array<int, array{path: string, content: string, type?: string}>  $files
     */
    public static function fromSourceFiles(array $files, ?PhpAstParser $parser = null): self
    {
        return self::over(SourceRepository::fromSourceFiles($files, $parser));
    }

    /**
     * Build from files a caller has already parsed. Only their path and source
     * are kept — the ASTs are released to the parser's bounded cache.
     *
     * @param  array<int, ParsedFile>  $parsed
     */
    public static function fromParsedFiles(array $parsed, ?PhpAstParser $parser = null): self
    {
        return self::over(SourceRepository::fromParsedFiles($parsed, $parser));
    }

    /**
     * Build the cross-file indexes in ONE streaming pass.
     *
     * Each file is parsed, its class shapes are copied into summaries, and its
     * AST is dropped before the next file is opened. This is the pass that used
     * to accumulate every ParsedFile in an array; nothing survives it but a few
     * hundred bytes per class.
     */
    public static function over(SourceRepository $sources): self
    {
        $classes = new ClassIndex($sources);
        $policies = new PolicyIndex($sources);
        $parseErrors = [];

        foreach ($sources->stream() as $parsed) {
            if (! $parsed->isAnalysable()) {
                $parseErrors[$parsed->path] = (string) $parsed->parseError;

                continue;
            }

            foreach ($parsed->classes() as $class) {
                $classes->addClass($class);
                $policies->addPolicy($class);
            }
        }

        $semantics = new LaravelSemantics(new ReceiverResolver, $classes);

        return new self(
            sources: $sources,
            classes: $classes,
            policies: $policies,
            semantics: $semantics,
            taint: new TaintTracker($semantics),
            parseErrors: $parseErrors,
        );
    }

    /**
     * Every path handed in, in order.
     *
     * @return array<int, string>
     */
    public function paths(): array
    {
        return $this->sources->paths();
    }

    public function fileCount(): int
    {
        return $this->sources->count();
    }

    /**
     * The AST of one file, parsed now or served from the bounded cache. Null
     * only when the path was never handed in.
     */
    public function parsed(string $path): ?ParsedFile
    {
        return $this->sources->parsed($path);
    }

    /**
     * What a file declares, without opening it — the cheap pre-filter a
     * detector uses to skip files that cannot possibly interest it.
     *
     * @return array<int, ClassSummary>
     */
    public function summariesIn(string $path): array
    {
        return $this->classes->summariesIn($path);
    }

    /**
     * Every file handed in, analysable or not, one AST alive at a time.
     *
     * @return Generator<int, ParsedFile>
     */
    public function files(): Generator
    {
        yield from $this->sources->stream();
    }

    /**
     * Only the files we can reason about, one AST alive at a time.
     *
     * @return Generator<int, ParsedFile>
     */
    public function analysable(): Generator
    {
        foreach ($this->sources->stream() as $file) {
            if ($file->isAnalysable()) {
                yield $file;
            }
        }
    }

    /**
     * Files that could not be parsed, mapped to the reason. These produce no
     * findings and must be surfaced as "not analysed" rather than "clean".
     *
     * @return array<string, string>
     */
    public function unanalysable(): array
    {
        return $this->parseErrors;
    }

    public function sources(): SourceRepository
    {
        return $this->sources;
    }

    public function parser(): PhpAstParser
    {
        return $this->sources->parser();
    }

    public function classes(): ClassIndex
    {
        return $this->classes;
    }

    public function policies(): PolicyIndex
    {
        return $this->policies;
    }

    public function semantics(): LaravelSemantics
    {
        return $this->semantics;
    }

    public function taint(): TaintTracker
    {
        return $this->taint;
    }

    /**
     * Every controller class in the scan, as summaries. Summaries rather than
     * shapes because "every controller in a 900-file application" is precisely
     * the list that must never be held as live syntax trees; open the one you
     * are analysing with classes()->find().
     *
     * @return array<int, ClassSummary>
     */
    public function controllers(): array
    {
        $controllers = [];

        foreach ($this->classes->all() as $class) {
            if ($this->semantics->isController($class)) {
                $controllers[] = $class;
            }
        }

        return $controllers;
    }
}
