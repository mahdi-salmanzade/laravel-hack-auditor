<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

/**
 * One semantic layer per file set, shared by every detector in a run.
 *
 * Each detector used to build its own SemanticContext over the same files, so a
 * five-detector run indexed the whole application five times: five passes of
 * parsing, five class indexes, five policy indexes. Sharing the parser removed
 * the duplicated AST cache but not the duplicated WORK.
 *
 * The workspace memoises the context for the file set it was last asked about,
 * keyed by a fingerprint of every path and every byte of source. The
 * fingerprint is what makes sharing safe: a detector handed a DIFFERENT file
 * set gets a different context, never a stale one, so a detector used
 * standalone behaves exactly as it did before.
 */
final class SemanticWorkspace
{
    private ?SemanticContext $context = null;

    private ?string $fingerprint = null;

    public function __construct(private readonly PhpAstParser $parser = new PhpAstParser) {}

    public function parser(): PhpAstParser
    {
        return $this->parser;
    }

    /**
     * The semantic layer for these files, built once and reused while the set
     * is unchanged.
     *
     * @param  array<int, array{path: string, content: string, type?: string}>  $files
     */
    public function contextFor(array $files): SemanticContext
    {
        $fingerprint = $this->fingerprint($files);

        if ($this->fingerprint === $fingerprint && $this->context !== null) {
            return $this->context;
        }

        $this->fingerprint = $fingerprint;

        return $this->context = SemanticContext::fromSourceFiles($files, $this->parser);
    }

    /**
     * @param  array<int, array{path: string, content: string, type?: string}>  $files
     */
    private function fingerprint(array $files): string
    {
        $state = hash_init('xxh128');

        foreach ($files as $file) {
            hash_update($state, $file['path']);
            hash_update($state, "\0");
            hash_update($state, $file['content']);
            hash_update($state, "\0");
        }

        return hash_final($state);
    }
}
