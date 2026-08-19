<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

use PhpParser\Error as ParserError;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\NodeVisitor\ParentConnectingVisitor;
use PhpParser\Parser;
use PhpParser\ParserFactory;
use Throwable;

/**
 * Parses PHP source into an annotated AST exactly once per (path, content)
 * pair and caches the result.
 *
 * This is the single entry point for the semantic layer. Detectors built on it
 * must never re-derive structure with a regex over raw source: every previous
 * false positive in this package (the $fillable apostrophe bug, the method
 * signature offsets, the SSRF verb patterns) came from doing exactly that.
 *
 * Degrading gracefully is a hard requirement. A file that cannot be parsed —
 * a PHP version we do not understand, a truncated chunk, a Blade template that
 * was mis-classified as PHP — produces an UNANALYSABLE ParsedFile. Callers get
 * no nodes, therefore no findings, and the file is recorded in errors() so the
 * report can say "not analysed" instead of guessing.
 *
 * The AST is annotated by two visitors:
 *  - NameResolver in non-replacing mode, which attaches a `resolvedName`
 *    attribute to every Name node (so `Post::find()` under
 *    `use App\Models\Post;` resolves to `App\Models\Post`) and a
 *    `namespacedName` to every class-like declaration.
 *  - ParentConnectingVisitor, so a node can be interpreted in the context of
 *    its parent (e.g. distinguishing an assignment target from a read).
 */
final class PhpAstParser
{
    /**
     * Total size of the syntax trees held at once, in bytes.
     *
     * An unbounded cache grew linearly with application size and crossed PHP's
     * default 128M memory_limit at around 640 files. A 750-file application died
     * mid-scan with "Allowed memory size exhausted", a FATAL that no try/catch
     * can intercept, so the graceful-degradation path above never ran and the
     * scan produced nothing at all.
     *
     * The budget is in BYTES, not files, because file count is a bad proxy for
     * what a syntax tree costs. Measured over the corpus, an annotated AST runs
     * 50-130x the size of its source: a typical 3 KB Laravel controller costs
     * ~0.2 MB, but pixelfed's 170 KB ApiV1Controller costs 22 MB on its own. A
     * 300-FILE cap therefore held anywhere between 15 MB and 300 MB depending on
     * which files happened to be resident, and a single fat controller arriving
     * on top of a full cache was still enough to kill the process.
     *
     * The cost measured here is the real allocation delta of the parse, so the
     * budget means what it says regardless of how the files are shaped.
     */
    private const MAX_CACHED_AST_BYTES = 24 * 1024 * 1024;

    /**
     * Secondary cap for pathologically small files, so a scan of ten thousand
     * one-line stubs cannot accumulate unbounded per-object overhead that the
     * byte budget alone would not notice.
     */
    private const MAX_CACHED_FILES = 400;

    /**
     * Floor charged to any cached entry, covering the ParsedFile, its token
     * array and the allocator's own bookkeeping when the measured delta is
     * implausibly small.
     */
    private const MIN_ENTRY_COST = 8 * 1024;

    private ?Parser $parser = null;

    /**
     * Insertion-ordered cache, evicted least-recently-used first.
     *
     * @var array<string, ParsedFile>
     */
    private array $cache = [];

    /**
     * Measured cost in bytes of each cached entry, in the same order.
     *
     * @var array<string, int>
     */
    private array $costs = [];

    private int $cachedBytes = 0;

    private int $parseCount = 0;

    /**
     * Paths that failed to parse, mapped to the reason.
     *
     * @var array<string, string>
     */
    private array $errors = [];

    /**
     * Parse source into a ParsedFile, reusing a cached AST when the same path
     * and identical content have already been parsed.
     */
    public function parse(string $path, string $source): ParsedFile
    {
        $key = $path.'@'.hash('xxh128', $source);

        if (isset($this->cache[$key])) {
            // Refresh recency so a file a detector keeps revisiting is not the
            // one evicted next. Cross-file lookups (a model, a base controller,
            // a policy) are re-asked constantly while a streaming pass churns
            // through everything else, and this is what keeps them resident.
            $parsed = $this->cache[$key];
            $cost = $this->costs[$key];
            unset($this->cache[$key], $this->costs[$key]);
            $this->costs[$key] = $cost;

            return $this->cache[$key] = $parsed;
        }

        $this->parseCount++;

        $before = memory_get_usage();
        $parsed = $this->parseUncached($path, $source);
        $cost = max(self::MIN_ENTRY_COST, memory_get_usage() - $before);

        $this->cache[$key] = $parsed;
        $this->costs[$key] = $cost;
        $this->cachedBytes += $cost;

        $this->evict();

        return $parsed;
    }

    /**
     * Bytes of syntax tree currently held. Exposed so a test can assert the
     * bound rather than trusting it.
     */
    public function cachedBytes(): int
    {
        return $this->cachedBytes;
    }

    public function cachedFiles(): int
    {
        return count($this->cache);
    }

    /**
     * How many times source has actually been turned into a syntax tree. A
     * cache hit does not count, so this is the honest measure of the work a
     * bounded cache costs.
     */
    public function parseCount(): int
    {
        return $this->parseCount;
    }

    /**
     * Drop least-recently-used entries until the cache is inside its budget.
     *
     * One entry always survives: a file whose tree is larger than the whole
     * budget still has to be analysable, and the caller is holding it anyway.
     */
    private function evict(): void
    {
        while (count($this->cache) > 1
            && ($this->cachedBytes > self::MAX_CACHED_AST_BYTES || count($this->cache) > self::MAX_CACHED_FILES)) {
            // The loop condition guarantees at least two entries, so this key
            // is always a string — no null branch to guard.
            $oldest = (string) array_key_first($this->cache);

            $this->cachedBytes -= $this->costs[$oldest];
            unset($this->cache[$oldest], $this->costs[$oldest]);
        }
    }

    /**
     * Parse a file from disk. An unreadable file is unanalysable, not empty.
     */
    public function parseFile(string $path): ParsedFile
    {
        $source = @file_get_contents($path);

        if ($source === false) {
            $this->errors[$path] = 'file could not be read';

            return ParsedFile::unanalysable($path, '', 'file could not be read');
        }

        return $this->parse($path, $source);
    }

    /**
     * Paths that could not be analysed, mapped to the reason.
     *
     * @return array<string, string>
     */
    public function errors(): array
    {
        return $this->errors;
    }

    /**
     * Whether any file handed to this parser failed to parse.
     */
    public function hasErrors(): bool
    {
        return $this->errors !== [];
    }

    private function parseUncached(string $path, string $source): ParsedFile
    {
        $parser = $this->parser ??= (new ParserFactory)->createForNewestSupportedVersion();

        try {
            $statements = $parser->parse($source);
        } catch (ParserError $error) {
            return $this->fail($path, $source, $error->getMessage());
        } catch (Throwable $error) {
            return $this->fail($path, $source, $error->getMessage());
        }

        if ($statements === null) {
            return $this->fail($path, $source, 'parser produced no statements');
        }

        $tokens = $parser->getTokens();

        try {
            $traverser = new NodeTraverser(
                new NameResolver(null, ['preserveOriginalNames' => true, 'replaceNodes' => false]),
                new ParentConnectingVisitor,
            );

            $statements = array_values(array_filter(
                $traverser->traverse($statements),
                static fn (Node $node): bool => $node instanceof Node\Stmt,
            ));
        } catch (Throwable $error) {
            return $this->fail($path, $source, 'name resolution failed: '.$error->getMessage());
        }

        unset($this->errors[$path]);

        return ParsedFile::analysed($path, $source, $statements, $tokens);
    }

    private function fail(string $path, string $source, string $reason): ParsedFile
    {
        $this->errors[$path] = $reason;

        return ParsedFile::unanalysable($path, $source, $reason);
    }
}
