<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner;

use Illuminate\Support\Collection;
use Mahdi\HackAuditor\Support\SecretRedactor;
use SplFileInfo;

final class CodeExtractor
{
    /**
     * Real paths of every file this extractor has read for analysis. Lets the
     * `--verify` pass refuse to load a location the AI invented rather than one
     * the scan actually covered.
     *
     * @var array<string, true>
     */
    private array $extractedPaths = [];

    public function __construct(private readonly SecretRedactor $redactor = new SecretRedactor) {}

    /**
     * Whether this extractor has read the given real path for analysis.
     */
    public function hasExtracted(string $realPath): bool
    {
        return isset($this->extractedPaths[$realPath]);
    }

    /**
     * Extract file contents and metadata for AI analysis.
     *
     * Reads the file, determines its type from its class declaration and
     * location, strips block/doc comments and trailing whitespace, and redacts
     * secrets. Every step preserves line positions: line N of the returned
     * content is line N of the file on disk.
     *
     * @return array{path: string, content: string, type: string}
     */
    public function extract(SplFileInfo $file): array
    {
        $realPath = $file->getRealPath();

        if ($realPath === false) {
            return [
                'path' => $file->getPathname(),
                'content' => '',
                'type' => 'other',
            ];
        }

        $basePath = base_path().DIRECTORY_SEPARATOR;
        $relativePath = str_starts_with($realPath, $basePath)
            ? substr($realPath, strlen($basePath))
            : $realPath;

        if (is_dir($realPath)) {
            return [
                'path' => $file->getPathname(),
                'content' => '',
                'type' => 'other',
            ];
        }

        $this->extractedPaths[$realPath] = true;

        $content = (string) file_get_contents($realPath);
        $cleanedContent = $this->cleanContent($content);
        $cleanedContent = $this->redactSecrets($cleanedContent);
        $type = $this->detectType($content, $relativePath);

        return [
            'path' => $relativePath,
            'content' => $cleanedContent,
            'type' => $type,
        ];
    }

    /**
     * Estimate the token count for a string.
     *
     * Uses a rough heuristic of ~4 characters per token, which is conservative
     * enough to avoid blowing context windows.
     */
    public function estimateTokens(string $content): int
    {
        return (int) ceil(strlen($content) / 4);
    }

    /**
     * Group extracted files into chunks for batched AI requests.
     *
     * Uses token-aware chunking: estimates tokens per file and caps each chunk
     * at ~60% of the configured max_tokens to leave room for the system prompt
     * and AI response. Falls back to file-count chunking only as a secondary limit.
     *
     * @param  Collection<int, SplFileInfo>  $files
     * @return array<int, array<int, array{path: string, content: string, type: string}>>
     */
    public function chunk(Collection $files): array
    {
        /** @var int $maxFilesPerChunk */
        $maxFilesPerChunk = config('hack-auditor.scan.chunk_size', 10);

        /** @var int $maxTokens */
        $maxTokens = (int) config('hack-auditor.ai.max_tokens', 4096);

        $tokenBudget = (int) ($maxTokens * 2.5);

        $extracted = $files->map(fn (SplFileInfo $file): array => $this->extract($file));

        $chunks = [];
        $currentChunk = [];
        $currentTokens = 0;

        foreach ($extracted as $file) {
            $fileTokens = $this->estimateTokens($file['content']);

            $wouldExceedTokens = $currentTokens + $fileTokens > $tokenBudget && count($currentChunk) > 0;
            $wouldExceedFiles = count($currentChunk) >= $maxFilesPerChunk;

            if ($wouldExceedTokens || $wouldExceedFiles) {
                $chunks[] = $currentChunk;
                $currentChunk = [];
                $currentTokens = 0;
            }

            $currentChunk[] = $file;
            $currentTokens += $fileTokens;
        }

        if (count($currentChunk) > 0) {
            $chunks[] = $currentChunk;
        }

        return $chunks;
    }

    /**
     * The first named class a PHP source declares, read from the token stream.
     *
     * `/class\s+(\w+)/` matched the word "class" anywhere — a `// This class
     * exposes invoices` comment produced the FQCN `App\Http\Controllers\exposes`,
     * the route table had nothing for it, and the IDOR detector went silent.
     * Tokens make comments, strings, `Foo::class` and `new class {}` impossible
     * to confuse with a declaration. Works on fragments and unparsable files
     * alike, since token_get_all() never throws.
     *
     * @return array{namespace: string|null, class: string, fqcn: string, extends: string|null}|null
     */
    public static function classDeclaration(string $source): ?array
    {
        $tokens = array_values(array_filter(
            token_get_all($source),
            static fn (array|string $token): bool => ! is_array($token)
                || ! in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
        ));

        $namespace = null;
        $count = count($tokens);

        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];

            if (! is_array($token)) {
                continue;
            }

            if ($token[0] === T_NAMESPACE) {
                $next = $tokens[$i + 1] ?? null;

                if (is_array($next) && in_array($next[0], [T_STRING, T_NAME_QUALIFIED], true)) {
                    $namespace = $next[1];
                } elseif ($next === '{' || $next === ';') {
                    $namespace = null;
                }

                continue;
            }

            if ($token[0] !== T_CLASS) {
                continue;
            }

            $previous = $tokens[$i - 1] ?? null;

            // `Foo::class` is a constant fetch and `new class` is anonymous.
            if (is_array($previous) && in_array($previous[0], [T_DOUBLE_COLON, T_NEW], true)) {
                continue;
            }

            $name = $tokens[$i + 1] ?? null;

            if (! is_array($name) || $name[0] !== T_STRING) {
                continue;
            }

            $extends = null;
            $afterName = $tokens[$i + 2] ?? null;
            $parent = $tokens[$i + 3] ?? null;

            if (is_array($afterName) && $afterName[0] === T_EXTENDS
                && is_array($parent) && in_array($parent[0], [T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED], true)) {
                $extends = ltrim($parent[1], '\\');
            }

            return [
                'namespace' => $namespace,
                'class' => $name[1],
                'fqcn' => $namespace !== null ? $namespace.'\\'.$name[1] : $name[1],
                'extends' => $extends,
            ];
        }

        return null;
    }

    /**
     * Detect the file type from its class declaration and location.
     *
     * Only a direct `extends Controller` used to count, so an
     * `InvoiceController extends ApiController` was 'other': the scanner never
     * asked the router about it and every deterministic detector that needs a
     * route table treated it as unreachable. A class is now a controller when
     * it extends anything named *Controller, is itself named *Controller, or
     * lives under app/Http/Controllers/; models, requests and middleware get
     * the same parent-suffix and directory treatment.
     */
    private function detectType(string $content, string $relativePath): string
    {
        $path = str_replace('\\', '/', $relativePath);

        if (str_starts_with($path, 'routes/') || str_contains($path, '/routes/')) {
            return 'route';
        }

        $declaration = self::classDeclaration($content);

        if ($declaration === null) {
            return 'other';
        }

        $class = $declaration['class'];
        $parent = $declaration['extends'] !== null ? $this->shortName($declaration['extends']) : '';

        if (str_ends_with($parent, 'Controller')) {
            return 'controller';
        }

        if (in_array($parent, ['Model', 'Authenticatable', 'Pivot', 'MorphPivot', 'User'], true)) {
            return 'model';
        }

        if (str_ends_with($parent, 'FormRequest')) {
            return 'request';
        }

        if ($parent === 'Middleware') {
            return 'middleware';
        }

        if (str_ends_with($class, 'Controller') || $this->isUnder($path, 'app/Http/Controllers')) {
            return 'controller';
        }

        if ($this->isUnder($path, 'app/Models')) {
            return 'model';
        }

        if ($this->isUnder($path, 'app/Http/Requests') || str_ends_with($parent, 'Request')) {
            return 'request';
        }

        if ($this->isUnder($path, 'app/Http/Middleware')) {
            return 'middleware';
        }

        return 'other';
    }

    /**
     * Whether a relative path lies inside the given directory, matched on whole
     * path segments.
     */
    private function isUnder(string $path, string $directory): bool
    {
        return str_starts_with($path, $directory.'/') || str_contains($path, '/'.$directory.'/');
    }

    /**
     * The unqualified part of a class name.
     */
    private function shortName(string $name): string
    {
        $position = strrpos($name, '\\');

        return $position === false ? $name : substr($name, $position + 1);
    }

    /**
     * Redact hardcoded secret values from content before it is ever sent to a
     * cloud AI provider. Replaces secret VALUES with detection-friendly markers
     * so the AI can still flag the presence of a hardcoded secret without seeing
     * its actual value. Controlled by the privacy.redact_secrets config flag.
     */
    private function redactSecrets(string $content): string
    {
        if (! config('hack-auditor.privacy.redact_secrets', true)) {
            return $content;
        }

        return $this->redactor->redact($content);
    }

    /**
     * Strip block and doc comments while preserving every line position.
     *
     * The invariant: line N of the extracted content is line N of the file on
     * disk. Findings, `--verify` and the deterministic detectors all report
     * lines read off this text, so anything that deletes a newline makes every
     * line below it lie. That is why comments are replaced by exactly as many
     * newlines as they spanned, blank lines are never collapsed, and nothing is
     * trimmed from the front.
     *
     * Comments are found with token_get_all(). The previous regex treated the
     * `/*` inside `glob('exports/*.csv')` as a comment opener and deleted the
     * code up to the next `* /`, method signatures and IDORs included.
     */
    private function cleanContent(string $content): string
    {
        $cleaned = '';

        foreach (token_get_all($content) as $token) {
            if (! is_array($token)) {
                $cleaned .= $token;

                continue;
            }

            [$id, $text] = $token;

            if ($id === T_DOC_COMMENT || ($id === T_COMMENT && str_starts_with($text, '/*'))) {
                $newlines = substr_count($text, "\n");

                if ($newlines > 0) {
                    $cleaned .= str_repeat("\n", $newlines);
                } elseif ($cleaned !== '' && ! ctype_space(substr($cleaned, -1))) {
                    // A same-line comment becomes a space so `new/**/Foo` stays two tokens.
                    $cleaned .= ' ';
                }

                continue;
            }

            if ($id === T_WHITESPACE) {
                $text = (string) preg_replace("/[ \t]+(?=\r?\n)/", '', $text);
            } elseif ($id === T_COMMENT) {
                $text = rtrim($text, " \t");
            }

            $cleaned .= $text;
        }

        return rtrim($cleaned);
    }
}
