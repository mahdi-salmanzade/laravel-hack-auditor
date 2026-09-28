<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlAnalyzer;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\CodeExtractor;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * LINE FIDELITY: line N of CodeExtractor output must be line N on disk.
 *
 * Every line number a finding carries — AI or deterministic — is read off the
 * extracted text. The docblock strip, blank-line collapse, trim and multi-line
 * PEM redaction each used to delete newlines, so a findOrFail() on line 23 was
 * reported on line 13. The comment strip was also a regex that treated the
 * `/*` in glob('exports/*.csv') as a comment opener and ate the code after it.
 */
beforeEach(function (): void {
    $this->tempDir = sys_get_temp_dir().'/hack-auditor-fidelity-'.uniqid();
    mkdir($this->tempDir.'/app/Http/Controllers', 0755, true);
    $this->tempDir = realpath($this->tempDir);

    $reflector = new ReflectionProperty($this->app, 'basePath');
    $reflector->setValue($this->app, $this->tempDir);
    $this->app['config']->set('hack-auditor.privacy.redact_secrets', true);
});

afterEach(function (): void {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($this->tempDir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );

    foreach ($iterator as $file) {
        $file->isDir() ? rmdir($file->getRealPath()) : unlink($file->getRealPath());
    }

    rmdir($this->tempDir);
});

/**
 * A docblock-heavy controller with an IDOR, a same-line block comment, blank
 * runs, a `/*` inside a string and a multi-line PEM literal — everything that
 * used to shift or delete lines.
 */
function fidelityController(): string
{
    return <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\Invoice;
    use Illuminate\Http\Request;

    /**
     * Invoices.
     *
     * Handles invoice display.
     * More text.
     */
    class IdorController extends Controller
    {
        private string $pem = '-----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz
    QIDAQABAoIBAQC9876543210zyxwvutsrqponmlkjihgfedcba
    -----END RSA PRIVATE KEY-----';



        /**
         * Show an invoice.
         *
         * @param int $id
         */
        public function show(Request $request, int $id)
        {
            $files = glob(storage_path('exports/*.csv')); /* same-line */ $count = count($files);

            $invoice = Invoice::findOrFail($id);

            return response()->json($invoice);
        }
    }

    PHP;
}

function fidelityExtract(string $source): array
{
    $path = test()->tempDir.'/app/Http/Controllers/IdorController.php';
    file_put_contents($path, $source);

    return (new CodeExtractor)->extract(new SplFileInfo($path));
}

function fidelityLineOf(string $content, string $needle): int
{
    foreach (explode("\n", $content) as $index => $line) {
        if (str_contains($line, $needle)) {
            return $index + 1;
        }
    }

    return 0;
}

it('keeps every code line of a docblock-heavy controller on its line number', function (): void {
    $source = fidelityController();
    $extracted = fidelityExtract($source);

    foreach (['class IdorController', 'public function show', 'glob(storage_path', 'Invoice::findOrFail($id)', 'return response()->json($invoice)'] as $needle) {
        expect(fidelityLineOf($extracted['content'], $needle))
            ->toBe(fidelityLineOf($source, $needle), "`{$needle}` moved");
    }

    $sourceLines = explode("\n", rtrim($source));
    $extractedLines = explode("\n", $extracted['content']);

    expect(count($extractedLines))->toBe(count($sourceLines))
        ->and($extracted['content'])->not->toContain('Handles invoice display')
        ->and($extracted['content'])->not->toContain('same-line')
        ->and($extracted['content'])->not->toContain('MIIEpAIBAAKCAQEA')
        ->and($extracted['content'])->toContain('__REDACTED_PRIVATE_KEY__');
});

it('does not treat a /* inside a string literal as a comment opener', function (): void {
    $extracted = fidelityExtract(fidelityController());

    expect($extracted['content'])->toContain("glob(storage_path('exports/*.csv'))")
        ->and($extracted['content'])->toContain('$count = count($files);')
        ->and($extracted['content'])->toContain('public function show(Request $request, int $id)')
        ->and($extracted['content'])->toContain('Invoice::findOrFail($id)');
});

it('lands the deterministic IDOR on the real line when run over extracted content', function (): void {
    $source = fidelityController();
    $extracted = fidelityExtract($source);

    $context = new AccessControlContext(routedMethods: [
        'App\Http\Controllers\IdorController@show' => ['route' => 'GET invoices/{id}', 'middleware' => ['web', 'auth']],
    ]);

    $findings = (new AccessControlAnalyzer)->analyze([$extracted], $context);
    $idor = array_values(array_filter($findings, fn ($v): bool => $v->type === VulnerabilityType::Idor));

    expect($idor)->toHaveCount(1)
        ->and($idor[0]->line)->toBe(fidelityLineOf($source, 'Invoice::findOrFail($id)'))
        ->and($idor[0]->line)->toBe(32);
});

it('keeps a same-line block comment from gluing two tokens together', function (): void {
    $extracted = fidelityExtract("<?php\n\$x = new/**/\\stdClass;\n");

    expect($extracted['content'])->toBe("<?php\n\$x = new \\stdClass;");
});
