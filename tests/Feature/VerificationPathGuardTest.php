<?php

declare(strict_types=1);

use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\AI\ResponseParser;
use Mahdi\HackAuditor\Scanner\CodeExtractor;
use Mahdi\HackAuditor\Scanner\FileCollector;
use Mahdi\HackAuditor\Scanner\HackScanner;
use Mahdi\HackAuditor\Scanner\VerificationEngine;

/**
 * `--verify` must never send the provider a file the scan did not.
 *
 * The verification pass used to read whatever `location` the AI returned —
 * `.env`, an absolute path, anything — and send it UNREDACTED. A location is
 * now loaded only when it is inside base_path(), not sensitive, and one of the
 * files this scanner extracted; and it goes through the same redaction.
 */
final class VerificationSpyAdapter extends AIAdapter
{
    /** @var array<int, string> */
    public array $prompts = [];

    /**
     * @param  array<int, array<string, mixed>>  $findings
     */
    public function __construct(private readonly array $findings) {}

    public function sendWithUsage(string $systemPrompt, string $userPrompt): array
    {
        $this->prompts[] = $userPrompt;

        $isVerification = count($this->prompts) > 1;

        $text = $isVerification
            ? '{"verified":false,"exploit":null,"reasoning":"x"}'
            : (string) json_encode(['vulnerabilities' => $this->findings, 'overall_score' => 50, 'summary' => 's']);

        return ['text' => $text, 'usage' => ['prompt_tokens' => 1, 'completion_tokens' => 1]];
    }

    public function send(string $systemPrompt, string $userPrompt): string
    {
        return $this->sendWithUsage($systemPrompt, $userPrompt)['text'];
    }
}

beforeEach(function (): void {
    $this->tempDir = sys_get_temp_dir().'/hack-auditor-verify-guard-'.uniqid();
    mkdir($this->tempDir.'/app/Http/Controllers', 0755, true);
    mkdir($this->tempDir.'/app/Services', 0755, true);
    $this->tempDir = realpath($this->tempDir);

    file_put_contents($this->tempDir.'/.env', "APP_KEY=base64:REALKEYDONOTLEAK\nDB_PASSWORD=prod-db-pass-123\n");
    file_put_contents($this->tempDir.'/app/Services/Unscanned.php', "<?php\n\$note = 'UNSCANNED-FILE-CONTENT';\n");
    file_put_contents($this->tempDir.'/app/Http/Controllers/Probe.php', "<?php\n\$password = \"hunter2hunter2\";\n\$x = 1;\n");

    $this->outside = sys_get_temp_dir().'/hack-auditor-outside-'.uniqid().'.php';
    file_put_contents($this->outside, "<?php\n\$x = 'OUTSIDE-BASE-PATH';\n");

    $reflector = new ReflectionProperty($this->app, 'basePath');
    $reflector->setValue($this->app, $this->tempDir);
    $this->app['config']->set('hack-auditor.privacy.redact_secrets', true);
});

afterEach(function (): void {
    @unlink($this->outside);

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($this->tempDir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );

    foreach ($iterator as $file) {
        $file->isDir() ? rmdir($file->getRealPath()) : unlink($file->getRealPath());
    }

    rmdir($this->tempDir);
});

function verificationGuardScan(array $locations): VerificationSpyAdapter
{
    $findings = array_map(static fn (string $location): array => [
        'type' => 'sensitive_data_exposure',
        'location' => $location,
        'line' => 2,
        'severity' => 'critical',
        'description' => 'Hardcoded secret',
        'proof' => 'x',
        'fix' => 'y',
    ], $locations);

    $ai = new VerificationSpyAdapter($findings);
    $prompts = new PromptBuilder;
    $parser = new ResponseParser;

    $scanner = new HackScanner(
        new FileCollector,
        new CodeExtractor,
        $prompts,
        $parser,
        $ai,
        verificationEngine: new VerificationEngine($ai, $prompts, $parser),
    );

    $scanner->setVerify(true);
    $scanner->scanFile('app/Http/Controllers/Probe.php');

    return $ai;
}

it('never loads .env, out-of-tree or unscanned files for verification', function (): void {
    $ai = verificationGuardScan([
        '.env',
        test()->outside,
        '../'.basename(dirname(test()->outside)).'/'.basename(test()->outside),
        'app/Services/Unscanned.php',
    ]);

    $all = implode("\n", $ai->prompts);

    expect($ai->prompts)->toHaveCount(1)
        ->and($all)->not->toContain('REALKEYDONOTLEAK')
        ->and($all)->not->toContain('prod-db-pass-123')
        ->and($all)->not->toContain('OUTSIDE-BASE-PATH')
        ->and($all)->not->toContain('UNSCANNED-FILE-CONTENT');
});

it('verifies a scanned file with the same redaction the scan pass applied', function (): void {
    $ai = verificationGuardScan(['app/Http/Controllers/Probe.php']);

    expect($ai->prompts)->toHaveCount(2)
        ->and($ai->prompts[1])->toContain('__REDACTED_SECRET__')
        ->and($ai->prompts[1])->not->toContain('hunter2hunter2');
});
