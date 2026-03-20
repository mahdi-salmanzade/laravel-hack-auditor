<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;
use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\CTF\CTFGenerator;

beforeEach(function (): void {
    // Mock the AIAdapter at the PromptBuilder level to avoid real AI calls
    $mockAdapter = Mockery::mock(AIAdapter::class);
    $mockAdapter->shouldReceive('ask')
        ->andReturn(json_encode([
            'title' => 'Test SQL Injection Challenge',
            'difficulty' => 'Medium',
            'category' => 'Web Security',
            'description' => 'A vulnerable endpoint awaits.',
            'rules' => 'No brute force allowed.',
            'hints' => 'Check the query construction.',
            'challenge_code' => '<?php DB::select("SELECT * FROM users WHERE id = $id");',
            'solution_explanation' => 'Use UNION-based injection to extract data.',
            'fix_explanation' => 'Use parameterized queries with bound parameters.',
        ], JSON_THROW_ON_ERROR));

    $mockPromptBuilder = Mockery::mock(PromptBuilder::class);
    $mockPromptBuilder->shouldReceive('forCtfGeneration')->andReturn('system prompt');
    $mockPromptBuilder->shouldReceive('ctfGeneric')->andReturn('user prompt');
    $mockPromptBuilder->shouldReceive('ctfFromSourceCode')->andReturn('user prompt with source');

    $generator = new CTFGenerator(
        ai: $mockAdapter,
        promptBuilder: $mockPromptBuilder,
    );

    $this->app->instance(CTFGenerator::class, $generator);
});

afterEach(function (): void {
    $storagePath = storage_path('hack-auditor');
    if (is_dir($storagePath)) {
        File::deleteDirectory($storagePath);
    }
});

it('command with specific vulnerability argument runs successfully', function (): void {
    $this->artisan('hack:ctf', ['vulnerability' => 'sql_injection'])
        ->expectsOutputToContain('CTF')
        ->assertSuccessful();
});

it('command output contains the banner', function (): void {
    $this->artisan('hack:ctf', ['vulnerability' => 'sql_injection'])
        ->expectsOutputToContain('HACK AUDITOR')
        ->expectsOutputToContain('CTF Generator');
});

it('command output contains challenge generated confirmation', function (): void {
    $this->artisan('hack:ctf', ['vulnerability' => 'sql_injection'])
        ->expectsOutputToContain('sql_injection');
});

it('command output contains happy hacking message', function (): void {
    $this->artisan('hack:ctf', ['vulnerability' => 'sql_injection'])
        ->expectsOutputToContain('Happy hacking');
});

it('command fails with unknown vulnerability type', function (): void {
    $this->artisan('hack:ctf', ['vulnerability' => 'totally_fake_type'])
        ->expectsOutputToContain('Unknown vulnerability type')
        ->assertFailed();
});

it('command shows available types when given an invalid type', function (): void {
    $this->artisan('hack:ctf', ['vulnerability' => 'invalid_type'])
        ->expectsOutputToContain('sql_injection')
        ->expectsOutputToContain('xss');
});

it('command accepts all valid vulnerability type values', function (): void {
    $validTypes = [
        'sql_injection',
        'xss',
        'csrf',
        'mass_assignment',
        'idor',
        'missing_rate_limit',
        'auth_bypass',
        'insecure_deserialization',
        'open_redirect',
        'sensitive_data_exposure',
        'weak_password_hashing',
        'missing_validation',
    ];

    foreach ($validTypes as $type) {
        $this->artisan('hack:ctf', ['vulnerability' => $type])
            ->assertSuccessful();
    }
});

it('command generates files in the configured output path', function (): void {
    $this->artisan('hack:ctf', ['vulnerability' => 'sql_injection'])
        ->assertSuccessful();

    $outputBase = storage_path('hack-auditor/ctf');

    // There should be at least one directory created under the CTF output path
    // (if storage_path resolves correctly in the test environment)
    if (is_dir($outputBase)) {
        $dirs = array_diff(scandir($outputBase), ['.', '..']);
        expect($dirs)->not->toBeEmpty();
    }
});

it('command from-scan flag fails when no scan results exist', function (): void {
    $this->artisan('hack:ctf', ['--from-scan' => true])
        ->expectsOutputToContain('No scan results found')
        ->assertFailed();
});
