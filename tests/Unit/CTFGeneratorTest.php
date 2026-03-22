<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;
use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\CTF\CTFGenerator;

beforeEach(function (): void {
    $this->outputBase = sys_get_temp_dir().'/hack-auditor-ctf-test-'.uniqid();
    mkdir($this->outputBase, 0755, true);

    // Override storage_path to use our temp directory
    $this->app['config']->set('hack-auditor.ctf.output_path', 'hack-auditor/ctf');
});

afterEach(function (): void {
    // Clean up generated CTF files
    if (is_dir($this->outputBase)) {
        File::deleteDirectory($this->outputBase);
    }

    // Also clean up any CTF dirs created in storage
    $storagePath = storage_path('hack-auditor');
    if (is_dir($storagePath)) {
        File::deleteDirectory($storagePath);
    }
});

function buildCTFAIResponse(): string
{
    return json_encode([
        'title' => 'SQL Injection Challenge',
        'difficulty' => 'Medium',
        'category' => 'Web Security',
        'description' => 'A vulnerable login form awaits exploitation.',
        'rules' => 'No brute force. Find the SQL injection.',
        'hints' => 'Look at the login query carefully.',
        'challenge_code' => '<?php DB::select("SELECT * FROM users WHERE id = $id");',
        'solution_explanation' => 'Use a UNION-based injection.',
        'fix_explanation' => 'Use parameterized queries.',
    ], JSON_THROW_ON_ERROR);
}

function createMockedCTFGenerator(string $aiResponse): CTFGenerator
{
    $mockAdapter = Mockery::mock(AIAdapter::class);
    $mockAdapter->shouldReceive('ask')->andReturn($aiResponse);

    $mockPromptBuilder = Mockery::mock(PromptBuilder::class);
    $mockPromptBuilder->shouldReceive('forCtfGeneration')->andReturn('system prompt');
    $mockPromptBuilder->shouldReceive('ctfGeneric')->andReturn('user prompt');
    $mockPromptBuilder->shouldReceive('ctfFromSourceCode')->andReturn('user prompt with source');

    return new CTFGenerator(
        ai: $mockAdapter,
        promptBuilder: $mockPromptBuilder,
    );
}

it('creates the output directory', function (): void {
    $generator = createMockedCTFGenerator(buildCTFAIResponse());

    $outputPath = $generator->generate('sql_injection');

    expect(is_dir($outputPath))->toBeTrue();
});

it('generates README.md file', function (): void {
    $generator = createMockedCTFGenerator(buildCTFAIResponse());

    $outputPath = $generator->generate('sql_injection');

    expect(file_exists("{$outputPath}/README.md"))->toBeTrue();

    $readme = file_get_contents("{$outputPath}/README.md");
    expect($readme)->toContain('SQL Injection Challenge')
        ->and($readme)->toContain('Medium')
        ->and($readme)->toContain('Web Security');
});

it('generates challenge.php file', function (): void {
    $generator = createMockedCTFGenerator(buildCTFAIResponse());

    $outputPath = $generator->generate('sql_injection');

    expect(file_exists("{$outputPath}/challenge.php"))->toBeTrue();

    $challenge = file_get_contents("{$outputPath}/challenge.php");
    expect($challenge)->toContain('DB::select');
});

it('generates solution.php file', function (): void {
    $generator = createMockedCTFGenerator(buildCTFAIResponse());

    $outputPath = $generator->generate('sql_injection');

    expect(file_exists("{$outputPath}/solution.php"))->toBeTrue();

    $solution = file_get_contents("{$outputPath}/solution.php");
    expect($solution)->toContain('SPOILER WARNING')
        ->and($solution)->toContain('HOW TO EXPLOIT')
        ->and($solution)->toContain('HOW TO FIX');
});

it('generates flag.txt file with correct format', function (): void {
    $generator = createMockedCTFGenerator(buildCTFAIResponse());

    $outputPath = $generator->generate('sql_injection');

    expect(file_exists("{$outputPath}/flag.txt"))->toBeTrue();

    $flag = trim(file_get_contents("{$outputPath}/flag.txt"));
    expect($flag)->toMatch('/^FLAG\{hack_auditor_sql_injection_[a-f0-9]{6}\}$/');
});

it('generates docker-compose.yml file', function (): void {
    $generator = createMockedCTFGenerator(buildCTFAIResponse());

    $outputPath = $generator->generate('sql_injection');

    expect(file_exists("{$outputPath}/docker-compose.yml"))->toBeTrue();

    $dockerCompose = file_get_contents("{$outputPath}/docker-compose.yml");
    expect($dockerCompose)->toContain('services')
        ->and($dockerCompose)->toContain('nginx')
        ->and($dockerCompose)->toContain('php')
        ->and($dockerCompose)->toContain('mysql');
});

it('generates all expected files', function (): void {
    $generator = createMockedCTFGenerator(buildCTFAIResponse());

    $outputPath = $generator->generate('xss');

    $expectedFiles = ['README.md', 'challenge.php', 'solution.php', 'flag.txt', 'docker-compose.yml'];

    foreach ($expectedFiles as $file) {
        expect(file_exists("{$outputPath}/{$file}"))->toBeTrue("Expected file {$file} to exist in {$outputPath}");
    }
});

it('returns the correct output path', function (): void {
    $generator = createMockedCTFGenerator(buildCTFAIResponse());

    $outputPath = $generator->generate('sql_injection');

    expect($outputPath)->toBeString()
        ->and($outputPath)->toContain('sql_injection')
        ->and(is_dir($outputPath))->toBeTrue();
});

it('flag format matches FLAG{hack_auditor_*} pattern', function (): void {
    $generator = createMockedCTFGenerator(buildCTFAIResponse());

    $outputPath = $generator->generate('mass_assignment');

    $flag = trim(file_get_contents("{$outputPath}/flag.txt"));

    expect($flag)->toStartWith('FLAG{hack_auditor_')
        ->and($flag)->toEndWith('}')
        ->and($flag)->toMatch('/^FLAG\{hack_auditor_mass_assignment_[a-f0-9]{6}\}$/');
});

it('includes the vulnerability type slug in the directory name', function (): void {
    $generator = createMockedCTFGenerator(buildCTFAIResponse());

    $outputPath = $generator->generate('open_redirect');

    expect($outputPath)->toContain('open_redirect');
});

it('passes source code to the AI when provided', function (): void {
    $mockAdapter = Mockery::mock(AIAdapter::class);
    $mockAdapter->shouldReceive('ask')
        ->once()
        ->andReturn(buildCTFAIResponse());

    $mockPromptBuilder = Mockery::mock(PromptBuilder::class);
    $mockPromptBuilder->shouldReceive('forCtfGeneration')->andReturn('system prompt');
    $mockPromptBuilder->shouldReceive('ctfFromSourceCode')
        ->once()
        ->withArgs(function (string $type, string $source, string $flag): bool {
            return $type === 'sql_injection' && str_contains($source, 'vulnerable code');
        })
        ->andReturn('user prompt with source');

    $generator = new CTFGenerator(
        ai: $mockAdapter,
        promptBuilder: $mockPromptBuilder,
    );

    $generator->generate('sql_injection', '<?php // vulnerable code');
});
