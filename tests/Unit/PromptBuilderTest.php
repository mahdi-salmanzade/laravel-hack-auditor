<?php

declare(strict_types=1);

use Mahdi\HackAuditor\AI\PromptBuilder;

beforeEach(function (): void {
    $this->builder = new PromptBuilder;
});

it('system prompt contains Laravel security auditor phrase', function (): void {
    $prompt = $this->builder->systemPrompt();

    expect($prompt)->toContain('Laravel security auditor');
});

it('system prompt references context-first analysis', function (): void {
    $prompt = $this->builder->systemPrompt();

    expect($prompt)->toContain('CONTEXT-FIRST ANALYSIS');
});

it('system prompt contains key vulnerability categories', function (): void {
    $prompt = $this->builder->systemPrompt();

    expect($prompt)->toContain('SQL injection')
        ->and($prompt)->toContain('CSRF')
        ->and($prompt)->toContain('Mass assignment')
        ->and($prompt)->toContain('IDOR')
        ->and($prompt)->toContain('Rate limiting')
        ->and($prompt)->toContain('authentication')
        ->and($prompt)->toContain('Unserialization')
        ->and($prompt)->toContain('Open redirect')
        ->and($prompt)->toContain('sensitive data')
        ->and($prompt)->toContain('Missing validation');
});

it('system prompt instructs to return valid JSON', function (): void {
    $prompt = $this->builder->systemPrompt();

    expect($prompt)->toContain('valid JSON')
        ->and($prompt)->toContain('"vulnerabilities"')
        ->and($prompt)->toContain('"overall_score"')
        ->and($prompt)->toContain('"summary"');
});

it('system prompt specifies the severity levels', function (): void {
    $prompt = $this->builder->systemPrompt();

    expect($prompt)->toContain('Critical')
        ->and($prompt)->toContain('High')
        ->and($prompt)->toContain('Medium')
        ->and($prompt)->toContain('Low');
});

it('user prompt formats files correctly with markdown code fences', function (): void {
    $files = [
        [
            'path' => 'app/Http/Controllers/UserController.php',
            'content' => '<?php class UserController extends Controller {}',
            'type' => 'controller',
        ],
        [
            'path' => 'app/Models/User.php',
            'content' => '<?php class User extends Model {}',
            'type' => 'model',
        ],
    ];

    $prompt = $this->builder->userPrompt($files);

    expect($prompt)->toContain('Analyze the following Laravel application files')
        ->and($prompt)->toContain('### File: app/Http/Controllers/UserController.php')
        ->and($prompt)->toContain('```php')
        ->and($prompt)->toContain('<?php class UserController extends Controller {}')
        ->and($prompt)->toContain('### File: app/Models/User.php')
        ->and($prompt)->toContain('<?php class User extends Model {}');
});

it('user prompt handles empty files array', function (): void {
    $prompt = $this->builder->userPrompt([]);

    expect($prompt)->toContain('Analyze the following Laravel application files')
        ->and($prompt)->not->toContain('### File:');
});

it('user prompt includes each file path as a header', function (): void {
    $files = [
        [
            'path' => 'routes/web.php',
            'content' => '<?php Route::get("/", fn() => "hello");',
            'type' => 'route',
        ],
    ];

    $prompt = $this->builder->userPrompt($files);

    expect($prompt)->toContain('### File: routes/web.php');
});

it('ctf prompt includes the vulnerability type', function (): void {
    $prompt = $this->builder->ctfPrompt('SQL Injection', '<?php DB::select("SELECT * FROM users WHERE id = $id");');

    expect($prompt)->toContain('SQL Injection')
        ->and($prompt)->toContain('CTF')
        ->and($prompt)->toContain('Capture The Flag')
        ->and($prompt)->toContain('Vulnerability Type')
        ->and($prompt)->toContain('DB::select');
});

it('ctf prompt includes the vulnerable code', function (): void {
    $code = '<?php unserialize($request->cookie("prefs"));';
    $prompt = $this->builder->ctfPrompt('Insecure Deserialization', $code);

    expect($prompt)->toContain($code)
        ->and($prompt)->toContain('Insecure Deserialization');
});

it('ctf prompt instructs to generate JSON with required fields', function (): void {
    $prompt = $this->builder->ctfPrompt('XSS', '<?php echo $name;');

    expect($prompt)->toContain('"title"')
        ->and($prompt)->toContain('"difficulty"')
        ->and($prompt)->toContain('"challenge_code"')
        ->and($prompt)->toContain('"solution"')
        ->and($prompt)->toContain('"flag"')
        ->and($prompt)->toContain('FLAG{');
});

it('ctf prompt specifies flag format as FLAG{...}', function (): void {
    $prompt = $this->builder->ctfPrompt('CSRF', '<?php // no csrf');

    expect($prompt)->toContain('FLAG{');
});
