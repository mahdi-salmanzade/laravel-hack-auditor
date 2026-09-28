<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Support\SecretRedactor;

/**
 * Name-bound redaction runs on token_get_all(), and value-shape detectors
 * recognise provider credentials wherever they appear.
 *
 * The old STRING_LITERAL regex paired a closing quote with the NEXT opening
 * quote, so it rewrote the injected variable out of a SQL string — hiding the
 * SQL injection from the AI — and swallowed validation rules keyed `password`.
 */
beforeEach(function (): void {
    $this->redactor = new SecretRedactor;
});

it('leaves code untouched where a secret keyword is only text inside a string', function (string $code): void {
    expect($this->redactor->redact($code))->toBe($code)
        ->and($this->redactor->lastRedactionCount())->toBe(0);
})->with([
    'sqli concatenation' => ['DB::select("SELECT * FROM users WHERE password = \'" . $request->input(\'p\') . "\'");'],
    'ssrf token param' => ['$r = Http::get("https://x.test/?token=" . $request->query(\'next\'));'],
    'validation rules' => ['$request->validate([\'password\' => \'required|string|min:8\']);'],
    'rules with confirmed' => ['return [\'password\' => \'required|confirmed|min:12\', \'token\' => \'required\'];'],
    'hashed cast' => ['protected $casts = [\'password\' => \'hashed\', \'api_token\' => \'encrypted\'];'],
    'env() key' => ['$key = env(\'STRIPE_SECRET\');'],
    'config path' => ['\'secret\' => \'services.stripe.secret\','],
    'env var name as value' => ['\'password\' => \'DB_PASSWORD\','],
    'metadata key' => ['\'token_header\' => \'X-Api-Token\', \'password_field\' => \'passwd\','],
    'validation message' => ['\'password.required\' => \'The :attribute field is required.\','],
    'ternary' => ['$label = $isToken ? \'token\' : \'somethingelse\';'],
]);

it('keeps the injected variable of a SQL string visible even when a real secret sits beside it', function (): void {
    $code = <<<'PHP'
    <?php
    $password = 'hunter2hunter2';
    DB::select("SELECT * FROM users WHERE password = '" . $request->input('p') . "'");
    PHP;

    $result = $this->redactor->redact($code);

    expect($result)->toContain("\$password = '__REDACTED_SECRET__';")
        ->and($result)->toContain('$request->input(\'p\')')
        ->and($result)->not->toContain('hunter2hunter2');
});

it('redacts provider credentials by value shape wherever they appear', function (string $code, string $secret, string $marker): void {
    $result = $this->redactor->redact($code);

    expect($result)->not->toContain($secret)
        ->and($result)->toContain($marker);
})->with([
    // Provider prefixes are split across concatenations so no committed line
    // contains a token-shaped literal: GitHub push protection (rightly) refuses
    // realistic-looking credentials, even fake ones. The runtime strings are
    // exactly the shapes the redactor must catch.
    'stripe live' => ["Stripe::setApiKey('".'sk_'.'live_'."51HxxxxxxxxxxxxxxxxxxxxxxxxxxxxxAbCd');", 'sk_'.'live_51Hxxxx', '__REDACTED_STRIPE_KEY__'],
    'stripe restricted' => ["\$k = '".'rk_'.'test_'."abcdefghijklmnop1234';", 'rk_'.'test_abcdefghij', '__REDACTED_STRIPE_KEY__'],
    'github classic' => ["['X-GH' => '".'gh'.'p_'."1234567890abcdefghijklmnopqrstuvwxyzAB']", 'gh'.'p_1234567890', '__REDACTED_GITHUB_TOKEN__'],
    'github fine-grained' => ["Http::withToken('".'github'.'_pat_'."11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz');", 'github'.'_pat_11ABCDEFG', '__REDACTED_GITHUB_TOKEN__'],
    'slack webhook' => ["\$hook = 'https://hooks.".'slack.com/'."services/T000/B000/XXXXXXXXXXXXXXXXXXXXXXXX';", 'hooks.'.'slack.com/services/T000', '__REDACTED_SLACK_WEBHOOK__'],
    'slack bot token' => ["\$b = '".'xo'.'xb-'."123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx';", 'xo'.'xb-1234567890', '__REDACTED_SLACK_TOKEN__'],
    'jwt' => ["\$jwt = '".'ey'.'JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'.'ey'."JzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';", 'dozjgNryP4J3', '__REDACTED_JWT__'],
    'aws session key' => ["\$k = 'ASIAIOSFODNN7EXAMPLE';", 'ASIAIOSFODNN7EXAMPLE', '__REDACTED_AWS_KEY__'],
    'google api key' => ["\$g = '".'AI'.'za'."SyA1234567890abcdefghijklmnopqrstuv';", 'AI'.'zaSyA1234567890', '__REDACTED_GOOGLE_API_KEY__'],
    'openai key' => ["\$o = '".'sk-'.'proj-'."abcdefghijklmnopqrstuvwxyz012345';", 'sk-'.'proj-abcdefghij', '__REDACTED_AI_API_KEY__'],
    'anthropic key' => ["\$a = '".'sk-'.'ant-'."api03-abcdefghijklmnopqrstuvwxyz';", 'sk-'.'ant-api03-abcdef', '__REDACTED_AI_API_KEY__'],
    'key in a comment' => ['// old key: '.'sk_'.'live_'."abcdefghijklmnop1234\n\$x = 1;", 'sk_'.'live_abcdefghijklmnop1234', '__REDACTED_STRIPE_KEY__'],
    'pgp private key block' => ["-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc\n-----END PGP PRIVATE KEY BLOCK-----", 'abc', '__REDACTED_PRIVATE_KEY__'],
    'ec private key' => ["\$k = '-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIabc\n-----END EC PRIVATE KEY-----';", 'MHcCAQEEIabc', '__REDACTED_PRIVATE_KEY__'],
]);

it('redacts a secret default passed to env()', function (string $code, string $secret): void {
    $result = $this->redactor->redact($code);

    expect($result)->not->toContain($secret)
        ->and($result)->toContain('__REDACTED_SECRET__');
})->with([
    'secret-named env key' => ["'key' => env('STRIPE_SECRET', 'fallback-live-secret-value'),", 'fallback-live-secret-value'],
    'secret-named array key' => ["'secret' => env('AWS', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'),", 'wJalrXUtnFEMI'],
    'define()' => ["define('API_KEY', 'abcdef1234567890');", 'abcdef1234567890'],
]);

it('does not redact a non-secret env() default', function (): void {
    $code = "'driver' => env('CACHE_DRIVER', 'redis-cluster'),";

    expect($this->redactor->redact($code))->toBe($code);
});

it('redacts secret values bound through properties, constants, named args and heredocs', function (string $code, string $secret): void {
    $result = $this->redactor->redact($code);

    expect($result)->not->toContain($secret)
        ->and($result)->toContain('__REDACTED_SECRET__');
})->with([
    'property' => ['private string $clientSecret = "abc123def456";', 'abc123def456'],
    'this property' => ['$this->apiKey = \'abc123def456\';', 'abc123def456'],
    'class constant' => ['const SIGNING_SECRET = \'abc123def456\';', 'abc123def456'],
    'named argument' => ['new Client(token: \'abc123def456\');', 'abc123def456'],
    'array dim target' => ['$config[\'password\'] = \'abc123def456\';', 'abc123def456'],
    'comparison' => ['if ($request->password === \'SuperAdmin2024!\') {}', 'SuperAdmin2024!'],
    'heredoc' => ["\$secret = <<<EOT\nabc123def456\nEOT;\n", 'abc123def456'],
]);

it('preserves the line count of every redaction', function (): void {
    $code = "<?php\n\$k = '-----BEGIN RSA PRIVATE KEY-----\nAAA\nBBB\nCCC\n-----END RSA PRIVATE KEY-----';\n\$secret = <<<EOT\nline1\nline2\nEOT;\n\$x = \$request->input('id'); // line 11\n";

    $result = $this->redactor->redact($code);

    expect(substr_count($result, "\n"))->toBe(substr_count($code, "\n"))
        ->and(explode("\n", $result)[10])->toBe("\$x = \$request->input('id'); // line 11");
});

it('redacts .env secrets of any length, with export, and skips placeholders', function (): void {
    $env = implode("\n", [
        'APP_NAME=Laravel',
        'DB_PASSWORD=hunter2',
        'export STRIPE_SECRET=abc',
        'MAIL_PASSWORD="correct horse battery"',
        'REDIS_PASSWORD=null',
        'AWS_SECRET_ACCESS_KEY=',
        'PUSHER_APP_KEY=${PUSHER_KEY}',
        'DB_HOST=127.0.0.1',
    ]);

    $result = $this->redactor->redact($env);

    expect($result)->toBe(implode("\n", [
        'APP_NAME=Laravel',
        'DB_PASSWORD=__REDACTED_SECRET__',
        'export STRIPE_SECRET=__REDACTED_SECRET__',
        'MAIL_PASSWORD=__REDACTED_SECRET__',
        'REDIS_PASSWORD=null',
        'AWS_SECRET_ACCESS_KEY=',
        'PUSHER_APP_KEY=${PUSHER_KEY}',
        'DB_HOST=127.0.0.1',
    ]))->and($this->redactor->lastRedactionCount())->toBe(3);
});
