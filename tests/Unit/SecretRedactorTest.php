<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Support\SecretRedactor;

beforeEach(function (): void {
    $this->redactor = new SecretRedactor;
});

it('redacts AWS access key IDs', function (): void {
    $code = "\$key = 'AKIAIOSFODNN7EXAMPLE';";

    $result = $this->redactor->redact($code);

    expect($result)->toContain('__REDACTED_AWS_KEY__')
        ->and($result)->not->toContain('AKIAIOSFODNN7EXAMPLE')
        ->and($this->redactor->lastRedactionCount())->toBeGreaterThan(0);
});

it('redacts bearer tokens in authorization headers', function (): void {
    $code = "'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abc',";

    $result = $this->redactor->redact($code);

    expect($result)->toContain('__REDACTED_TOKEN__')
        ->and($result)->not->toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abc');
});

it('redacts database connection strings with credentials', function (): void {
    $code = "\$dsn = 'mysql://admin:s3cr3tP4ss@db.internal:3306/app';";

    $result = $this->redactor->redact($code);

    expect($result)->toContain('__REDACTED_DSN__')
        ->and($result)->not->toContain('s3cr3tP4ss');
});

it('redacts redis connection strings with credentials', function (): void {
    $code = "\$redis = 'redis://:supersecretpassword@127.0.0.1:6379';";

    $result = $this->redactor->redact($code);

    expect($result)->toContain('__REDACTED_DSN__')
        ->and($result)->not->toContain('supersecretpassword');
});

it('redacts PEM private key blocks', function (): void {
    $code = <<<'PHP'
    $pem = '-----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz
    QIDAQABAoIBAQC9876543210zyxwvutsrqponmlkjihgfedcba
    -----END RSA PRIVATE KEY-----';
    PHP;

    $result = $this->redactor->redact($code);

    expect($result)->toContain('__REDACTED_PRIVATE_KEY__')
        ->and($result)->not->toContain('MIIEpAIBAAKCAQEA')
        ->and($result)->not->toContain('BEGIN RSA PRIVATE KEY');
});

it('redacts api_key string literals', function (): void {
    $code = "\$config = ['api_key' => 'examplekeyvalue1234567890ab'];";

    $result = $this->redactor->redact($code);

    expect($result)->toContain('__REDACTED_SECRET__')
        ->and($result)->not->toContain('examplekeyvalue1234567890ab');
});

it('redacts secret assignments with arrow and equals syntax', function (): void {
    $arrow = "'client_secret' => 'abcdef1234567890ghijkl'";
    $equals = "\$password = 'hunter2hunter2hunter2';";

    expect($this->redactor->redact($arrow))->toContain('__REDACTED_SECRET__');
    expect($this->redactor->redact($equals))->toContain('__REDACTED_SECRET__')
        ->and($this->redactor->redact($equals))->not->toContain('hunter2hunter2hunter2');
});

it('redacts a secret value that contains an embedded apostrophe', function (): void {
    $code = "\$apiKey = \"abc'def12345\";";

    $result = $this->redactor->redact($code);

    expect($result)->toContain('__REDACTED_SECRET__')
        ->and($result)->not->toContain("abc'def12345")
        ->and($result)->not->toContain('def12345')
        ->and($this->redactor->lastRedactionCount())->toBeGreaterThan(0);
});

it('redacts a secret value that contains an embedded double quote', function (): void {
    $code = "\$client_secret = 'abc\"def12345';";

    $result = $this->redactor->redact($code);

    expect($result)->toContain('__REDACTED_SECRET__')
        ->and($result)->not->toContain('abc"def12345')
        ->and($result)->not->toContain('def12345');
});

it('redacts both halves of a concatenated secret, not just the first literal', function (): void {
    $code = '$token = "examplekey" . "value1234567890ab";';

    $result = $this->redactor->redact($code);

    expect($result)->toContain('__REDACTED_SECRET__')
        ->and($result)->not->toContain('value1234567890ab')
        ->and($result)->not->toContain('examplekey');
});

it('redacts a short high-signal password literal below the generic floor', function (): void {
    $code = '$password = "hunter2";';

    $result = $this->redactor->redact($code);

    expect($result)->toContain('__REDACTED_SECRET__')
        ->and($result)->not->toContain('hunter2');
});

it('redacts an AWS access key split across a concatenation chain', function (): void {
    $code = '$key = "AKIA" . "IOSFODNN7EXAMPLE";';

    $result = $this->redactor->redact($code);

    expect($result)->toContain('__REDACTED_AWS_KEY__')
        ->and($result)->not->toContain('AKIAIOSFODNN7EXAMPLE')
        ->and($result)->not->toContain('IOSFODNN7EXAMPLE');
});

it('redacts a concatenated secret whose body is in a third literal', function (): void {
    $code = "\$api_key = 'prefix_' . 'middle_' . 'realbodyXYZ123';";

    $result = $this->redactor->redact($code);

    expect($result)->toContain('__REDACTED_SECRET__')
        ->and($result)->not->toContain('realbodyXYZ123')
        ->and($result)->not->toContain('middle_');
});

it('does not redact a method call that merely contains a secret keyword', function (): void {
    $code = '$url = $this->passwordResetUrl();';

    $result = $this->redactor->redact($code);

    expect($result)->toBe($code)
        ->and($this->redactor->lastRedactionCount())->toBe(0);
});

it('does not redact a secret-named variable assigned from a method call', function (): void {
    $code = '$secret = $this->secrets();';

    $result = $this->redactor->redact($code);

    expect($result)->toBe($code)
        ->and($this->redactor->lastRedactionCount())->toBe(0);
});

it('does not redact a tokenizer object instantiation', function (): void {
    $code = '$tokenizer = new Tokenizer();';

    $result = $this->redactor->redact($code);

    expect($result)->toBe($code)
        ->and($this->redactor->lastRedactionCount())->toBe(0);
});

it('redacts env-style secret assignments', function (): void {
    $code = "APP_KEY=base64:aVeryLongSecretValueThatShouldBeHidden123\nDB_HOST=127.0.0.1";

    $result = $this->redactor->redact($code);

    expect($result)->toContain('__REDACTED_SECRET__')
        ->and($result)->not->toContain('aVeryLongSecretValueThatShouldBeHidden123')
        ->and($result)->toContain('DB_HOST=127.0.0.1');
});

it('leaves ordinary code and variable names untouched', function (): void {
    $code = <<<'PHP'
    public function tokenize(string $input): array
    {
        $secret = $this->secrets();
        return ['name' => 'John', 'status' => 'active'];
    }
    PHP;

    $result = $this->redactor->redact($code);

    expect($result)->toBe($code)
        ->and($this->redactor->lastRedactionCount())->toBe(0);
});

it('does not redact short non-secret string literals', function (): void {
    $code = "['password' => 'abc'];";

    $result = $this->redactor->redact($code);

    expect($result)->toBe($code)
        ->and($this->redactor->lastRedactionCount())->toBe(0);
});

it('does not redact identifiers that merely contain secret-like substrings in code', function (): void {
    $code = '$tokenizer = new Tokenizer(); $this->passwordResetUrl();';

    $result = $this->redactor->redact($code);

    expect($result)->toBe($code);
});

it('preserves the detection marker so a downstream scan can still flag the secret', function (): void {
    $code = "\$apiKey = 'AKIAIOSFODNN7EXAMPLE';";

    $result = $this->redactor->redact($code);

    expect($result)->toContain('__REDACTED');
});

it('reports the redaction count across multiple secrets', function (): void {
    $code = <<<'PHP'
    $a = 'AKIAIOSFODNN7EXAMPLE';
    $b = 'AKIA1234567890ABCDEF';
    PHP;

    $this->redactor->redact($code);

    expect($this->redactor->lastRedactionCount())->toBe(2);
});
