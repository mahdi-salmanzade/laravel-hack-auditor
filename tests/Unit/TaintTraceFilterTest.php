<?php

declare(strict_types=1);

use Mahdi\HackAuditor\AI\ResponseParser;
use Mahdi\HackAuditor\Support\VulnerabilityType;

beforeEach(function (): void {
    $this->parser = new ResponseParser;
});

function taintTraceResponse(string $type, string $severity, string $taintTrace, string $description = 'Vulnerable code found.'): string
{
    return json_encode([
        'vulnerabilities' => [
            [
                'type' => $type,
                'location' => 'app/Http/Controllers/TestController.php',
                'line' => 42,
                'severity' => $severity,
                'description' => $description,
                'proof' => 'vulnerable code here',
                'fix' => 'fixed code here',
                'taint_trace' => $taintTrace,
            ],
        ],
        'overall_score' => 40,
        'summary' => 'Vulnerabilities found.',
        'ctf_idea' => '',
    ], JSON_THROW_ON_ERROR);
}

// --- Safe source auto-drops ---

it('drops SQL injection when source is config()', function (): void {
    $response = taintTraceResponse(
        'SqlInjection',
        'High',
        "SOURCE: config('database.allowed_columns') → TRANSFORMS: implode(',') → SINK: DB::raw('SELECT ' . \$cols)",
    );

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(0);
});

it('drops SQL injection when source is env()', function (): void {
    $response = taintTraceResponse(
        'SqlInjection',
        'High',
        "SOURCE: env('DB_TABLE_PREFIX') → TRANSFORMS: string concat → SINK: DB::raw(\$prefix . 'users')",
    );

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(0);
});

it('drops XSS when source is Auth::user()', function (): void {
    $response = taintTraceResponse(
        'Xss',
        'Medium',
        'SOURCE: auth()->user()->name → TRANSFORMS: none → SINK: {!! $name !!}',
    );

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(0);
});

it('drops SQL injection when source is hardcoded array', function (): void {
    $response = taintTraceResponse(
        'SqlInjection',
        'Medium',
        "SOURCE: hardcoded array ['created_at', 'updated_at'] → TRANSFORMS: implode() → SINK: DB::raw()",
    );

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(0);
});

// --- Chain-breaking transform auto-drops ---

it('drops SQL injection when (int) cast breaks the chain', function (): void {
    $response = taintTraceResponse(
        'SqlInjection',
        'High',
        "SOURCE: \$request->input('id') → TRANSFORMS: (int) cast → SINK: DB::raw('WHERE id = ' . \$id)",
    );

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(0);
});

it('drops SQL injection when intval() breaks the chain', function (): void {
    $response = taintTraceResponse(
        'SqlInjection',
        'High',
        "SOURCE: \$request->input('limit') → TRANSFORMS: intval() → SINK: DB::raw('LIMIT ' . \$limit)",
    );

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(0);
});

it('drops XSS when htmlspecialchars() breaks the chain', function (): void {
    $response = taintTraceResponse(
        'Xss',
        'High',
        "SOURCE: \$request->input('name') → TRANSFORMS: htmlspecialchars() → SINK: echo \$name",
    );

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(0);
});

it('drops XSS when blade {{ }} escaping breaks the chain', function (): void {
    $response = taintTraceResponse(
        'Xss',
        'Medium',
        "SOURCE: \$request->input('bio') → TRANSFORMS: blade {{ }} escaping → SINK: {{ \$bio }}",
    );

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(0);
});

it('drops any type when $request->validated() breaks the chain', function (): void {
    $response = taintTraceResponse(
        'SqlInjection',
        'High',
        "SOURCE: \$request->input('email') → TRANSFORMS: \$request->validated() → SINK: User::create(\$data)",
    );

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(0);
});

it('drops open redirect when domain validation breaks the chain', function (): void {
    $response = taintTraceResponse(
        'OpenRedirect',
        'High',
        "SOURCE: \$request->input('redirect') → TRANSFORMS: domain allowlist check → SINK: redirect(\$url)",
    );

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(0);
});

// --- Real vulnerabilities pass through ---

it('keeps SQL injection with user-controlled source and no safe transform', function (): void {
    $response = taintTraceResponse(
        'SqlInjection',
        'Critical',
        "SOURCE: \$request->input('search') → TRANSFORMS: trim() → SINK: DB::raw('WHERE name LIKE ' . \$search)",
    );

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(1)
        ->and($report->vulnerabilities[0]->type)->toBe(VulnerabilityType::SqlInjection)
        ->and($report->vulnerabilities[0]->taintTrace)->toContain('SOURCE:');
});

it('keeps XSS with user input and no escaping', function (): void {
    $response = taintTraceResponse(
        'Xss',
        'High',
        "SOURCE: \$request->input('comment') → TRANSFORMS: none → SINK: {!! \$comment !!}",
    );

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(1);
});

it('keeps open redirect with unvalidated user URL', function (): void {
    $response = taintTraceResponse(
        'OpenRedirect',
        'High',
        "SOURCE: \$request->query('next') → TRANSFORMS: urldecode() → SINK: redirect(\$next)",
    );

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(1);
});

// --- Findings without taint_trace pass through ---

it('passes through findings without taint_trace', function (): void {
    $response = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'SqlInjection',
                'location' => 'app/Http/Controllers/TestController.php',
                'line' => 42,
                'severity' => 'Critical',
                'description' => 'Raw SQL injection.',
                'proof' => 'DB::raw($input)',
                'fix' => 'Use parameterized queries',
            ],
        ],
        'overall_score' => 30,
        'summary' => 'Vulnerability found.',
        'ctf_idea' => '',
    ], JSON_THROW_ON_ERROR);

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(1)
        ->and($report->vulnerabilities[0]->taintTrace)->toBeNull();
});

// --- Non-input-dependent types bypass taint filter ---

it('keeps IDOR findings regardless of taint trace content', function (): void {
    $response = taintTraceResponse(
        'Idor',
        'Medium',
        "SOURCE: config('app.admin_id') → TRANSFORMS: none → SINK: User::find(\$id)",
    );

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(1);
});

it('keeps MassAssignment findings regardless of taint trace', function (): void {
    $response = taintTraceResponse(
        'MassAssignment',
        'High',
        "SOURCE: config('fields') → TRANSFORMS: none → SINK: Model::create()",
    );

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(1);
});

// --- taint_trace is preserved on the Vulnerability object ---

it('preserves taint_trace on parsed Vulnerability', function (): void {
    $trace = "SOURCE: \$request->input('q') → TRANSFORMS: trim() → SINK: DB::raw()";
    $response = taintTraceResponse('SqlInjection', 'Critical', $trace);

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(1)
        ->and($report->vulnerabilities[0]->taintTrace)->toBe($trace);
});

it('includes taint_trace in toArray() output', function (): void {
    $trace = "SOURCE: \$request->input('q') → TRANSFORMS: trim() → SINK: DB::raw()";
    $response = taintTraceResponse('SqlInjection', 'Critical', $trace);

    $report = $this->parser->parse($response);
    $array = $report->vulnerabilities[0]->toArray();

    expect($array)->toHaveKey('taint_trace')
        ->and($array['taint_trace'])->toBe($trace);
});

it('excludes taint_trace from toArray() when null', function (): void {
    $response = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'SqlInjection',
                'location' => 'test.php',
                'line' => 1,
                'severity' => 'High',
                'description' => 'desc',
                'proof' => 'code',
                'fix' => 'fix',
            ],
        ],
        'overall_score' => 50,
        'summary' => 'Found.',
    ], JSON_THROW_ON_ERROR);

    $report = $this->parser->parse($response);
    $array = $report->vulnerabilities[0]->toArray();

    expect($array)->not->toHaveKey('taint_trace');
});

// --- Edge cases ---

it('handles empty taint_trace string as null', function (): void {
    $response = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'SqlInjection',
                'location' => 'test.php',
                'line' => 1,
                'severity' => 'High',
                'description' => 'desc',
                'proof' => 'code',
                'fix' => 'fix',
                'taint_trace' => '',
            ],
        ],
        'overall_score' => 50,
        'summary' => 'Found.',
    ], JSON_THROW_ON_ERROR);

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(1)
        ->and($report->vulnerabilities[0]->taintTrace)->toBeNull();
});

it('handles non-string taint_trace gracefully', function (): void {
    $response = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'SqlInjection',
                'location' => 'test.php',
                'line' => 1,
                'severity' => 'High',
                'description' => 'desc',
                'proof' => 'code',
                'fix' => 'fix',
                'taint_trace' => 12345,
            ],
        ],
        'overall_score' => 50,
        'summary' => 'Found.',
    ], JSON_THROW_ON_ERROR);

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(1)
        ->and($report->vulnerabilities[0]->taintTrace)->toBeNull();
});

// --- Combined with self-contradiction filter ---

it('applies both self-contradiction and taint trace filters', function (): void {
    $response = json_encode([
        'vulnerabilities' => [
            // This one gets killed by self-contradiction filter
            [
                'type' => 'MassAssignment',
                'location' => 'test.php',
                'line' => 10,
                'severity' => 'Medium',
                'description' => 'This is not actually a vulnerability since fields are explicit.',
                'proof' => 'code',
                'fix' => 'fix',
            ],
            // This one gets killed by taint trace filter (safe source)
            [
                'type' => 'SqlInjection',
                'location' => 'test.php',
                'line' => 20,
                'severity' => 'High',
                'description' => 'Config values in raw SQL.',
                'proof' => 'DB::raw($cols)',
                'fix' => 'Use parameterized queries',
                'taint_trace' => "SOURCE: config('report.columns') → TRANSFORMS: implode(',') → SINK: DB::raw()",
            ],
            // This one survives both filters
            [
                'type' => 'SqlInjection',
                'location' => 'test.php',
                'line' => 30,
                'severity' => 'Critical',
                'description' => 'User input concatenated into raw SQL.',
                'proof' => 'DB::raw($search)',
                'fix' => 'Use parameterized queries',
                'taint_trace' => "SOURCE: \$request->input('q') → TRANSFORMS: trim() → SINK: DB::raw()",
            ],
        ],
        'overall_score' => 30,
        'summary' => 'Multiple issues.',
        'ctf_idea' => '',
    ], JSON_THROW_ON_ERROR);

    $report = $this->parser->parse($response);

    expect($report->vulnerabilities)->toHaveCount(1)
        ->and($report->vulnerabilities[0]->line)->toBe(30)
        ->and($report->vulnerabilities[0]->taintTrace)->toContain('$request->input');
});
