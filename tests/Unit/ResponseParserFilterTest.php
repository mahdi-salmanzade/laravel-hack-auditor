<?php

declare(strict_types=1);

use Mahdi\HackAuditor\AI\ResponseParser;

it('filters out findings where description says it is not a vulnerability', function (): void {
    $parser = new ResponseParser;

    $json = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'MassAssignment',
                'location' => 'app/Http/Controllers/AuthController.php',
                'line' => 37,
                'severity' => 'Medium',
                'description' => 'The register method passes fields to create(). On closer inspection, this is not a mass assignment issue since fields are explicitly specified.',
                'proof' => 'User::create([...])',
                'fix' => 'Use $request->validated()',
            ],
            [
                'type' => 'Idor',
                'location' => 'app/Http/Controllers/RoomController.php',
                'line' => 56,
                'severity' => 'Medium',
                'description' => 'Room owner can add any user by ID without consent check.',
                'proof' => '$room->members()->create([...])',
                'fix' => 'Add consent verification',
            ],
        ],
        'overall_score' => 93,
        'summary' => 'Generally secure application.',
        'ctf_idea' => 'IDOR challenge',
    ]);

    $report = $parser->parse($json);

    expect($report->vulnerabilities)->toHaveCount(1)
        ->and($report->vulnerabilities[0]->type->value)->toBe('idor');
});

it('keeps findings that are genuine vulnerabilities', function (): void {
    $parser = new ResponseParser;

    $json = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'SqlInjection',
                'location' => 'app/Http/Controllers/UserController.php',
                'line' => 14,
                'severity' => 'Critical',
                'description' => 'Raw user input concatenated directly into SQL query.',
                'proof' => 'DB::select("SELECT * FROM users WHERE id = $id")',
                'fix' => 'Use parameterized queries',
            ],
        ],
        'overall_score' => 30,
        'summary' => 'Critical SQL injection found.',
        'ctf_idea' => 'SQL injection CTF',
    ]);

    $report = $parser->parse($json);

    expect($report->vulnerabilities)->toHaveCount(1);
});

it('filters findings that say code is already protected', function (): void {
    $parser = new ResponseParser;

    $json = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'SensitiveDataExposure',
                'location' => 'app/Models/User.php',
                'line' => 10,
                'severity' => 'Medium',
                'description' => 'User model returns sensitive fields. However, these are already protected by the $hidden property and already handled by Laravel serialization.',
                'proof' => 'return response()->json($user)',
                'fix' => 'Add to $hidden',
            ],
        ],
        'overall_score' => 95,
        'summary' => 'Well protected.',
        'ctf_idea' => '',
    ]);

    $report = $parser->parse($json);

    expect($report->vulnerabilities)->toHaveCount(0);
});

it('returns empty vulnerabilities when all findings are self-contradicting', function (): void {
    $parser = new ResponseParser;

    $json = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'MassAssignment',
                'location' => 'app/Http/Controllers/AuthController.php',
                'line' => 37,
                'severity' => 'Medium',
                'description' => 'This is not actually a vulnerability because fields are properly controlled.',
                'proof' => 'code',
                'fix' => 'fix',
            ],
        ],
        'overall_score' => 95,
        'summary' => 'Safe.',
        'ctf_idea' => '',
    ]);

    $report = $parser->parse($json);

    expect($report->vulnerabilities)->toHaveCount(0);
});

it('filters strong dismissals from production false positives', function (string $description): void {
    $parser = new ResponseParser;

    $json = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'Idor',
                'location' => 'app/Http/Controllers/TestController.php',
                'line' => 10,
                'severity' => 'Medium',
                'description' => $description,
                'proof' => 'code',
                'fix' => 'fix',
            ],
        ],
        'overall_score' => 90,
        'summary' => 'Test.',
        'ctf_idea' => '',
    ]);

    $report = $parser->parse($json);

    expect($report->vulnerabilities)->toHaveCount(0);
})->with([
    'no actual vulnerability on re-analysis' => 'No actual vulnerability here on re-analysis.',
    'by design for owner access' => 'this is by design for owner access',
    'actually safe with self-check' => 'this is actually safe. Removing this finding after self-check.',
    'intentional for owner' => "While WebhookTrigger has 'secret' in \$hidden, the code explicitly constructs the webhook_url using \$webhook->secret, effectively exposing the secret in the URL. This is intentional for the owner to see their webhook URL.",
    'actually safe via whereHas' => 'However, since the base query already has the membership constraint via whereHas, this is actually safe.',
    'on re-analysis by design' => 'On re-analysis, this is by design for owner access.',
]);

it('keeps findings where partial mitigation is acknowledged but code is still vulnerable', function (string $description): void {
    $parser = new ResponseParser;

    $json = json_encode([
        'vulnerabilities' => [
            [
                'type' => 'SqlInjection',
                'location' => 'app/Http/Controllers/ReportController.php',
                'line' => 42,
                'severity' => 'High',
                'description' => $description,
                'proof' => 'DB::select("SELECT ... " . $column)',
                'fix' => 'Use parameterized queries',
            ],
        ],
        'overall_score' => 40,
        'summary' => 'SQL injection risk found.',
        'ctf_idea' => '',
    ]);

    $report = $parser->parse($json);

    expect($report->vulnerabilities)->toHaveCount(1);
})->with([
    'cast mitigates but architecture is risky' => 'The values are cast to int in getDateInterval, which mitigates direct exploitation, but the architecture of building raw SQL via string concatenation is a SQL injection risk',
    'cast prevents but fragile defense' => 'although the (int) cast currently prevents injection, this is a fragile defense-in-depth failure',
]);
