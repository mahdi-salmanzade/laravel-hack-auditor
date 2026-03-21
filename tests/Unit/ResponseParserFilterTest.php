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
