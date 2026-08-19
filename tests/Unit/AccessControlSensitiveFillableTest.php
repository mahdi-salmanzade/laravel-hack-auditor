<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\AccessControl\SensitiveFillableDetector;
use Mahdi\HackAuditor\Scanner\AccessControl\SourceFile;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * @param  array<int, array{path: string, content: string, type: string}>  $files
 */
function runFillableDetector(array $files): array
{
    $detector = new SensitiveFillableDetector;
    $sources = array_map(fn (array $f): SourceFile => SourceFile::fromArray($f), $files);

    return $detector->detect($sources, new AccessControlContext);
}

function fillableModel(string $body): array
{
    return [[
        'path' => 'app/Models/Account.php',
        'type' => 'model',
        'content' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Account extends Model\n{\n{$body}\n}\n",
    ]];
}

it('flags is_admin in fillable as mass assignment at high severity', function (): void {
    $findings = runFillableDetector(fillableModel("    protected \$fillable = ['name', 'email', 'is_admin'];"));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::MassAssignment)
        ->and($findings[0]->severity)->toBe(SeverityLevel::High)
        ->and($findings[0]->description)->toContain('is_admin')
        ->and($findings[0]->line)->toBeGreaterThan(1);
});

it('flags role and role_id privilege fields at high severity', function (): void {
    $findings = runFillableDetector(fillableModel("    protected \$fillable = ['role', 'role_id'];"));

    $fields = array_map(fn ($f) => $f->description, $findings);

    expect($findings)->toHaveCount(2)
        ->and($findings[0]->type)->toBe(VulnerabilityType::MassAssignment)
        ->and($findings[0]->severity)->toBe(SeverityLevel::High)
        ->and($findings[1]->severity)->toBe(SeverityLevel::High)
        ->and(implode(' ', $fields))->toContain('role')
        ->and(implode(' ', $fields))->toContain('role_id');
});

it('flags is_* convention boolean flags at high severity', function (): void {
    $findings = runFillableDetector(fillableModel("    protected \$fillable = ['is_premium'];"));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(SeverityLevel::High)
        ->and($findings[0]->description)->toContain('is_premium');
});

it('flags *_admin convention fields at high severity', function (): void {
    $findings = runFillableDetector(fillableModel("    protected \$fillable = ['site_admin'];"));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(SeverityLevel::High)
        ->and($findings[0]->description)->toContain('site_admin');
});

it('flags balance and credits money fields at high severity', function (): void {
    $findings = runFillableDetector(fillableModel("    protected \$fillable = ['balance', 'credits'];"));

    expect($findings)->toHaveCount(2)
        ->and($findings[0]->severity)->toBe(SeverityLevel::High)
        ->and($findings[1]->severity)->toBe(SeverityLevel::High);
});

it('flags ownership user_id when mass assignable at high severity', function (): void {
    $findings = runFillableDetector(fillableModel("    protected \$fillable = ['title', 'user_id'];"));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::MassAssignment)
        ->and($findings[0]->severity)->toBe(SeverityLevel::High)
        ->and($findings[0]->description)->toContain('user_id');
});

it('flags subscription fields at medium severity', function (): void {
    $findings = runFillableDetector(fillableModel("    protected \$fillable = ['subscription_plan'];"));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(SeverityLevel::Medium)
        ->and($findings[0]->description)->toContain('subscription_plan');
});

it('does NOT flag benign fillable fields', function (): void {
    $findings = runFillableDetector(fillableModel("    protected \$fillable = ['name', 'email', 'bio', 'avatar', 'phone'];"));

    expect($findings)->toBeEmpty();
});

it('does NOT flag ambiguous status/type/level/tier columns without a privilege signal (H1)', function (): void {
    $findings = runFillableDetector(fillableModel(
        "    protected \$fillable = ['title', 'body', 'status', 'type', 'level', 'tier', 'plan', 'active'];"
    ));

    expect($findings)->toBeEmpty();
});

it('flags an ambiguous status column at MEDIUM when a sibling privilege field corroborates (H1)', function (): void {
    $findings = runFillableDetector(fillableModel(
        "    protected \$fillable = ['title', 'status', 'is_admin'];"
    ));

    $statusFinding = collect($findings)->first(fn ($f) => str_contains($f->description, "'status'"));

    expect($findings)->toHaveCount(2)
        ->and($statusFinding)->not->toBeNull()
        ->and($statusFinding->type)->toBe(VulnerabilityType::MassAssignment)
        ->and($statusFinding->severity)->toBe(SeverityLevel::Medium);
});

it('flags an ambiguous status column at MEDIUM when a sibling role field corroborates (H1)', function (): void {
    $findings = runFillableDetector(fillableModel(
        "    protected \$fillable = ['title', 'status', 'role'];"
    ));

    $statusFinding = collect($findings)->first(fn ($f) => str_contains($f->description, "'status'"));

    expect($statusFinding)->not->toBeNull()
        ->and($statusFinding->severity)->toBe(SeverityLevel::Medium);
});

it('flags an ambiguous active column at MEDIUM when a privilege boolean cast corroborates (H1)', function (): void {
    $body = "    protected \$fillable = ['title', 'active'];\n".
        "    protected \$casts = ['active' => 'boolean'];";

    $findings = runFillableDetector(fillableModel($body));

    $activeFinding = collect($findings)->first(fn ($f) => str_contains($f->description, "'active'"));

    expect($activeFinding)->not->toBeNull()
        ->and($activeFinding->severity)->toBe(SeverityLevel::Medium);
});

it('does NOT flag a model fully guarded with $guarded = ['."'*'".'] (H2)', function (): void {
    $body = "    protected \$fillable = ['name', 'is_admin', 'role'];\n".
        "    protected \$guarded = ['*'];";

    $findings = runFillableDetector(fillableModel($body));

    expect($findings)->toBeEmpty();
});

it('still flags is_admin at HIGH alongside ambiguous fields (regression)', function (): void {
    $findings = runFillableDetector(fillableModel(
        "    protected \$fillable = ['status', 'type', 'is_admin'];"
    ));

    $adminFinding = collect($findings)->first(fn ($f) => str_contains($f->description, "'is_admin'"));

    expect($adminFinding)->not->toBeNull()
        ->and($adminFinding->severity)->toBe(SeverityLevel::High);

    foreach ($findings as $finding) {
        if (! str_contains($finding->description, "'is_admin'")) {
            expect($finding->severity)->toBe(SeverityLevel::Medium);
        }
    }
});

it('does NOT flag when sensitive field is also in guarded', function (): void {
    $body = "    protected \$fillable = ['name', 'is_admin'];\n    protected \$guarded = ['is_admin'];";

    $findings = runFillableDetector(fillableModel($body));

    expect($findings)->toBeEmpty();
});

it('does NOT flag ownership field when a guarding mutator exists', function (): void {
    $body = "    protected \$fillable = ['user_id'];\n".
        "    public function setUserIdAttribute(\$value) { abort_unless(auth()->id(), 403); \$this->attributes['user_id'] = \$value; }";

    $findings = runFillableDetector(fillableModel($body));

    expect($findings)->toBeEmpty();
});

it('does NOT flag non-model files', function (): void {
    $files = [[
        'path' => 'app/Http/Controllers/AccountController.php',
        'type' => 'controller',
        'content' => "<?php\nclass AccountController { protected \$fillable = ['is_admin']; }",
    ]];

    $findings = runFillableDetector($files);

    expect($findings)->toBeEmpty();
});

it('does NOT flag a model without a fillable array', function (): void {
    $findings = runFillableDetector(fillableModel('    protected $guarded = [];'));

    expect($findings)->toBeEmpty();
});

it('still detects privilege fields when a comment inside $fillable contains an apostrophe', function (): void {
    // A regex over the raw array body pairs quotes across comments, so one
    // apostrophe here used to swallow every field after it and silently
    // disable the detector. Parsing is tokenised now.
    $findings = runFillableDetector(fillableModel(<<<'BODY'
    protected $fillable = [
        // lets a request reassign someone else's account
        'user_id',
        // privilege flag
        'is_admin',
    ];
BODY));

    expect($findings)->not->toBeEmpty()
        ->and($findings[0]->type)->toBe(VulnerabilityType::MassAssignment);
});

it('ignores fields that only appear inside comments', function (): void {
    $findings = runFillableDetector(fillableModel(<<<'BODY'
    protected $fillable = [
        // 'is_admin' is deliberately NOT mass assignable
        'name',
    ];
BODY));

    expect($findings)->toBeEmpty();
});

it('reads $fillable written with hash and block comments', function (): void {
    foreach ([
        "    protected \$fillable = [\n        # don't do this\n        'is_admin',\n    ];",
        "    protected \$fillable = [\n        /* it's risky */\n        'is_admin',\n    ];",
    ] as $body) {
        expect(runFillableDetector(fillableModel($body)))->not->toBeEmpty();
    }
});
