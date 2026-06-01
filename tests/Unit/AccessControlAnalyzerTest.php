<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlAnalyzer;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlDetector;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

function vulnerableModelFile(): array
{
    return [
        'path' => 'app/Models/Account.php',
        'type' => 'model',
        'content' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\n".
            "class Account extends Model\n{\n    protected \$fillable = ['name', 'is_admin'];\n}\n",
    ];
}

function vulnerableControllerFile(): array
{
    return [
        'path' => 'app/Http/Controllers/InvoiceController.php',
        'type' => 'controller',
        'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Invoice;\n".
            "class InvoiceController\n{\n    public function show(Request \$request)\n    {\n".
            "        \$invoice = Invoice::findOrFail(\$request->id);\n        return \$invoice;\n    }\n}\n",
    ];
}

it('aggregates findings across all detectors', function (): void {
    $analyzer = new AccessControlAnalyzer;

    $findings = $analyzer->analyze(
        [vulnerableModelFile(), vulnerableControllerFile()],
        new AccessControlContext,
    );

    $types = array_map(fn (Vulnerability $v): VulnerabilityType => $v->type, $findings);

    $massAssignment = collect($findings)->first(fn (Vulnerability $v) => $v->type === VulnerabilityType::MassAssignment);
    $idor = collect($findings)->first(fn (Vulnerability $v) => $v->type === VulnerabilityType::Idor);

    expect($types)->toContain(VulnerabilityType::MassAssignment)
        ->and($types)->toContain(VulnerabilityType::Idor)
        ->and($massAssignment->severity)->toBe(SeverityLevel::High)
        ->and($massAssignment->description)->toContain('is_admin')
        ->and($idor->severity)->toBe(SeverityLevel::High)
        ->and($idor->location)->toBe('app/Http/Controllers/InvoiceController.php');
});

it('dedupes identical findings within its own output', function (): void {
    $vuln = new Vulnerability(
        type: VulnerabilityType::Idor,
        location: 'app/Foo.php',
        line: 10,
        severity: SeverityLevel::High,
        description: 'x',
        proof: 'x',
        fix: 'x',
    );

    $stub = new class([$vuln, $vuln]) implements AccessControlDetector
    {
        public function __construct(private array $out) {}

        public function detect(array $files, AccessControlContext $context): array
        {
            return $this->out;
        }
    };

    $analyzer = new AccessControlAnalyzer([$stub]);

    expect($analyzer->analyze([], new AccessControlContext))->toHaveCount(1);
});

it('merge keeps AI findings and appends non-duplicate deterministic findings', function (): void {
    $analyzer = new AccessControlAnalyzer;

    $ai = new Vulnerability(
        type: VulnerabilityType::Xss,
        location: 'app/A.php',
        line: 5,
        severity: SeverityLevel::Medium,
        description: 'ai',
        proof: 'ai',
        fix: 'ai',
    );

    $deterministic = new Vulnerability(
        type: VulnerabilityType::Idor,
        location: 'app/B.php',
        line: 20,
        severity: SeverityLevel::High,
        description: 'det',
        proof: 'det',
        fix: 'det',
    );

    $merged = $analyzer->merge([$ai], [$deterministic]);

    expect($merged)->toHaveCount(2)
        ->and($merged[0])->toBe($ai)
        ->and($merged[1])->toBe($deterministic);
});

it('merge drops a deterministic finding that duplicates an AI finding at same file+line+type', function (): void {
    $analyzer = new AccessControlAnalyzer;

    $ai = new Vulnerability(
        type: VulnerabilityType::Idor,
        location: 'app/Http/Controllers/InvoiceController.php',
        line: 7,
        severity: SeverityLevel::High,
        description: 'ai version',
        proof: 'ai',
        fix: 'ai',
    );

    $deterministic = new Vulnerability(
        type: VulnerabilityType::Idor,
        location: 'app/Http/Controllers/InvoiceController.php',
        line: 8,
        severity: SeverityLevel::High,
        description: 'deterministic version',
        proof: 'det',
        fix: 'det',
    );

    $merged = $analyzer->merge([$ai], [$deterministic]);

    expect($merged)->toHaveCount(1)
        ->and($merged[0]->description)->toBe('ai version');
});

it('merge keeps a deterministic finding of a different type at the same location', function (): void {
    $analyzer = new AccessControlAnalyzer;

    $ai = new Vulnerability(
        type: VulnerabilityType::Xss,
        location: 'app/X.php',
        line: 10,
        severity: SeverityLevel::Medium,
        description: 'ai',
        proof: 'ai',
        fix: 'ai',
    );

    $deterministic = new Vulnerability(
        type: VulnerabilityType::Idor,
        location: 'app/X.php',
        line: 10,
        severity: SeverityLevel::High,
        description: 'det',
        proof: 'det',
        fix: 'det',
    );

    expect($analyzer->merge([$ai], [$deterministic]))->toHaveCount(2);
});

it('collapses same-type findings whose locations differ only in path format (basename-tolerant)', function (): void {
    $aiFinding = new Vulnerability(
        type: VulnerabilityType::SensitiveDataExposure,
        location: 'SensitiveDataController.php',
        line: 18,
        severity: SeverityLevel::High,
        description: 'ai',
        proof: 'ai',
        fix: 'ai',
    );

    $detFinding = new Vulnerability(
        type: VulnerabilityType::SensitiveDataExposure,
        location: '/abs/app/Http/Controllers/SensitiveDataController.php',
        line: 18,
        severity: SeverityLevel::High,
        description: 'det',
        proof: 'det',
        fix: 'det',
    );

    $merged = (new AccessControlAnalyzer)->merge([$aiFinding], [$detFinding]);

    expect($merged)->toHaveCount(1)
        ->and($merged[0]->description)->toBe('ai');
});

it('collapses two same-type findings at nearby lines from the same source list in merge', function (): void {
    $first = new Vulnerability(
        type: VulnerabilityType::Idor,
        location: 'app/Http/Controllers/InvoiceController.php',
        line: 12,
        severity: SeverityLevel::High,
        description: 'first',
        proof: 'first',
        fix: 'first',
    );

    $second = new Vulnerability(
        type: VulnerabilityType::Idor,
        location: 'app/Http/Controllers/InvoiceController.php',
        line: 14,
        severity: SeverityLevel::High,
        description: 'second',
        proof: 'second',
        fix: 'second',
    );

    $merged = (new AccessControlAnalyzer)->merge([$first, $second], []);

    expect($merged)->toHaveCount(1)
        ->and($merged[0]->description)->toBe('first');
});

it('collapses an Idor and an AuthBypass at the same location into one finding in dedupe (H3)', function (): void {
    $idor = new Vulnerability(
        type: VulnerabilityType::Idor,
        location: 'app/Http/Controllers/PostController.php',
        line: 12,
        severity: SeverityLevel::High,
        description: 'idor',
        proof: 'idor',
        fix: 'idor',
    );

    $authBypass = new Vulnerability(
        type: VulnerabilityType::AuthBypass,
        location: 'app/Http/Controllers/PostController.php',
        line: 12,
        severity: SeverityLevel::High,
        description: 'authbypass',
        proof: 'authbypass',
        fix: 'authbypass',
    );

    $stub = new class([$idor, $authBypass]) implements AccessControlDetector
    {
        public function __construct(private array $out) {}

        public function detect(array $files, AccessControlContext $context): array
        {
            return $this->out;
        }
    };

    $findings = (new AccessControlAnalyzer([$stub]))->analyze([], new AccessControlContext);

    expect($findings)->toHaveCount(1);
});

it('collapses an AuthBypass against an existing Idor of the same location in merge (H3)', function (): void {
    $analyzer = new AccessControlAnalyzer;

    $aiIdor = new Vulnerability(
        type: VulnerabilityType::Idor,
        location: 'app/Http/Controllers/PostController.php',
        line: 12,
        severity: SeverityLevel::High,
        description: 'ai idor',
        proof: 'ai',
        fix: 'ai',
    );

    $detAuthBypass = new Vulnerability(
        type: VulnerabilityType::AuthBypass,
        location: 'app/Http/Controllers/PostController.php',
        line: 13,
        severity: SeverityLevel::High,
        description: 'det authbypass',
        proof: 'det',
        fix: 'det',
    );

    $merged = $analyzer->merge([$aiIdor], [$detAuthBypass]);

    expect($merged)->toHaveCount(1)
        ->and($merged[0]->description)->toBe('ai idor');
});

it('does NOT collapse a non-access-control type at the same location as an Idor (H3 bound)', function (): void {
    $analyzer = new AccessControlAnalyzer;

    $aiIdor = new Vulnerability(
        type: VulnerabilityType::Idor,
        location: 'app/X.php',
        line: 12,
        severity: SeverityLevel::High,
        description: 'idor',
        proof: 'idor',
        fix: 'idor',
    );

    $detCsrf = new Vulnerability(
        type: VulnerabilityType::Csrf,
        location: 'app/X.php',
        line: 12,
        severity: SeverityLevel::High,
        description: 'csrf',
        proof: 'csrf',
        fix: 'csrf',
    );

    expect($analyzer->merge([$aiIdor], [$detCsrf]))->toHaveCount(2);
});
