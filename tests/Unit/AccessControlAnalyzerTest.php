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

it('keeps two same-type AI findings at nearby but different lines as separate claims', function (): void {
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

    expect($merged)->toHaveCount(2);
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

/**
 * Build a finding for the dedupe regression tests below.
 */
function dedupeFinding(string $location, int $line, VulnerabilityType $type = VulnerabilityType::SqlInjection, string $description = 'd'): Vulnerability
{
    return new Vulnerability(
        type: $type,
        location: $location,
        line: $line,
        severity: SeverityLevel::Critical,
        description: $description,
        proof: 'p',
        fix: 'f',
    );
}

it('never merges AI findings in different files that only share a basename', function (): void {
    $merged = (new AccessControlAnalyzer)->merge([
        dedupeFinding('app/Http/Controllers/Api/UserController.php', 40),
        dedupeFinding('app/Http/Controllers/Admin/UserController.php', 42),
    ], []);

    expect($merged)->toHaveCount(2);
});

it('never merges an AI finding with a deterministic finding in a same-basename different file', function (): void {
    $merged = (new AccessControlAnalyzer)->merge(
        [dedupeFinding('app/Http/Controllers/Api/UserController.php', 40)],
        [dedupeFinding('app/Http/Controllers/Admin/UserController.php', 42)],
    );

    expect($merged)->toHaveCount(2);
});

it('keeps two AI SQL injections four lines apart in the same file (r5 repro)', function (): void {
    $merged = (new AccessControlAnalyzer)->merge([
        dedupeFinding('app/Http/Controllers/ReportController.php', 10),
        dedupeFinding('app/Http/Controllers/ReportController.php', 14),
    ], []);

    expect($merged)->toHaveCount(2);
});

it('keeps an AI idor and an AI auth_bypass on different lines of the same file', function (): void {
    $merged = (new AccessControlAnalyzer)->merge([
        dedupeFinding('app/Http/Controllers/PostController.php', 20, VulnerabilityType::Idor),
        dedupeFinding('app/Http/Controllers/PostController.php', 24, VulnerabilityType::AuthBypass),
    ], []);

    expect($merged)->toHaveCount(2);
});

it('still collapses exact AI duplicates regardless of path format', function (): void {
    $merged = (new AccessControlAnalyzer)->merge([
        dedupeFinding('app/Http/Controllers/ReportController.php', 10, description: 'first'),
        dedupeFinding('./app\\Http\\Controllers\\ReportController.php', 10, description: 'second'),
    ], []);

    expect($merged)->toHaveCount(1)
        ->and($merged[0]->description)->toBe('first');
});

it('collapses a deterministic finding near an AI finding in the same file across base_path formats', function (): void {
    $merged = (new AccessControlAnalyzer)->merge(
        [dedupeFinding('app/Http/Controllers/InvoiceController.php', 14, VulnerabilityType::Idor, 'ai')],
        [dedupeFinding(base_path('app/Http/Controllers/InvoiceController.php'), 11, VulnerabilityType::Idor, 'det')],
    );

    expect($merged)->toHaveCount(1)
        ->and($merged[0]->description)->toBe('ai');
});

it('does not collapse a deterministic finding more than LINE_PROXIMITY lines from the AI finding', function (): void {
    $merged = (new AccessControlAnalyzer)->merge(
        [dedupeFinding('app/Http/Controllers/InvoiceController.php', 10, VulnerabilityType::Idor)],
        [dedupeFinding('app/Http/Controllers/InvoiceController.php', 30, VulnerabilityType::Idor)],
    );

    expect($merged)->toHaveCount(2);
});

it('reports one access-control finding per method when two detectors reach the same missing check', function (): void {
    // PolicyRouteMismatch flags the unapplied policy at the signature; the
    // write-side IDOR rule flags the unguarded update lines later. One bug,
    // one fix — it must not be counted twice.
    $bypass = new Vulnerability(
        type: VulnerabilityType::AuthBypass,
        location: 'app/Http/Controllers/PostController.php',
        line: 7,
        severity: SeverityLevel::High,
        description: 'Policy defined but never applied.',
        proof: 'update()',
        fix: '',
    );
    $idor = new Vulnerability(
        type: VulnerabilityType::Idor,
        location: 'app/Http/Controllers/PostController.php',
        line: 16,
        severity: SeverityLevel::High,
        description: 'Unguarded update by id.',
        proof: '$post->update()',
        fix: '',
    );
    $otherMethodIdor = new Vulnerability(
        type: VulnerabilityType::Idor,
        location: 'app/Http/Controllers/PostController.php',
        line: 21,
        severity: SeverityLevel::High,
        description: 'Unguarded fetch by id.',
        proof: 'Post::findOrFail($id)',
        fix: '',
    );

    $detector = new class([$bypass, $idor, $otherMethodIdor]) implements AccessControlDetector
    {
        public function __construct(private array $findings) {}

        public function detect(array $files, AccessControlContext $context): array
        {
            return $this->findings;
        }
    };

    $source = "<?php\n\nnamespace App\\Http\\Controllers;\n\nclass PostController\n{\n    public function update(\$id)\n    {\n"
        .str_repeat("        // ...\n", 7)
        ."        \$post->update(request()->all());\n    }\n\n    public function show(\$id)\n    {\n        return Post::findOrFail(\$id);\n    }\n}\n";

    $findings = (new AccessControlAnalyzer([$detector]))->analyze(
        [['path' => 'app/Http/Controllers/PostController.php', 'type' => 'controller', 'content' => $source]],
        new AccessControlContext,
    );

    expect(array_map(fn ($f): string => $f->type->value.'@'.$f->line, $findings))
        ->toBe(['auth_bypass@7', 'idor@21']);
});
