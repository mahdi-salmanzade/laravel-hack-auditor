<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Mcp\Support\FindingFormatter;
use Mahdi\HackAuditor\Report\HtmlReportGenerator;
use Mahdi\HackAuditor\Scanner\ScanCoverage;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\Confidence;
use Mahdi\HackAuditor\Support\FindingClass;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * The two-class model: assertions vs questions.
 *
 * A review item is a QUESTION. It must never be counted as a vulnerability,
 * never move the score, never fail a build, and — the one that actually broke
 * production apps — never carry a fix. Every test below pins one of those.
 */
function makeFinding(
    FindingClass $class = FindingClass::Vulnerability,
    Confidence $confidence = Confidence::Probable,
    SeverityLevel $severity = SeverityLevel::Critical,
    string $fix = 'Use $request->validated().',
    string $location = 'app/Http/Controllers/ContractController.php',
): Vulnerability {
    return new Vulnerability(
        type: VulnerabilityType::Idor,
        location: $location,
        line: 42,
        severity: $severity,
        description: 'Is access to this contract enforced somewhere this scan cannot read?',
        proof: 'Contract::findOrFail($id)',
        fix: $fix,
        findingClass: $class,
        confidence: $confidence,
    );
}

function reportWith(array $findings, int $score = 60): VulnerabilityReport
{
    $report = new VulnerabilityReport(
        vulnerabilities: $findings,
        overallScore: $score,
        summary: 'Summary.',
        ctfIdea: '',
    );

    $report->setCoverage(ScanCoverage::complete(12));

    return $report;
}

/*
|--------------------------------------------------------------------------
| The finding model
|--------------------------------------------------------------------------
*/

it('defaults to an asserted vulnerability at probable confidence', function (): void {
    // Existing detectors pass neither axis. They must keep behaving exactly as
    // they did before classes existed.
    $finding = new Vulnerability(
        type: VulnerabilityType::SqlInjection,
        location: 'app/Http/Controllers/UserController.php',
        line: 10,
        severity: SeverityLevel::Critical,
        description: 'Raw SQL.',
        proof: 'DB::select("... $id")',
        fix: 'Bind the parameter.',
    );

    expect($finding->findingClass)->toBe(FindingClass::Vulnerability)
        ->and($finding->confidence)->toBe(Confidence::Probable)
        ->and($finding->isConfirmedVulnerability())->toBeTrue()
        ->and($finding->isReviewItem())->toBeFalse()
        ->and($finding->fix)->toBe('Bind the parameter.');
});

it('never lets a review finding carry a fix, however it was built', function (): void {
    // THE test. Applying "add $this->authorize('delete', $contract)" to a
    // controller whose $contract only exists inside a closure 403s every
    // delete. A question does not get to hand out executable advice.
    $constructed = makeFinding(class: FindingClass::Review, fix: "add \$this->authorize('delete', \$contract)");
    $withered = makeFinding(fix: "add \$this->authorize('delete', \$contract)")->withClass(FindingClass::Review);
    $viaConfidence = makeFinding(fix: 'Remove company_id from $fillable.')->withConfidence(Confidence::Possible);

    expect($constructed->fix)->toBe('')
        ->and($constructed->hasFix())->toBeFalse()
        ->and($withered->fix)->toBe('')
        ->and($withered->hasFix())->toBeFalse()
        ->and($viaConfidence->fix)->toBe('')
        ->and($viaConfidence->hasFix())->toBeFalse();
});

it('cannot recover a dropped fix by moving the finding back to vulnerability', function (): void {
    $resurrected = makeFinding(fix: 'Delete the model.')
        ->withClass(FindingClass::Review)
        ->withClass(FindingClass::Vulnerability);

    expect($resurrected->findingClass)->toBe(FindingClass::Vulnerability)
        ->and($resurrected->fix)->toBe('');
});

it('forces possible confidence down to the review class', function (): void {
    // "Possible" is not a quiet vulnerability. It is a question.
    $finding = makeFinding(class: FindingClass::Vulnerability, confidence: Confidence::Possible);

    expect($finding->findingClass)->toBe(FindingClass::Review)
        ->and($finding->isReviewItem())->toBeTrue();
});

it('keeps the withers immutable', function (): void {
    $original = makeFinding();
    $review = $original->withClass(FindingClass::Review);
    $possible = $original->withConfidence(Confidence::Possible);

    expect($original->findingClass)->toBe(FindingClass::Vulnerability)
        ->and($original->confidence)->toBe(Confidence::Probable)
        ->and($original->fix)->not->toBe('')
        ->and($review)->not->toBe($original)
        ->and($possible)->not->toBe($original);
});

it('only permits a fix on a proven assertion', function (): void {
    expect(makeFinding(confidence: Confidence::Proven)->mayCarryFix())->toBeTrue()
        ->and(makeFinding(confidence: Confidence::Probable)->mayCarryFix())->toBeFalse()
        ->and(makeFinding(class: FindingClass::Review, confidence: Confidence::Proven)->mayCarryFix())->toBeFalse();
});

it('serialises both axes without disturbing the existing keys', function (): void {
    $data = makeFinding(class: FindingClass::Review, confidence: Confidence::Possible)->toArray();

    expect($data['class'])->toBe('review')
        ->and($data['confidence'])->toBe('possible')
        ->and($data)->toHaveKeys(['type', 'type_label', 'location', 'line', 'severity', 'severity_label', 'owasp', 'cwe', 'description', 'proof', 'fix'])
        ->and($data['fix'])->toBe('');
});

it('resolves an unknown class or confidence to the weakest claim', function (): void {
    expect(FindingClass::fromString('totally-made-up'))->toBe(FindingClass::Review)
        ->and(Confidence::fromString('certain-ish'))->toBe(Confidence::Possible)
        ->and(FindingClass::fromString('VULNERABILITY'))->toBe(FindingClass::Vulnerability)
        ->and(Confidence::fromString(' Proven '))->toBe(Confidence::Proven);
});

/*
|--------------------------------------------------------------------------
| The report
|--------------------------------------------------------------------------
*/

it('counts the two classes separately', function (): void {
    $report = reportWith([
        makeFinding(severity: SeverityLevel::Critical),
        makeFinding(severity: SeverityLevel::High),
        makeFinding(class: FindingClass::Review, severity: SeverityLevel::Critical),
        makeFinding(class: FindingClass::Review, severity: SeverityLevel::High),
        makeFinding(class: FindingClass::Review, severity: SeverityLevel::Low),
    ]);

    expect($report->totalCount())->toBe(2)
        ->and($report->reviewCount())->toBe(3)
        ->and($report->allFindingsCount())->toBe(5)
        ->and($report->criticalCount())->toBe(1)
        ->and($report->highCount())->toBe(1)
        ->and($report->lowCount())->toBe(0)
        ->and($report->confirmedVulnerabilities())->toHaveCount(2)
        ->and($report->reviewItems())->toHaveCount(3);
});

it('never lets a review item reach the build gate', function (): void {
    // Severity says how bad it would be IF real. The analyzer has not
    // established that it is real, so it cannot fail anyone's pipeline.
    $reviewOnly = reportWith([
        makeFinding(class: FindingClass::Review, severity: SeverityLevel::Critical),
        makeFinding(class: FindingClass::Review, severity: SeverityLevel::Critical),
    ]);

    expect($reviewOnly->hasCritical())->toBeFalse()
        ->and($reviewOnly->criticalCount())->toBe(0);
});

it('reports the same score whether or not review items are present', function (): void {
    $withoutReview = reportWith([makeFinding()], score: 60);
    $withReview = reportWith([
        makeFinding(),
        makeFinding(class: FindingClass::Review, severity: SeverityLevel::Critical),
        makeFinding(class: FindingClass::Review, severity: SeverityLevel::Critical),
    ], score: 60);

    expect($withReview->overallScore)->toBe($withoutReview->overallScore)
        ->and($withReview->toArray()['overall_score'])->toBe(60)
        ->and($withReview->scoreIsMeaningful())->toBeTrue();
});

it('splits the two classes in the serialised report', function (): void {
    $data = reportWith([
        makeFinding(),
        makeFinding(class: FindingClass::Review, severity: SeverityLevel::High),
    ])->toArray();

    expect($data['vulnerabilities'])->toHaveCount(1)
        ->and($data['review_items'])->toHaveCount(1)
        ->and($data['vulnerabilities'][0]['class'])->toBe('vulnerability')
        ->and($data['review_items'][0]['class'])->toBe('review')
        ->and($data['counts']['total'])->toBe(1)
        ->and($data['counts']['review'])->toBe(1)
        ->and($data['counts']['high'])->toBe(0);
});

it('states what was analysed instead of implying the code is safe', function (): void {
    $report = reportWith([makeFinding(class: FindingClass::Review)]);

    expect($report->totalCount())->toBe(0)
        ->and($report->coverageStatement())->toContain('12')
        ->and($report->coverageStatement())->toContain('not that they are safe');
});

it('does not treat a review item as a new or resolved finding when comparing scans', function (): void {
    $previous = reportWith([makeFinding()]);
    $current = reportWith([
        makeFinding(),
        makeFinding(class: FindingClass::Review, location: 'app/Models/Account.php'),
    ]);

    $comparison = $current->compareWith($previous);

    expect($comparison['new_findings'])->toBeEmpty()
        ->and($comparison['resolved_findings'])->toBeEmpty()
        ->and($comparison['unchanged_findings'])->toHaveCount(1);
});

/*
|--------------------------------------------------------------------------
| Rendering
|--------------------------------------------------------------------------
*/

it('renders the two classes as separate sections in the HTML report', function (): void {
    $report = reportWith([
        makeFinding(),
        makeFinding(class: FindingClass::Review, severity: SeverityLevel::High),
    ]);

    $html = app(HtmlReportGenerator::class)->generate($report);

    expect($html)->toContain('Confirmed vulnerabilities (1)')
        ->and($html)->toContain('Needs review (1)')
        ->and($html)->toContain('No fix is suggested')
        ->and($html)->toContain('Not vulnerabilities.');
});

it('hands an MCP client the class and confidence of every finding', function (): void {
    // An agent that sees only severity will "fix" a question on a human's
    // behalf. The class is what stops it.
    $report = reportWith([
        makeFinding(confidence: Confidence::Proven),
        makeFinding(class: FindingClass::Review, severity: SeverityLevel::High),
    ]);

    $structured = FindingFormatter::report($report, 'app/')->getStructuredContent();

    expect($structured['findings'])->toHaveCount(1)
        ->and($structured['findings'][0]['class'])->toBe('vulnerability')
        ->and($structured['findings'][0]['confidence'])->toBe('proven')
        ->and($structured['review_items'])->toHaveCount(1)
        ->and($structured['review_items'][0]['class'])->toBe('review')
        ->and($structured['review_items'][0]['fix'])->toBe('')
        ->and($structured['counts']['total'])->toBe(1)
        ->and($structured['counts']['review'])->toBe(1)
        ->and($structured['counts']['high'])->toBe(0);
});

it('says a zero is coverage rather than a guarantee in the HTML report', function (): void {
    $report = reportWith([makeFinding(class: FindingClass::Review)]);

    $html = app(HtmlReportGenerator::class)->generate($report);

    expect($html)->toContain('Confirmed vulnerabilities (0)')
        ->and($html)->toContain('No vulnerabilities found.')
        ->and($html)->toContain('not that they are safe');
});
