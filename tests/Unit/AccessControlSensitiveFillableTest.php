<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\AccessControl\SensitiveFillableDetector;
use Mahdi\HackAuditor\Scanner\AccessControl\SourceFile;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\Confidence;
use Mahdi\HackAuditor\Support\FindingClass;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * SensitiveFillableDetector contract.
 *
 * The rule this suite pins down: a `$fillable` entry is EVIDENCE OF NOTHING on
 * its own. Measured over six real applications the "column is fillable,
 * therefore vulnerable" rule produced 87 findings and 87 false positives,
 * because none of those applications ever passed wholesale request data into
 * the flagged models.
 *
 * So a finding is only a VULNERABILITY when the whole chain is resolved —
 * request array -> mass-assignment call on this model -> the column survives
 * whatever restriction the payload carries. An unambiguous privilege column
 * with no such chain becomes a REVIEW question with no fix; an ownership column
 * with no such chain becomes nothing at all.
 */

/**
 * @param  array<int, array{path: string, content: string, type: string}>  $files
 * @return array<int, Vulnerability>
 */
function runFillableDetector(array $files): array
{
    $detector = new SensitiveFillableDetector;
    $sources = array_map(fn (array $f): SourceFile => SourceFile::fromArray($f), $files);

    return $detector->detect($sources, new AccessControlContext);
}

/**
 * One model file and nothing else — no mass-assignment sink anywhere.
 *
 * @return array<int, array{path: string, content: string, type: string}>
 */
function fillableModel(string $body, string $class = 'Account'): array
{
    return [[
        'path' => 'app/Models/'.$class.'.php',
        'type' => 'model',
        'content' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass {$class} extends Model\n{\n{$body}\n}\n",
    ]];
}

/**
 * A controller whose action body is the given statements: the sink half of the
 * evidence chain.
 *
 * @return array{path: string, content: string, type: string}
 */
function fillableSinkController(string $statements, string $model = 'Account'): array
{
    return [
        'path' => 'app/Http/Controllers/AccountController.php',
        'type' => 'controller',
        'content' => <<<PHP
        <?php

        declare(strict_types=1);

        namespace App\Http\Controllers;

        use App\Models\\{$model};
        use Illuminate\Http\Request;

        class AccountController
        {
            public function update(Request \$request, int \$id)
            {
        {$statements}
            }
        }

        PHP,
    ];
}

/**
 * Model plus a sink, i.e. a complete chain.
 *
 * @return array<int, array{path: string, content: string, type: string}>
 */
function fillableWithSink(string $body, string $statements, string $class = 'Account'): array
{
    return [...fillableModel($body, $class), fillableSinkController($statements, $class)];
}

/**
 * The 1-based line of the first line containing the needle.
 */
function fillableLineContaining(string $content, string $needle): int
{
    foreach (explode("\n", $content) as $index => $line) {
        if (str_contains($line, $needle)) {
            return $index + 1;
        }
    }

    throw new RuntimeException('needle not present in fixture: '.$needle);
}

/*
|--------------------------------------------------------------------------
| A proven chain: source -> sink -> reach
|--------------------------------------------------------------------------
*/

it('flags a privilege column when request data provably reaches a mass-assignment call', function (): void {
    $files = fillableWithSink(
        "    protected \$fillable = ['name', 'is_admin'];",
        '        Account::create($request->all());',
    );

    $findings = runFillableDetector($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::MassAssignment)
        ->and($findings[0]->severity)->toBe(SeverityLevel::High)
        ->and($findings[0]->description)->toContain("'is_admin'")
        ->and($findings[0]->description)->toContain('Account::create()')
        ->and($findings[0]->description)->toContain('$request->all()');
});

it('cites BOTH lines: the $fillable entry and the sink', function (): void {
    $files = fillableWithSink(
        "    protected \$fillable = [\n        'name',\n        'is_admin',\n    ];",
        '        Account::create($request->all());',
    );

    $fieldLine = fillableLineContaining($files[0]['content'], "'is_admin',");
    $sinkLine = fillableLineContaining($files[1]['content'], 'Account::create($request->all())');

    $findings = runFillableDetector($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->location)->toBe('app/Models/Account.php')
        ->and($findings[0]->line)->toBe($fieldLine)
        ->and($findings[0]->description)->toContain('app/Models/Account.php:'.$fieldLine)
        ->and($findings[0]->description)->toContain('app/Http/Controllers/AccountController.php:'.$sinkLine)
        ->and($findings[0]->proof)->toContain('SOURCE')
        ->and($findings[0]->proof)->toContain('SINK');
});

it('follows a local variable that a reaching assignment proves holds request data', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['name', 'is_admin'];",
        "        \$data = \$request->all();\n\n        Account::create(\$data);",
    ));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->description)->toContain("'is_admin'");
});

it('accepts an instance fill() whose receiver resolves to the model', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['name', 'is_admin'];",
        "        \$account = Account::findOrFail(\$id);\n\n        \$account->fill(\$request->all());",
    ));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->description)->toContain('$account->fill()');
});

it('accepts an array literal whose value is client controlled', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['title', 'user_id'];",
        "        Account::create(['user_id' => \$request->input('user_id')]);",
    ));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->description)->toContain("'user_id'");
});

it('treats an unrestricted validated() on a plain Request as the whole payload', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['name', 'is_admin'];",
        '        Account::create($request->validated());',
    ));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->description)->toContain('$request->validated()');
});

/*
|--------------------------------------------------------------------------
| No sink: review, or silence
|--------------------------------------------------------------------------
*/

it('asks a QUESTION instead of asserting a vulnerability when no sink is proven', function (): void {
    $findings = runFillableDetector(fillableModel("    protected \$fillable = ['name', 'is_admin'];"));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::MassAssignment)
        ->and($findings[0]->description)->toStartWith("Should 'is_admin' be mass-assignable on Account?")
        ->and($findings[0]->description)->toContain('question for review')
        ->and($findings[0]->proof)->toContain('No mass-assignment sink');
});

it('emits NO fix for a review finding', function (): void {
    $findings = runFillableDetector(fillableModel("    protected \$fillable = ['name', 'is_admin'];"));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->findingClass)->toBe(FindingClass::Review)
        ->and($findings[0]->confidence)->toBe(Confidence::Possible)
        ->and($findings[0]->hasFix())->toBeFalse()
        ->and($findings[0]->fix)->toBe('');
});

it('raises a review question only for the UNAMBIGUOUS privilege columns', function (): void {
    foreach (['role', 'role_id', 'permissions', 'balance', 'credits'] as $field) {
        $findings = runFillableDetector(fillableModel("    protected \$fillable = ['name', '{$field}'];"));

        expect($findings)->toHaveCount(1)
            ->and($findings[0]->description)->toStartWith("Should '{$field}' be");
    }
});

it('says NOTHING about an ownership column with no proven sink (akaunting regression)', function (): void {
    // akaunting lists company_id in $fillable on 25 models and never mass
    // assigns it. The old rule reported all 25, and its advice — "remove
    // company_id from $fillable" — would have disabled the tenant scope, whose
    // isTenantable() check reads exactly that array.
    foreach (['user_id', 'company_id', 'account_id', 'tenant_id', 'team_id', 'owner_id'] as $field) {
        $findings = runFillableDetector(fillableModel("    protected \$fillable = ['name', '{$field}'];"));

        expect($findings)->toBe([]);
    }
});

it('says nothing about account-state columns with no proven sink', function (): void {
    $findings = runFillableDetector([[
        'path' => 'app/Models/User.php',
        'type' => 'model',
        'content' => "<?php\n\nnamespace App\\Models;\n\nuse Illuminate\\Foundation\\Auth\\User as Authenticatable;\n\nclass User extends Authenticatable\n{\n    protected \$fillable = ['name', 'email', 'password', 'is_verified'];\n}\n",
    ]]);

    expect($findings)->toBe([]);
});

/*
|--------------------------------------------------------------------------
| Reach: the restriction the payload carries is proof of safety
|--------------------------------------------------------------------------
*/

it('does NOT flag a column the payload cannot carry (only)', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['title', 'user_id'];",
        "        Account::create(\$request->only(['title']));",
    ));

    expect($findings)->toBe([]);
});

it('does NOT flag a column the payload excludes (except)', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['title', 'user_id'];",
        "        Account::create(\$request->except(['user_id']));",
    ));

    expect($findings)->toBe([]);
});

it('does NOT flag a column validate() never lets through', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['title', 'user_id'];",
        "        Account::create(\$request->validate(['title' => 'required|string']));",
    ));

    expect($findings)->toBe([]);
});

it('reads a FormRequest rules() array as the restriction on validated()', function (): void {
    $files = [
        ...fillableModel("    protected \$fillable = ['title', 'user_id'];"),
        [
            'path' => 'app/Http/Requests/StoreAccountRequest.php',
            'type' => 'request',
            'content' => <<<'PHP'
            <?php

            declare(strict_types=1);

            namespace App\Http\Requests;

            use Illuminate\Foundation\Http\FormRequest;

            class StoreAccountRequest extends FormRequest
            {
                public function rules(): array
                {
                    return ['title' => 'required|string'];
                }
            }

            PHP,
        ],
        [
            'path' => 'app/Http/Controllers/AccountController.php',
            'type' => 'controller',
            'content' => <<<'PHP'
            <?php

            declare(strict_types=1);

            namespace App\Http\Controllers;

            use App\Http\Requests\StoreAccountRequest;
            use App\Models\Account;

            class AccountController
            {
                public function store(StoreAccountRequest $request)
                {
                    Account::create($request->validated());
                }
            }

            PHP,
        ],
    ];

    expect(runFillableDetector($files))->toBe([]);
});

it('does NOT flag a column a server value overwrites through array_merge', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['title', 'user_id'];",
        "        Account::create(array_merge(\$request->all(), ['user_id' => auth()->id()]));",
    ));

    expect($findings)->toBe([]);
});

it('does NOT flag a column written from a server value in an array literal', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['title', 'user_id'];",
        "        Account::create(['title' => \$request->input('title'), 'user_id' => auth()->id()]);",
    ));

    expect($findings)->toBe([]);
});

it('does NOT flag a column overwritten on the array between assignment and sink', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['title', 'user_id'];",
        "        \$data = \$request->all();\n        \$data['user_id'] = auth()->id();\n\n        Account::create(\$data);",
    ));

    expect($findings)->toBe([]);
});

it('does NOT flag a column the model instance is given a server value for afterwards (snipe-it regression)', function (): void {
    // snipe-it writes `$accessory->fill($request->all());` and then
    // `$accessory->company_id = Company::getIdForCurrentUser(...);` on the very
    // next line. Eloquent applies the later assignment, so company_id is
    // server-controlled whatever the request body said.
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['name', 'company_id'];",
        "        \$account = new Account;\n        \$account->fill(\$request->all());\n        \$account->company_id = Company::getIdForCurrentUser(\$request->input('company_id'));\n        \$account->save();",
    ));

    expect($findings)->toBe([]);
});

/*
|--------------------------------------------------------------------------
| Sink resolution: never attribute a write to a model we cannot name
|--------------------------------------------------------------------------
*/

it('does NOT attribute a relation write to the model the relation hangs off', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['name', 'is_admin'];",
        '        $request->user()->accounts()->create($request->all());',
    ));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->description)->toStartWith("Should 'is_admin' be");
});

it('does NOT treat a sink on a DIFFERENT model as a sink on this one', function (): void {
    $files = [
        ...fillableModel("    protected \$fillable = ['name', 'is_admin'];", 'Account'),
        ...fillableModel("    protected \$fillable = ['name'];", 'Profile'),
        fillableSinkController('        Profile::create($request->all());', 'Profile'),
    ];

    $findings = runFillableDetector($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->description)->toStartWith("Should 'is_admin' be");
});

it('does NOT treat insert() as a mass-assignment sink', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['title', 'user_id'];",
        '        Account::insert($request->all());',
    ));

    expect($findings)->toBe([]);
});

/*
|--------------------------------------------------------------------------
| Fix safety
|--------------------------------------------------------------------------
*/

it('targets the SINK, and refuses to advise removing an ownership column', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['title', 'company_id'];",
        '        Account::create($request->all());',
    ));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain('app/Http/Controllers/AccountController.php')
        ->and($findings[0]->fix)->toContain('$request->all()')
        ->and($findings[0]->fix)->toContain('Do NOT simply drop')
        ->and($findings[0]->fix)->not->toContain('Removing ');
});

it('offers column removal only for an unambiguous privilege column', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['name', 'is_admin'];",
        '        Account::create($request->all());',
    ));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain("Removing 'is_admin' from Account::\$fillable");
});

it('never synthesises a call, a variable or a $guarded instruction in its advice', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['name', 'is_admin'];",
        '        Account::create($request->all());',
    ));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->not->toContain('authorize(')
        ->and($findings[0]->fix)->not->toContain('$model->')
        ->and($findings[0]->fix)->not->toContain('$guarded');
});

/*
|--------------------------------------------------------------------------
| Column taxonomy (unchanged behaviour, now gated on a sink)
|--------------------------------------------------------------------------
*/

it('does NOT flag benign fillable fields even with a sink present', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['name', 'email', 'bio', 'avatar', 'phone'];",
        '        Account::create($request->all());',
    ));

    expect($findings)->toBe([]);
});

it('does NOT flag ambiguous status/type/level/tier columns without a privilege signal', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['title', 'body', 'status', 'type', 'level', 'tier', 'plan', 'active'];",
        '        Account::create($request->all());',
    ));

    expect($findings)->toBe([]);
});

it('flags an ambiguous status column at MEDIUM when a sibling privilege field corroborates', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['title', 'status', 'is_admin'];",
        '        Account::create($request->all());',
    ));

    $status = collect($findings)->first(fn (Vulnerability $v): bool => str_contains($v->description, "'status'"));

    expect($findings)->toHaveCount(2)
        ->and($status)->not->toBeNull()
        ->and($status->severity)->toBe(SeverityLevel::Medium);
});

it('flags an ambiguous active column at MEDIUM when a privilege boolean cast corroborates', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['title', 'active'];\n    protected \$casts = ['active' => 'boolean'];",
        '        Account::create($request->all());',
    ));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(SeverityLevel::Medium)
        ->and($findings[0]->description)->toContain("'active'");
});

it('reads a Laravel 11 casts() method as a corroborating privilege signal', function (): void {
    $body = <<<'BODY'
        protected $fillable = ['title', 'active'];

        /**
         * @return array<string, string>
         */
        protected function casts(): array
        {
            return ['active' => 'boolean'];
        }
    BODY;

    $findings = runFillableDetector(fillableWithSink($body, '        Account::create($request->all());'));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(SeverityLevel::Medium);
});

it('does NOT flag an is_* column on a model with no corroborating privilege signal', function (): void {
    // snipe-it's CustomField carries `is_unique`, a schema attribute that the
    // naming convention alone reads as a privilege flag.
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['name', 'is_unique'];",
        '        Account::create($request->all());',
    ));

    expect($findings)->toBe([]);
});

it('flags an is_* column when the model carries a corroborating privilege signal', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['name', 'is_premium', 'role'];",
        '        Account::create($request->all());',
    ));

    $premium = collect($findings)->first(fn (Vulnerability $v): bool => str_contains($v->description, "'is_premium'"));

    expect($premium)->not->toBeNull()
        ->and($premium->severity)->toBe(SeverityLevel::High);
});

it('does NOT flag ordinary publishing and lifecycle is_* flags', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['title', 'is_published', 'is_featured', 'is_default', 'is_public', 'is_active', 'is_archived', 'is_pinned', 'role'];",
        '        Account::create($request->all());',
    ));

    $fields = implode(' ', array_map(fn (Vulnerability $v): string => $v->description, $findings));

    expect($fields)->toContain("'role'")
        ->and($fields)->not->toContain('is_published')
        ->and($fields)->not->toContain('is_featured')
        ->and($fields)->not->toContain('is_pinned');
});

it('flags account-state fields only on a model that actually authenticates', function (): void {
    $comment = [
        [
            'path' => 'app/Models/Comment.php',
            'type' => 'model',
            'content' => "<?php\n\nnamespace App\\Models;\n\nuse Illuminate\\Database\\Eloquent\\Model;\n\nclass Comment extends Model\n{\n    protected \$fillable = ['body', 'is_verified', 'is_active'];\n}\n",
        ],
        [
            'path' => 'app/Http/Controllers/CommentController.php',
            'type' => 'controller',
            'content' => "<?php\n\nnamespace App\\Http\\Controllers;\n\nuse App\\Models\\Comment;\nuse Illuminate\\Http\\Request;\n\nclass CommentController\n{\n    public function store(Request \$request)\n    {\n        Comment::create(\$request->all());\n    }\n}\n",
        ],
    ];

    $user = [
        [
            'path' => 'app/Models/User.php',
            'type' => 'model',
            'content' => "<?php\n\nnamespace App\\Models;\n\nuse Illuminate\\Foundation\\Auth\\User as Authenticatable;\n\nclass User extends Authenticatable\n{\n    protected \$fillable = ['name', 'email', 'password', 'is_verified'];\n}\n",
        ],
        [
            'path' => 'app/Http/Controllers/UserController.php',
            'type' => 'controller',
            'content' => "<?php\n\nnamespace App\\Http\\Controllers;\n\nuse App\\Models\\User;\nuse Illuminate\\Http\\Request;\n\nclass UserController\n{\n    public function store(Request \$request)\n    {\n        User::create(\$request->all());\n    }\n}\n",
        ],
    ];

    $userFindings = runFillableDetector($user);

    expect(runFillableDetector($comment))->toBe([])
        ->and($userFindings)->toHaveCount(1)
        ->and($userFindings[0]->severity)->toBe(SeverityLevel::High)
        ->and($userFindings[0]->description)->toContain('is_verified');
});

it('flags subscription fields at medium severity when a sink exists', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['subscription_plan'];",
        '        Account::create($request->all());',
    ));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(SeverityLevel::Medium)
        ->and($findings[0]->description)->toContain('subscription_plan');
});

/*
|--------------------------------------------------------------------------
| Suppressors
|--------------------------------------------------------------------------
*/

it('does NOT flag a model fully guarded with $guarded = [\'*\']', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['name', 'is_admin', 'role'];\n    protected \$guarded = ['*'];",
        '        Account::create($request->all());',
    ));

    expect($findings)->toBe([]);
});

it('does NOT flag a column the model also names in $guarded', function (): void {
    $findings = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['name', 'is_admin'];\n    protected \$guarded = ['is_admin'];",
        '        Account::create($request->all());',
    ));

    expect($findings)->toBe([]);
});

it('does NOT flag a column with a set{Field}Attribute mutator', function (): void {
    $body = "    protected \$fillable = ['user_id'];\n".
        "    public function setUserIdAttribute(\$value) { abort_unless(auth()->id(), 403); \$this->attributes['user_id'] = \$value; }";

    expect(runFillableDetector(fillableWithSink($body, '        Account::create($request->all());')))->toBe([]);
});

it('accepts a Laravel 9 Attribute accessor as the guard on an ownership column', function (): void {
    $files = [
        [
            'path' => 'app/Models/Post.php',
            'type' => 'model',
            'content' => <<<'PHP'
            <?php

            namespace App\Models;

            use Illuminate\Database\Eloquent\Casts\Attribute;
            use Illuminate\Database\Eloquent\Model;

            class Post extends Model
            {
                protected $fillable = ['title', 'user_id'];

                protected function userId(): Attribute
                {
                    return Attribute::make(set: fn (): int => (int) auth()->id());
                }
            }
            PHP,
        ],
        [
            'path' => 'app/Http/Controllers/PostController.php',
            'type' => 'controller',
            'content' => "<?php\n\nnamespace App\\Http\\Controllers;\n\nuse App\\Models\\Post;\nuse Illuminate\\Http\\Request;\n\nclass PostController\n{\n    public function store(Request \$request)\n    {\n        Post::create(\$request->all());\n    }\n}\n",
        ],
    ];

    expect(runFillableDetector($files))->toBe([]);
});

it('does NOT flag non-model files', function (): void {
    $files = [[
        'path' => 'app/Http/Controllers/AccountController.php',
        'type' => 'controller',
        'content' => "<?php\nclass AccountController { protected \$fillable = ['is_admin']; }",
    ]];

    expect(runFillableDetector($files))->toBe([]);
});

it('does NOT flag a model without a fillable array', function (): void {
    expect(runFillableDetector(fillableModel('    protected $guarded = [];')))->toBe([]);
});

/*
|--------------------------------------------------------------------------
| The array is read from the AST, never from raw text
|--------------------------------------------------------------------------
*/

it('still detects privilege fields when a comment inside $fillable contains an apostrophe', function (): void {
    $body = <<<'BODY'
        protected $fillable = [
            // lets a request reassign someone else's account
            'user_id',
            // privilege flag
            'is_admin',
        ];
    BODY;

    $findings = runFillableDetector(fillableWithSink($body, '        Account::create($request->all());'));

    expect($findings)->toHaveCount(2)
        ->and($findings[0]->type)->toBe(VulnerabilityType::MassAssignment);
});

it('ignores fields that only appear inside comments', function (): void {
    $body = <<<'BODY'
        protected $fillable = [
            // 'is_admin' is deliberately NOT mass assignable
            'name',
        ];
    BODY;

    expect(runFillableDetector(fillableWithSink($body, '        Account::create($request->all());')))->toBe([]);
});

it('reads $fillable written with hash and block comments', function (): void {
    foreach ([
        "    protected \$fillable = [\n        # don't do this\n        'is_admin',\n    ];",
        "    protected \$fillable = [\n        /* it's risky */\n        'is_admin',\n    ];",
    ] as $body) {
        expect(runFillableDetector(fillableWithSink($body, '        Account::create($request->all());')))->toHaveCount(1);
    }
});

it('does NOT read a $fillable array out of a docblock example', function (): void {
    $body = <<<'BODY'
        /**
         * Do NOT do this:
         *
         *     protected $fillable = ['is_admin', 'role'];
         *
         * @var array<int, string>
         */
        protected $fillable = ['name', 'email'];
    BODY;

    expect(runFillableDetector(fillableWithSink($body, '        Account::create($request->all());')))->toBe([]);
});

it('does NOT read a $fillable array out of a string literal', function (): void {
    $body = <<<'BODY'
        public function example(): string
        {
            return 'protected $fillable = [\'is_admin\'];';
        }

        protected $fillable = ['name'];
    BODY;

    expect(runFillableDetector(fillableWithSink($body, '        Account::create($request->all());')))->toBe([]);
});

it('does NOT treat a controller as a model because its docblock mentions one', function (): void {
    $findings = runFillableDetector([[
        'path' => 'app/Http/Controllers/DocsController.php',
        'type' => 'controller',
        'content' => "<?php\n\nnamespace App\\Http\\Controllers;\n\n/**\n * Example: class Foo extends Model { protected \$fillable = ['is_admin']; }\n */\nclass DocsController\n{\n}\n",
    ]]);

    expect($findings)->toBe([]);
});

it('reports the line of the field literal, not the first quoted occurrence in the file', function (): void {
    $body = <<<'BODY'
        /**
         * 'is_admin' must never be mass assigned.
         *
         * @var array<string, string>
         */
        protected $casts = ['is_admin' => 'boolean'];

        /**
         * @var array<int, string>
         */
        protected $fillable = [
            'name',
            'is_admin',
        ];
    BODY;

    $files = fillableWithSink($body, '        Account::create($request->all());');
    $expected = fillableLineContaining($files[0]['content'], "        'is_admin',");

    $findings = runFillableDetector($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->line)->toBe($expected);
});

it('skips non-literal $fillable entries instead of guessing at them', function (): void {
    $body = <<<'BODY'
        public const EXTRA = ['bio'];

        protected $fillable = [
            self::EXTRA[0],
            'is_admin',
            ...self::EXTRA,
        ];
    BODY;

    $findings = runFillableDetector(fillableWithSink($body, '        Account::create($request->all());'));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->description)->toContain('is_admin');
});

it('emits nothing for a file that cannot be parsed instead of guessing', function (): void {
    $findings = runFillableDetector([[
        'path' => 'app/Models/Broken.php',
        'type' => 'model',
        'content' => "<?php\nnamespace App\\Models;\nclass Broken extends Model {\n    protected \$fillable = ['is_admin'];\n",
    ]]);

    expect($findings)->toBe([]);
});

/*
|--------------------------------------------------------------------------
| Clean corpus
|--------------------------------------------------------------------------
*/

/**
 * Load the clean precision corpus in the shape the detector consumes.
 *
 * @return array<int, array{path: string, content: string, type: string}>
 */
function fillablePrecisionFiles(): array
{
    $root = dirname(__DIR__).'/Fixtures/precision';
    $files = [];

    /** @var iterable<SplFileInfo> $iterator */
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
    );

    foreach ($iterator as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        $relative = str_replace(DIRECTORY_SEPARATOR, '/', str_replace($root.DIRECTORY_SEPARATOR, '', $file->getPathname()));

        $files[] = [
            'path' => $relative,
            'content' => (string) file_get_contents($file->getPathname()),
            'type' => match (true) {
                str_contains($relative, 'Http/Controllers/') => 'controller',
                str_contains($relative, 'Models/') => 'model',
                str_starts_with($relative, 'routes/') => 'route',
                default => 'other',
            },
        ];
    }

    return $files;
}

it('reports nothing for any file in the clean precision corpus', function (): void {
    $claims = array_map(
        fn (Vulnerability $v): string => sprintf('%s:%d %s', $v->location, $v->line, $v->description),
        runFillableDetector(fillablePrecisionFiles()),
    );

    expect($claims)->toBe([]);
});

/*
|--------------------------------------------------------------------------
| Finding class contract
|--------------------------------------------------------------------------
*/

it('asserts a proven chain and only asks a question without one', function (): void {
    $proven = runFillableDetector(fillableWithSink(
        "    protected \$fillable = ['name', 'is_admin'];",
        '        Account::create($request->all());',
    ));

    $review = runFillableDetector(fillableModel("    protected \$fillable = ['name', 'is_admin'];"));

    expect($proven)->toHaveCount(1)
        ->and($proven[0]->findingClass)->toBe(FindingClass::Vulnerability)
        ->and($proven[0]->confidence)->toBe(Confidence::Proven)
        ->and($proven[0]->isConfirmedVulnerability())->toBeTrue()
        ->and($proven[0]->hasFix())->toBeTrue()
        ->and($review)->toHaveCount(1)
        ->and($review[0]->findingClass)->toBe(FindingClass::Review)
        ->and($review[0]->isConfirmedVulnerability())->toBeFalse()
        ->and($review[0]->hasFix())->toBeFalse();
});

it('never emits a finding that carries a fix without proven confidence', function (): void {
    $files = [
        ...fillableWithSink("    protected \$fillable = ['name', 'is_admin', 'user_id'];", '        Account::create($request->all());'),
        ...fillableModel("    protected \$fillable = ['role'];", 'Membership'),
    ];

    foreach (runFillableDetector($files) as $finding) {
        expect($finding->hasFix())->toBe($finding->mayCarryFix());
    }
});
