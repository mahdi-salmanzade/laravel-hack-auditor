<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\AccessControl\SourceFile;
use Mahdi\HackAuditor\Scanner\AccessControl\SsrfDetector;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * FALSE-POSITIVE REGRESSION SUITE FOR SsrfDetector.
 *
 * Every silence assertion here corresponds to a HIGH-severity finding the
 * regex-based detector shipped against a real, clean 73-controller
 * application, or to the root cause behind one:
 *
 *   FP-4  $this->imageUpload->delete($request->user()->profile_image)
 *         — a LOCAL storage service, reported as an outbound request, with the
 *           AUTHENTICATED USER OBJECT cited as attacker-controlled input.
 *   FP-5  User::query()->whereIn(...)->lockForUpdate()->get()
 *         and $participants->get($blockedId)
 *         — a database read and a Collection lookup, reported as SSRF.
 *
 * The two causes were (a) matching `->get(`/`->delete(` with no idea what the
 * receiver was, and (b) treating `$request->` as proof of attacker control.
 * Both are covered below, along with the recall cases that must survive.
 */

/**
 * @param  array<int, array{path: string, content: string, type: string}>  $files
 * @return array<int, Vulnerability>
 */
function ssrfPrecisionFindings(array $files): array
{
    return (new SsrfDetector)->detect(
        array_map(static fn (array $file): SourceFile => SourceFile::fromArray($file), $files),
        new AccessControlContext,
    );
}

/**
 * @param  array<string, string>  $extra  Extra files: path => source
 * @return array<int, array{path: string, content: string, type: string}>
 */
function ssrfPrecisionApp(string $controller, array $extra = []): array
{
    $files = [[
        'path' => 'app/Http/Controllers/TargetController.php',
        'type' => 'controller',
        'content' => $controller,
    ]];

    foreach ($extra as $path => $content) {
        $files[] = ['path' => $path, 'type' => 'other', 'content' => $content];
    }

    return $files;
}

/**
 * @param  array<int, Vulnerability>  $findings
 * @return array<int, string>
 */
function ssrfPrecisionDescribe(array $findings): array
{
    return array_map(
        static fn (Vulnerability $v): string => sprintf('%s:%d [%s] %s', $v->location, $v->line, $v->type->value, $v->description),
        $findings,
    );
}

/*
|--------------------------------------------------------------------------
| FP-4 — a local service is not an HTTP client
|--------------------------------------------------------------------------
*/

it('stays silent on a promoted local service whose method happens to be called delete (FP-4)', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use App\Services\ImageUploadService;
    use Illuminate\Http\Request;

    class TargetController extends Controller
    {
        public function __construct(private readonly ImageUploadService $imageUpload) {}

        public function deleteProfileImage(Request $request)
        {
            $user = $request->user();

            $this->imageUpload->delete($user->profile_image);

            return response()->json(['ok' => true]);
        }
    }
    PHP;

    $service = <<<'PHP'
    <?php
    namespace App\Services;

    use Illuminate\Support\Facades\Storage;

    class ImageUploadService
    {
        public function delete(?string $path): void
        {
            Storage::disk('public')->delete($path);
        }
    }
    PHP;

    expect(ssrfPrecisionDescribe(ssrfPrecisionFindings(ssrfPrecisionApp($controller, ['app/Services/ImageUploadService.php' => $service]))))->toBe([]);
});

it('stays silent on the same local service even when its class is not in the scan (FP-4)', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use App\Services\ImageUploadService;
    use Illuminate\Http\Request;

    class TargetController extends Controller
    {
        public function __construct(private readonly ImageUploadService $imageUpload) {}

        public function updateProfileImage(Request $request)
        {
            $this->imageUpload->delete($request->user()->profile_image);

            return response()->json(['ok' => true]);
        }
    }
    PHP;

    expect(ssrfPrecisionDescribe(ssrfPrecisionFindings(ssrfPrecisionApp($controller))))->toBe([]);
});

it('never treats $request->user() as attacker-controlled input, even at a real HTTP sink', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Http;

    class TargetController extends Controller
    {
        public function ping(Request $request)
        {
            return Http::get($request->user()->profile_image);
        }
    }
    PHP;

    expect(ssrfPrecisionDescribe(ssrfPrecisionFindings(ssrfPrecisionApp($controller))))->toBe([]);
});

it('never treats auth()->user(), $request->ip() or config() as attacker-controlled input', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Http;

    class TargetController extends Controller
    {
        public function fromAuthUser(Request $request)
        {
            return Http::get(auth()->user()->callback_url);
        }

        public function fromIp(Request $request)
        {
            return Http::get('https://geo.internal/lookup/'.$request->ip());
        }

        public function fromConfig()
        {
            return Http::get(config('services.billing.url'));
        }

        public function fromRouteHelper()
        {
            return Http::get(route('webhooks.receive'));
        }
    }
    PHP;

    expect(ssrfPrecisionDescribe(ssrfPrecisionFindings(ssrfPrecisionApp($controller))))->toBe([]);
});

it('never treats a route-model-bound parameter as attacker-controlled input', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use App\Models\Room;
    use Illuminate\Support\Facades\Http;

    class TargetController extends Controller
    {
        public function notify(Room $room)
        {
            return Http::post($room->webhook_url, ['event' => 'ping']);
        }
    }
    PHP;

    expect(ssrfPrecisionDescribe(ssrfPrecisionFindings(ssrfPrecisionApp($controller))))->toBe([]);
});

/*
|--------------------------------------------------------------------------
| FP-5 — Eloquent and Collections are not HTTP clients
|--------------------------------------------------------------------------
*/

it('stays silent on an Eloquent read and a Collection lookup that both end in ->get() (FP-5)', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use App\Http\Requests\BlockUserRequest;
    use App\Models\User;

    class TargetController extends Controller
    {
        public function store(BlockUserRequest $request)
        {
            $blockedId = (int) $request->validated('user_id');

            $participants = User::query()
                ->whereIn('id', [$request->user()->id, $blockedId])
                ->lockForUpdate()
                ->get()
                ->keyBy('id');

            $blocked = $participants->get($blockedId);

            abort_if($blocked === null, 404);

            return response()->json(['blocked' => true], 201);
        }
    }
    PHP;

    expect(ssrfPrecisionDescribe(ssrfPrecisionFindings(ssrfPrecisionApp($controller))))->toBe([]);
});

it('stays silent on a query builder chain whose verb is delete()', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use App\Models\Token;
    use Illuminate\Http\Request;

    class TargetController extends Controller
    {
        public function purge(Request $request)
        {
            return Token::query()->where('name', $request->input('name'))->delete();
        }
    }
    PHP;

    expect(ssrfPrecisionDescribe(ssrfPrecisionFindings(ssrfPrecisionApp($controller))))->toBe([]);
});

it('stays silent on the Storage facade', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Storage;

    class TargetController extends Controller
    {
        public function destroy(Request $request)
        {
            Storage::disk('public')->delete($request->input('path'));

            return response()->noContent();
        }
    }
    PHP;

    expect(ssrfPrecisionDescribe(ssrfPrecisionFindings(ssrfPrecisionApp($controller))))->toBe([]);
});

/*
|--------------------------------------------------------------------------
| An unresolved receiver is never evidence
|--------------------------------------------------------------------------
*/

it('stays silent on ->get()/->post()/->delete() when the receiver type is unresolved', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use Illuminate\Http\Request;

    class TargetController extends Controller
    {
        public function fetch(Request $request)
        {
            $url = $request->input('url');

            $a = $this->whatever->get($url);
            $b = $undeclared->post($url);
            $c = $this->registry->delete($url);

            return [$a, $b, $c];
        }
    }
    PHP;

    expect(ssrfPrecisionDescribe(ssrfPrecisionFindings(ssrfPrecisionApp($controller))))->toBe([]);
});

it('stays silent on file_get_contents when the value is a path rather than a URL', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use Illuminate\Http\Request;

    class TargetController extends Controller
    {
        public function show(Request $request)
        {
            $document = $request->input('document');

            return response(file_get_contents($document));
        }
    }
    PHP;

    expect(ssrfPrecisionDescribe(ssrfPrecisionFindings(ssrfPrecisionApp($controller))))->toBe([]);
});

it('stays silent when a proven HTTP client is handed a constant or a config value', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use GuzzleHttp\Client;
    use Illuminate\Http\Request;

    class TargetController extends Controller
    {
        public function __construct(private readonly Client $client) {}

        public function status(Request $request)
        {
            $this->client->get('https://api.example.com/status');

            return $this->client->request('GET', config('services.billing.url'));
        }
    }
    PHP;

    expect(ssrfPrecisionDescribe(ssrfPrecisionFindings(ssrfPrecisionApp($controller))))->toBe([]);
});

/*
|--------------------------------------------------------------------------
| Sanitisation
|--------------------------------------------------------------------------
*/

it('stays silent when the host is checked against an allow-list via parse_url', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Http;

    class TargetController extends Controller
    {
        public function fetch(Request $request)
        {
            $url = $request->input('url');
            $host = parse_url($url, PHP_URL_HOST);

            abort_unless(in_array($host, ['api.example.com', 'cdn.example.com'], true), 403);

            return Http::get($url);
        }
    }
    PHP;

    expect(ssrfPrecisionDescribe(ssrfPrecisionFindings(ssrfPrecisionApp($controller))))->toBe([]);
});

it('stays silent when the destination is prefix-checked with Str::startsWith', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Http;
    use Illuminate\Support\Str;

    class TargetController extends Controller
    {
        public function fetch(Request $request)
        {
            $url = $request->input('url');

            abort_unless(Str::startsWith($url, 'https://api.example.com/'), 403);

            return Http::get($url);
        }
    }
    PHP;

    expect(ssrfPrecisionDescribe(ssrfPrecisionFindings(ssrfPrecisionApp($controller))))->toBe([]);
});

it('stays silent when a FormRequest declares a url rule for the destination', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use App\Http\Requests\StoreWebhookRequest;
    use Illuminate\Support\Facades\Http;

    class TargetController extends Controller
    {
        public function store(StoreWebhookRequest $request)
        {
            return Http::get($request->validated('endpoint'));
        }
    }
    PHP;

    $formRequest = <<<'PHP'
    <?php
    namespace App\Http\Requests;

    use Illuminate\Foundation\Http\FormRequest;

    class StoreWebhookRequest extends FormRequest
    {
        public function rules(): array
        {
            return ['endpoint' => ['required', 'url']];
        }
    }
    PHP;

    expect(ssrfPrecisionDescribe(ssrfPrecisionFindings(ssrfPrecisionApp($controller, ['app/Http/Requests/StoreWebhookRequest.php' => $formRequest]))))->toBe([]);
});

it('does not mistake a field NAMED url for a url validation rule', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Http;

    class TargetController extends Controller
    {
        public function fetch(Request $request)
        {
            $request->validate(['url' => ['required', 'string']]);

            return Http::get($request->input('url'));
        }
    }
    PHP;

    $findings = ssrfPrecisionFindings(ssrfPrecisionApp($controller));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->line)->toBe(13);
});

/*
|--------------------------------------------------------------------------
| Recall — genuine SSRF still fires, at the exact AST line
|--------------------------------------------------------------------------
*/

it('flags a Guzzle client resolved from a promoted property', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use GuzzleHttp\Client;
    use Illuminate\Http\Request;

    class TargetController extends Controller
    {
        public function __construct(private readonly Client $client) {}

        public function fetch(Request $request)
        {
            return $this->client->get($request->input('url'));
        }
    }
    PHP;

    $findings = ssrfPrecisionFindings(ssrfPrecisionApp($controller));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::Ssrf)
        ->and($findings[0]->line)->toBe(13);
});

it('flags a Guzzle client held in a typed property and a locally constructed one', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use GuzzleHttp\Client;
    use Illuminate\Http\Request;

    class TargetController extends Controller
    {
        public function fetch(Request $request)
        {
            $client = new Client;

            return $client->get($request->query('target_url'));
        }
    }
    PHP;

    $findings = ssrfPrecisionFindings(ssrfPrecisionApp($controller));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->line)->toBe(13);
});

it('flags header, cookie, route-parameter and superglobal sources', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Http;

    class TargetController extends Controller
    {
        public function fromHeader(Request $request)
        {
            return Http::get($request->header('X-Forward-To'));
        }

        public function fromCookie(Request $request)
        {
            return Http::get($request->cookie('next'));
        }

        public function fromRouteParameter(Request $request)
        {
            return Http::get($request->route('endpoint'));
        }

        public function fromSuperglobal()
        {
            return Http::get($_GET['url']);
        }
    }
    PHP;

    $lines = array_map(
        static fn (Vulnerability $v): int => $v->line,
        ssrfPrecisionFindings(ssrfPrecisionApp($controller)),
    );

    expect($lines)->toBe([11, 16, 21, 26]);
});

it('reports the exact AST line of the sink, not a docblock or a neighbouring method', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Http;

    class TargetController extends Controller
    {
        /**
         * Proxy a remote document.
         *
         * @param  string  $label  Display label, e.g. "draft (pending)"
         */
        public function proxy(
            Request $request,
            string $label = 'draft (pending)',
        ) {
            $url = $request->input('url');

            return Http::withToken('static-token')->get($url);
        }

        // public function legacyProxy(Request $request)
        // {
        //     return Http::get($request->input('url'));
        // }
    }
    PHP;

    $findings = ssrfPrecisionFindings(ssrfPrecisionApp($controller));

    $lines = explode("\n", $controller);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->line)->toBe(20)
        ->and($lines[$findings[0]->line - 1])->toContain('Http::withToken');
});

it('flags a named url argument on a proven HTTP client', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Http;

    class TargetController extends Controller
    {
        public function fetch(Request $request)
        {
            return Http::get(url: $request->input('url'));
        }
    }
    PHP;

    $findings = ssrfPrecisionFindings(ssrfPrecisionApp($controller));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->line)->toBe(11);
});

it('flags curl_setopt_array with a tainted CURLOPT_URL', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use Illuminate\Http\Request;

    class TargetController extends Controller
    {
        public function fetch(Request $request)
        {
            $handle = curl_init();

            curl_setopt_array($handle, [
                CURLOPT_URL => $request->input('url'),
                CURLOPT_RETURNTRANSFER => true,
            ]);

            return curl_exec($handle);
        }
    }
    PHP;

    $findings = ssrfPrecisionFindings(ssrfPrecisionApp($controller));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->line)->toBe(12);
});

/*
|--------------------------------------------------------------------------
| The advice must never be able to break an application
|--------------------------------------------------------------------------
*/

it('emits remediation advice that names no identifier from the analysed code', function (): void {
    $controller = <<<'PHP'
    <?php
    namespace App\Http\Controllers;

    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Http;

    class TargetController extends Controller
    {
        public function fetch(Request $request)
        {
            return Http::get($request->input('url'));
        }
    }
    PHP;

    $findings = ssrfPrecisionFindings(ssrfPrecisionApp($controller));

    expect($findings)->toHaveCount(1);

    foreach ($findings as $finding) {
        expect($finding->fix)->not->toContain('$')
            ->and($finding->fix)->not->toContain('authorize(')
            ->and($finding->fix)->not->toContain('TargetController');
    }
});

it('reports nothing for a file that cannot be parsed', function (): void {
    $files = [[
        'path' => 'app/Http/Controllers/BrokenController.php',
        'type' => 'controller',
        'content' => "<?php\nclass BrokenController {\n    public function fetch( { return Http::get(\$_GET['url']);\n",
    ]];

    expect(ssrfPrecisionFindings($files))->toBe([]);
});
