<?php

declare(strict_types=1);

use Illuminate\Support\Collection;
use Mahdi\HackAuditor\Scanner\CodeExtractor;

beforeEach(function (): void {
    $this->extractor = new CodeExtractor;
    $this->tempDir = sys_get_temp_dir().'/hack-auditor-extractor-'.uniqid();
    mkdir($this->tempDir, 0755, true);
    $this->tempDir = realpath($this->tempDir);
});

afterEach(function (): void {
    if (is_dir($this->tempDir)) {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->tempDir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($iterator as $file) {
            if ($file->isDir()) {
                rmdir($file->getRealPath());
            } else {
                unlink($file->getRealPath());
            }
        }

        rmdir($this->tempDir);
    }
});

it('detects controller type from class structure', function (): void {
    $filePath = $this->tempDir.'/UserController.php';
    file_put_contents($filePath, <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    class UserController extends Controller
    {
        public function index() {}
    }
    PHP);

    $file = new SplFileInfo($filePath);
    $result = $this->extractor->extract($file);

    expect($result['type'])->toBe('controller');
});

it('detects model type from class structure', function (): void {
    $filePath = $this->tempDir.'/User.php';
    file_put_contents($filePath, <<<'PHP'
    <?php

    namespace App\Models;

    use Illuminate\Database\Eloquent\Model;

    class User extends Model
    {
        protected $fillable = ['name', 'email'];
    }
    PHP);

    $file = new SplFileInfo($filePath);
    $result = $this->extractor->extract($file);

    expect($result['type'])->toBe('model');
});

it('detects middleware type from class structure', function (): void {
    $filePath = $this->tempDir.'/CheckAge.php';
    file_put_contents($filePath, <<<'PHP'
    <?php

    namespace App\Http\Middleware;

    class CheckAge extends Middleware
    {
        public function handle($request, $next) {}
    }
    PHP);

    $file = new SplFileInfo($filePath);
    $result = $this->extractor->extract($file);

    expect($result['type'])->toBe('middleware');
});

it('detects request type from class structure', function (): void {
    $filePath = $this->tempDir.'/StoreUserRequest.php';
    file_put_contents($filePath, <<<'PHP'
    <?php

    namespace App\Http\Requests;

    use Illuminate\Foundation\Http\FormRequest;

    class StoreUserRequest extends FormRequest
    {
        public function rules(): array { return []; }
    }
    PHP);

    $file = new SplFileInfo($filePath);
    $result = $this->extractor->extract($file);

    expect($result['type'])->toBe('request');
});

it('detects route type from path containing routes/', function (): void {
    $routesDir = $this->tempDir.'/routes';
    mkdir($routesDir, 0755, true);

    $filePath = $routesDir.'/web.php';
    file_put_contents($filePath, <<<'PHP'
    <?php

    use Illuminate\Support\Facades\Route;

    Route::get('/', function () {
        return view('welcome');
    });
    PHP);

    // Set base_path to tempDir so relative path includes routes/
    $reflector = new ReflectionProperty($this->app, 'basePath');
    $reflector->setValue($this->app, $this->tempDir);

    $file = new SplFileInfo($filePath);
    $result = $this->extractor->extract($file);

    expect($result['type'])->toBe('route');
});

it('returns other type for unrecognized files', function (): void {
    $filePath = $this->tempDir.'/helpers.php';
    file_put_contents($filePath, <<<'PHP'
    <?php

    function formatMoney(float $amount): string
    {
        return '$' . number_format($amount, 2);
    }
    PHP);

    $file = new SplFileInfo($filePath);
    $result = $this->extractor->extract($file);

    expect($result['type'])->toBe('other');
});

it('chunks files correctly based on config chunk_size', function (): void {
    $this->app['config']->set('hack-auditor.scan.chunk_size', 2);

    $files = new Collection;

    for ($i = 1; $i <= 5; $i++) {
        $filePath = $this->tempDir."/File{$i}.php";
        file_put_contents($filePath, "<?php class File{$i} {}");
        $files->push(new SplFileInfo($filePath));
    }

    $chunks = $this->extractor->chunk($files);

    expect($chunks)->toHaveCount(3)
        ->and($chunks[0])->toHaveCount(2)
        ->and($chunks[1])->toHaveCount(2)
        ->and($chunks[2])->toHaveCount(1);
});

it('groups all files into one chunk when chunk_size exceeds file count', function (): void {
    $this->app['config']->set('hack-auditor.scan.chunk_size', 100);

    $files = new Collection;

    for ($i = 1; $i <= 3; $i++) {
        $filePath = $this->tempDir."/File{$i}.php";
        file_put_contents($filePath, "<?php class File{$i} {}");
        $files->push(new SplFileInfo($filePath));
    }

    $chunks = $this->extractor->chunk($files);

    expect($chunks)->toHaveCount(1)
        ->and($chunks[0])->toHaveCount(3);
});

it('strips multi-line comments but preserves single-line comments', function (): void {
    $filePath = $this->tempDir.'/Commented.php';
    file_put_contents($filePath, <<<'PHP'
    <?php

    /**
     * This is a multi-line docblock that should be stripped.
     * It contains multiple lines.
     */
    class CommentedClass
    {
        // This single-line comment should remain
        public function hello()
        {
            /* inline block comment removed */
            return 'world'; // keep this too
        }
    }
    PHP);

    $file = new SplFileInfo($filePath);
    $result = $this->extractor->extract($file);

    expect($result['content'])->toContain('// This single-line comment should remain')
        ->and($result['content'])->toContain('// keep this too')
        ->and($result['content'])->not->toContain('multi-line docblock')
        ->and($result['content'])->not->toContain('inline block comment removed');
});

it('collapses excessive blank lines', function (): void {
    $filePath = $this->tempDir.'/SpacedOut.php';
    $content = "<?php\n\nclass A {\n\n\n\n\n\npublic function b() {}\n\n\n\n\n}";
    file_put_contents($filePath, $content);

    $file = new SplFileInfo($filePath);
    $result = $this->extractor->extract($file);

    // After cleaning, no more than 2 consecutive newlines
    expect($result['content'])->not->toContain("\n\n\n");
});

it('returns empty content and other type for files with unresolvable path', function (): void {
    // Use a mock SplFileInfo that returns false for getRealPath
    $mockFile = Mockery::mock(SplFileInfo::class);
    $mockFile->shouldReceive('getRealPath')->andReturn(false);
    $mockFile->shouldReceive('getPathname')->andReturn('/fake/path.php');

    $result = $this->extractor->extract($mockFile);

    expect($result['content'])->toBe('')
        ->and($result['type'])->toBe('other')
        ->and($result['path'])->toBe('/fake/path.php');
});

it('extracts the correct relative path for files under base_path', function (): void {
    $reflector = new ReflectionProperty($this->app, 'basePath');
    $reflector->setValue($this->app, $this->tempDir);

    $subDir = $this->tempDir.'/app/Http/Controllers';
    mkdir($subDir, 0755, true);

    $filePath = $subDir.'/TestController.php';
    file_put_contents($filePath, '<?php class TestController extends Controller {}');

    $file = new SplFileInfo($filePath);
    $result = $this->extractor->extract($file);

    expect($result['path'])->toBe('app/Http/Controllers/TestController.php');
});
