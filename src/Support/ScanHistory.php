<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Support;

use Illuminate\Support\Str;

class ScanHistory
{
    private readonly string $directory;

    public function __construct(?string $directory = null)
    {
        $this->directory = $directory ?? storage_path('hack-auditor/scans');
    }

    /**
     * Save a scan result. Returns the scan ID (ULID).
     *
     * @param  array<string, mixed>  $data
     */
    public function save(array $data): string
    {
        $id = (string) Str::ulid();

        $entry = array_merge($data, [
            'id' => $id,
            'created_at' => now()->toIso8601String(),
        ]);

        $this->ensureDirectory();

        file_put_contents(
            $this->path($id),
            json_encode($entry, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
            LOCK_EX,
        );

        return $id;
    }

    /**
     * Get a scan by ID.
     *
     * @return array<string, mixed>|null
     */
    public function find(string $id): ?array
    {
        $path = $this->path($id);

        if (! file_exists($path)) {
            return null;
        }

        $data = json_decode((string) file_get_contents($path), true);

        return is_array($data) ? $data : null;
    }

    /**
     * Get the latest scan result (ULID is time-sortable).
     *
     * @return array<string, mixed>|null
     */
    public function latest(): ?array
    {
        $files = $this->listFiles();

        if ($files === []) {
            return null;
        }

        rsort($files);

        $data = json_decode((string) file_get_contents($files[0]), true);

        return is_array($data) ? $data : null;
    }

    /**
     * Get all scan results, newest first.
     *
     * @return array<int, array<string, mixed>>
     */
    public function all(): array
    {
        $files = $this->listFiles();
        rsort($files);

        $results = [];

        foreach ($files as $file) {
            $data = json_decode((string) file_get_contents($file), true);

            if (is_array($data)) {
                $results[] = $data;
            }
        }

        return $results;
    }

    /**
     * Get recent scans (last N).
     *
     * @return array<int, array<string, mixed>>
     */
    public function recent(int $limit = 10): array
    {
        return array_slice($this->all(), 0, $limit);
    }

    /**
     * Get scans with critical vulnerabilities.
     *
     * @return array<int, array<string, mixed>>
     */
    public function withCritical(): array
    {
        return array_values(array_filter(
            $this->all(),
            fn (array $scan): bool => ($scan['counts']['critical'] ?? 0) > 0,
        ));
    }

    /**
     * Get the number of saved scans.
     */
    public function count(): int
    {
        return count($this->listFiles());
    }

    /**
     * Delete a scan by ID.
     */
    public function delete(string $id): bool
    {
        $path = $this->path($id);

        if (file_exists($path)) {
            return unlink($path);
        }

        return false;
    }

    /**
     * Clear all scan history. Returns number of files deleted.
     */
    public function clear(): int
    {
        $files = $this->listFiles();
        $count = count($files);

        foreach ($files as $file) {
            unlink($file);
        }

        return $count;
    }

    /**
     * Get the storage directory path.
     */
    public function getDirectory(): string
    {
        return $this->directory;
    }

    private function path(string $id): string
    {
        return $this->directory.DIRECTORY_SEPARATOR.$id.'.json';
    }

    /**
     * @return array<int, string>
     */
    private function listFiles(): array
    {
        if (! is_dir($this->directory)) {
            return [];
        }

        $files = glob($this->directory.DIRECTORY_SEPARATOR.'*.json');

        return $files !== false ? $files : [];
    }

    private function ensureDirectory(): void
    {
        if (! is_dir($this->directory)) {
            mkdir($this->directory, 0755, true);
        }
    }
}
