<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * @property string $id
 * @property int $score
 * @property int $total_vulnerabilities
 * @property int $critical_count
 * @property int $high_count
 * @property int $medium_count
 * @property int $low_count
 * @property array<int, array<string, mixed>> $vulnerabilities
 * @property string $summary
 * @property int $files_scanned
 * @property int $scan_duration_ms
 * @property string|null $ai_provider
 * @property string|null $ai_model
 * @property string $laravel_version
 * @property \Illuminate\Support\Carbon|null $created_at
 * @property \Illuminate\Support\Carbon|null $updated_at
 *
 * @method static Builder<static> critical()
 * @method static Builder<static> recent(int $days = 7)
 * @method static Builder<static> byScore(string $direction = 'asc')
 */
final class ScanResult extends Model
{
    use HasUlids;

    /** @var string */
    protected $table = 'hack_auditor_scans';

    /** @var list<string> */
    protected $fillable = [
        'score',
        'total_vulnerabilities',
        'critical_count',
        'high_count',
        'medium_count',
        'low_count',
        'vulnerabilities',
        'summary',
        'files_scanned',
        'scan_duration_ms',
        'ai_provider',
        'ai_model',
        'laravel_version',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'vulnerabilities' => 'array',
            'score' => 'integer',
            'total_vulnerabilities' => 'integer',
            'critical_count' => 'integer',
            'high_count' => 'integer',
            'medium_count' => 'integer',
            'low_count' => 'integer',
            'files_scanned' => 'integer',
            'scan_duration_ms' => 'integer',
            'created_at' => 'datetime',
            'updated_at' => 'datetime',
        ];
    }

    /**
     * Scope to only include scans with critical vulnerabilities.
     *
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    public function scopeCritical(Builder $query): Builder
    {
        return $query->where('critical_count', '>', 0);
    }

    /**
     * Scope to only include scans from the last N days.
     *
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    public function scopeRecent(Builder $query, int $days = 7): Builder
    {
        return $query->where('created_at', '>=', now()->subDays($days));
    }

    /**
     * Scope to order scans by score in the given direction.
     *
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    public function scopeByScore(Builder $query, string $direction = 'asc'): Builder
    {
        return $query->orderBy('score', $direction);
    }

    /**
     * Reconstruct a VulnerabilityReport DTO from the stored scan data.
     *
     * Creates Vulnerability DTOs from the JSON vulnerabilities column,
     * mapping stored string values back to their respective enums.
     */
    public function report(): VulnerabilityReport
    {
        /** @var array<int, array<string, mixed>> $rawVulnerabilities */
        $rawVulnerabilities = $this->vulnerabilities;

        $vulnerabilities = array_map(
            fn (array $item): Vulnerability => new Vulnerability(
                type: VulnerabilityType::fromString((string) ($item['type'] ?? 'missing_validation')),
                location: (string) ($item['location'] ?? ''),
                line: (int) ($item['line'] ?? 0),
                severity: SeverityLevel::fromString((string) ($item['severity'] ?? 'low')),
                description: (string) ($item['description'] ?? ''),
                proof: (string) ($item['proof'] ?? ''),
                fix: (string) ($item['fix'] ?? ''),
            ),
            $rawVulnerabilities,
        );

        return new VulnerabilityReport(
            vulnerabilities: $vulnerabilities,
            overallScore: $this->score,
            summary: $this->summary,
            ctfIdea: '',
        );
    }
}
