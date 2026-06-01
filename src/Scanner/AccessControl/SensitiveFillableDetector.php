<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\AccessControl;

use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * Flags Eloquent models whose $fillable array exposes privilege- or
 * identity-bearing columns to mass assignment.
 *
 * Laravel-specific reasoning: any attribute listed in $fillable can be set
 * directly from request input via Model::create($request->all()) or
 * $model->fill($request->all()). When that attribute controls authorization
 * (is_admin, role, plan, balance) or resource ownership (user_id, owner_id),
 * an attacker can escalate privileges or hijack records simply by adding the
 * field to the request body. This is CWE-915 (mass assignment of sensitive
 * attributes), the canonical Laravel privilege-escalation bug.
 *
 * Conservative design: only flags when a clearly-sensitive field is present in
 * $fillable AND the model shows no compensating guard (a `$guarded` of the
 * same field, a mutator that re-checks authorization, or an explicit cast that
 * neutralizes it). Prefer a miss over a false positive.
 */
final class SensitiveFillableDetector implements AccessControlDetector
{
    /**
     * Exact field names that always represent a privilege or money boundary.
     *
     * These are unambiguous: there is no common, legitimate reason to let a
     * client mass-assign them, so they are flagged on sight at High.
     *
     * @var array<int, string>
     */
    private const SENSITIVE_EXACT = [
        'is_admin', 'admin', 'role', 'role_id', 'roles', 'is_superadmin',
        'is_super_admin', 'permissions', 'permission_id', 'plan_id',
        'balance', 'credits', 'wallet_balance', 'is_verified', 'verified',
        'email_verified_at', 'is_active', 'is_staff',
    ];

    /**
     * Field names that are AMBIGUOUS: extremely common, legitimately
     * mass-assignable columns (post type, ticket status, character level,
     * subscription tier) that are ONLY a privilege boundary in some apps.
     *
     * We flag these at Medium and only when a corroborating privilege signal
     * exists elsewhere in the same model (a sibling admin/role field or a cast
     * suggesting a privilege boolean). Otherwise we stay silent to keep the
     * false-positive rate low — the product's core value proposition.
     *
     * @var array<int, string>
     */
    private const AMBIGUOUS_PRIVILEGE = [
        'status', 'type', 'active', 'level', 'tier', 'plan',
        'account_type', 'user_type',
    ];

    /**
     * Sibling field names that, when present in the SAME $fillable, indicate the
     * model carries a privilege boundary — corroborating signal for ambiguous
     * fields.
     *
     * @var array<int, string>
     */
    private const PRIVILEGE_SIBLINGS = [
        'is_admin', 'admin', 'is_superadmin', 'is_super_admin', 'is_staff',
        'role', 'role_id', 'roles', 'permissions', 'permission_id',
    ];

    /**
     * Ownership/identity fields that let an attacker reassign a record's owner.
     *
     * @var array<int, string>
     */
    private const OWNERSHIP_FIELDS = [
        'user_id', 'owner_id', 'author_id', 'account_id', 'team_id',
        'organization_id', 'org_id', 'company_id', 'tenant_id', 'customer_id',
    ];

    public function detect(array $files, AccessControlContext $context): array
    {
        $findings = [];

        foreach ($files as $file) {
            if (! $this->looksLikeModel($file)) {
                continue;
            }

            $fillable = $this->parseArrayProperty($file->content, 'fillable');

            if ($fillable === []) {
                continue;
            }

            $guarded = $this->parseArrayProperty($file->content, 'guarded');

            if (in_array('*', $guarded, true)) {
                continue;
            }

            foreach ($fillable as $field) {
                $normalized = strtolower(trim($field));

                if ($normalized === '' || $normalized === '*') {
                    continue;
                }

                if (in_array($normalized, $guarded, true)) {
                    continue;
                }

                [$isSensitive, $reason, $severity] = $this->classify($normalized, $file->content, $fillable);

                if (! $isSensitive) {
                    continue;
                }

                $findings[] = new Vulnerability(
                    type: VulnerabilityType::MassAssignment,
                    location: $file->path,
                    line: $this->lineForField($file, $field),
                    severity: $severity,
                    description: sprintf(
                        "Model %s lists '%s' in \$fillable. %s Because this column is mass-assignable, an attacker can set it by adding \"%s\" to the request body of any create/update that calls fill()/create()/update() with request input.",
                        $file->className() ?? 'model',
                        $field,
                        $reason,
                        $field,
                    ),
                    proof: sprintf("\$fillable contains '%s' with no compensating \$guarded entry, mutator, or authorization gate on assignment.", $field),
                    fix: sprintf(
                        "Remove '%s' from \$fillable and assign it explicitly only after an authorization check (e.g. \$model->%s = \$request->validated('%s') guarded by \$this->authorize(...)), or move it into \$guarded.",
                        $field,
                        $field,
                        $field,
                    ),
                );
            }
        }

        return $findings;
    }

    /**
     * Classify a field as sensitive and return [bool, reason, severity].
     *
     * @param  array<int, string>  $fillable  All fillable fields (for corroboration)
     * @return array{0: bool, 1: string, 2: SeverityLevel}
     */
    private function classify(string $field, string $content, array $fillable): array
    {
        if (in_array($field, self::SENSITIVE_EXACT, true)) {
            return [
                true,
                'This is a privilege/identity attribute that governs authorization.',
                SeverityLevel::High,
            ];
        }

        if (in_array($field, self::AMBIGUOUS_PRIVILEGE, true)) {
            if (! $this->hasCorroboratingPrivilegeSignal($field, $content, $fillable)) {
                return [false, '', SeverityLevel::Medium];
            }

            return [
                true,
                'This attribute commonly maps to a privilege boundary, and this model carries a corroborating privilege signal (a sibling admin/role field or a privilege cast), so mass-assigning it may allow escalation.',
                SeverityLevel::Medium,
            ];
        }

        if (in_array($field, self::OWNERSHIP_FIELDS, true)) {
            if ($this->hasAssignmentGuardFor($field, $content)) {
                return [false, '', SeverityLevel::Medium];
            }

            return [
                true,
                'This is an ownership/identity foreign key; making it mass-assignable lets an attacker reassign the record to (or impersonate) another owner.',
                SeverityLevel::High,
            ];
        }

        if (preg_match('/^is_/', $field) || preg_match('/_admin$/', $field) || preg_match('/^can_/', $field)) {
            return [
                true,
                'The naming convention (is_*/*_admin/can_*) indicates a boolean privilege flag.',
                SeverityLevel::High,
            ];
        }

        if (preg_match('/^subscription/', $field) || $field === 'subscribed' || preg_match('/_credits$/', $field)) {
            return [
                true,
                'This attribute controls billing/subscription state.',
                SeverityLevel::Medium,
            ];
        }

        return [false, '', SeverityLevel::Medium];
    }

    /**
     * Whether an ambiguous field (status/type/level/tier/plan) is corroborated
     * as a real privilege boundary by other signals in the same model.
     *
     * Signals: a sibling unambiguous privilege field in $fillable
     * (is_admin/role/*_admin/etc.), or a cast that types this field as a
     * privilege-style boolean.
     *
     * @param  array<int, string>  $fillable
     */
    private function hasCorroboratingPrivilegeSignal(string $field, string $content, array $fillable): bool
    {
        foreach ($fillable as $sibling) {
            $normalizedSibling = strtolower(trim($sibling));

            if ($normalizedSibling === $field) {
                continue;
            }

            if (in_array($normalizedSibling, self::PRIVILEGE_SIBLINGS, true)) {
                return true;
            }

            if (preg_match('/^is_/', $normalizedSibling)
                || preg_match('/_admin$/', $normalizedSibling)
                || preg_match('/^can_/', $normalizedSibling)) {
                return true;
            }
        }

        return $this->hasPrivilegeCast($field, $content);
    }

    /**
     * Whether the model casts the given field as a boolean (suggesting it is a
     * privilege flag rather than a free-text status/type column).
     */
    private function hasPrivilegeCast(string $field, string $content): bool
    {
        $casts = $this->parseCasts($content);
        $cast = $casts[$field] ?? null;

        return $cast === 'boolean' || $cast === 'bool';
    }

    /**
     * Parse a simple $casts array into [field => cast-type], lowercased keys.
     *
     * @return array<string, string>
     */
    private function parseCasts(string $content): array
    {
        if (! preg_match('/\$casts\s*=\s*\[(.*?)\]/s', $content, $match)) {
            return [];
        }

        $casts = [];

        if (preg_match_all("/['\"]([^'\"]+)['\"]\s*=>\s*['\"]([^'\"]+)['\"]/", $match[1], $pairs, PREG_SET_ORDER)) {
            foreach ($pairs as $pair) {
                $casts[strtolower(trim($pair[1]))] = strtolower(trim($pair[2]));
            }
        }

        return $casts;
    }

    /**
     * Whether the model defines a mutator that re-checks authorization for the
     * given field (a compensating control), e.g. set{Field}Attribute().
     */
    private function hasAssignmentGuardFor(string $field, string $content): bool
    {
        $studly = str_replace(' ', '', ucwords(str_replace('_', ' ', $field)));
        $mutator = 'set'.$studly.'Attribute';

        return str_contains($content, $mutator);
    }

    /**
     * Heuristic: a file is a model if classified as such or extends Model.
     */
    private function looksLikeModel(SourceFile $file): bool
    {
        if ($file->type === 'model') {
            return true;
        }

        return (bool) preg_match('/extends\s+(Model|Authenticatable)\b/', $file->content)
            || str_contains($file->content, 'Illuminate\\Database\\Eloquent\\Model');
    }

    /**
     * Resolve the line of a specific quoted field inside the $fillable array.
     */
    private function lineForField(SourceFile $file, string $field): int
    {
        $quoted = preg_quote($field, '/');

        if (preg_match('/[\'"]'.$quoted.'[\'"]/', $file->content, $m, PREG_OFFSET_CAPTURE)) {
            return $file->lineForOffset((int) $m[0][1]);
        }

        return $file->lineForNeedle('fillable');
    }

    /**
     * Parse a simple PHP string array property, lowercased, using bracket-depth.
     *
     * @return array<int, string>
     */
    private function parseArrayProperty(string $content, string $property): array
    {
        $escaped = preg_quote($property, '/');

        if (! preg_match('/\$'.$escaped.'\s*=\s*\[/s', $content, $match, PREG_OFFSET_CAPTURE)) {
            return [];
        }

        $start = (int) $match[0][1] + strlen($match[0][0]);
        $depth = 1;
        $pos = $start;
        $length = strlen($content);

        while ($pos < $length && $depth > 0) {
            if ($content[$pos] === '[') {
                $depth++;
            } elseif ($content[$pos] === ']') {
                $depth--;
            }
            $pos++;
        }

        $inner = substr($content, $start, $pos - $start - 1);
        $values = [];

        if (preg_match_all("/['\"]([^'\"]+)['\"]/", $inner, $valueMatches)) {
            foreach ($valueMatches[1] as $value) {
                $values[] = strtolower(trim($value));
            }
        }

        return $values;
    }
}
