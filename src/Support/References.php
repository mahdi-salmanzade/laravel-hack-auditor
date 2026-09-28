<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Support;

/**
 * Authoritative reading for each vulnerability type.
 *
 * A finding that says "CWE-89" is only useful to someone who already knows
 * what CWE-89 is. Every finding carries a link to its CWE entry, plus the OWASP
 * Cheat Sheet for the type where a well-known one exists, so a reader can check
 * the claim against a source that is not this tool.
 *
 * Keyed off the type's string value (not an exhaustive enum match) so a type
 * added later simply gets the CWE link and no cheat sheet until one is mapped.
 */
final class References
{
    private const string CWE_URL = 'https://cwe.mitre.org/data/definitions/%d.html';

    private const string CHEAT_SHEET_URL = 'https://cheatsheetseries.owasp.org/cheatsheets/%s.html';

    /**
     * OWASP Cheat Sheet slug per vulnerability type value.
     *
     * Only sheets that directly address the flaw are listed; a vague match
     * would send readers to advice about a different problem.
     *
     * @var array<string, array{slug: string, title: string}>
     */
    private const array CHEAT_SHEETS = [
        'sql_injection' => ['slug' => 'SQL_Injection_Prevention_Cheat_Sheet', 'title' => 'OWASP SQL Injection Prevention Cheat Sheet'],
        'dynamic_column_injection' => ['slug' => 'SQL_Injection_Prevention_Cheat_Sheet', 'title' => 'OWASP SQL Injection Prevention Cheat Sheet'],
        'xss' => ['slug' => 'Cross_Site_Scripting_Prevention_Cheat_Sheet', 'title' => 'OWASP Cross Site Scripting Prevention Cheat Sheet'],
        'csrf' => ['slug' => 'Cross-Site_Request_Forgery_Prevention_Cheat_Sheet', 'title' => 'OWASP Cross-Site Request Forgery Prevention Cheat Sheet'],
        'mass_assignment' => ['slug' => 'Mass_Assignment_Cheat_Sheet', 'title' => 'OWASP Mass Assignment Cheat Sheet'],
        'idor' => ['slug' => 'Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet', 'title' => 'OWASP IDOR Prevention Cheat Sheet'],
        'auth_bypass' => ['slug' => 'Authorization_Cheat_Sheet', 'title' => 'OWASP Authorization Cheat Sheet'],
        'insecure_deserialization' => ['slug' => 'Deserialization_Cheat_Sheet', 'title' => 'OWASP Deserialization Cheat Sheet'],
        'open_redirect' => ['slug' => 'Unvalidated_Redirects_and_Forwards_Cheat_Sheet', 'title' => 'OWASP Unvalidated Redirects and Forwards Cheat Sheet'],
        'weak_password_hashing' => ['slug' => 'Password_Storage_Cheat_Sheet', 'title' => 'OWASP Password Storage Cheat Sheet'],
        'missing_validation' => ['slug' => 'Input_Validation_Cheat_Sheet', 'title' => 'OWASP Input Validation Cheat Sheet'],
        'ssrf' => ['slug' => 'Server_Side_Request_Forgery_Prevention_Cheat_Sheet', 'title' => 'OWASP SSRF Prevention Cheat Sheet'],
        'command_injection' => ['slug' => 'OS_Command_Injection_Defense_Cheat_Sheet', 'title' => 'OWASP OS Command Injection Defense Cheat Sheet'],
        'debug_mode_exposure' => ['slug' => 'Error_Handling_Cheat_Sheet', 'title' => 'OWASP Error Handling Cheat Sheet'],
        'insecure_cookie_config' => ['slug' => 'Session_Management_Cheat_Sheet', 'title' => 'OWASP Session Management Cheat Sheet'],
        'dependency_vulnerability' => ['slug' => 'Vulnerable_Dependency_Management_Cheat_Sheet', 'title' => 'OWASP Vulnerable Dependency Management Cheat Sheet'],
        'path_traversal' => ['slug' => 'File_Upload_Cheat_Sheet', 'title' => 'OWASP File Upload Cheat Sheet'],
        'insecure_file_upload' => ['slug' => 'File_Upload_Cheat_Sheet', 'title' => 'OWASP File Upload Cheat Sheet'],
        'xxe' => ['slug' => 'XML_External_Entity_Prevention_Cheat_Sheet', 'title' => 'OWASP XXE Prevention Cheat Sheet'],
    ];

    /**
     * Every reference for a type: the CWE entry first, then the cheat sheet.
     *
     * @return array<int, array{title: string, url: string}>
     */
    public static function for(VulnerabilityType $type): array
    {
        $references = [];

        $cweUrl = self::cweUrl($type);

        if ($cweUrl !== null) {
            $references[] = ['title' => $type->cweId(), 'url' => $cweUrl];
        }

        $sheet = self::CHEAT_SHEETS[$type->value] ?? null;

        if ($sheet !== null) {
            $references[] = ['title' => $sheet['title'], 'url' => sprintf(self::CHEAT_SHEET_URL, $sheet['slug'])];
        }

        return $references;
    }

    /**
     * The numeric CWE id for a type, or null when it has none.
     */
    public static function cweNumber(VulnerabilityType $type): ?int
    {
        if (preg_match('/CWE-(\d+)/i', $type->cweId(), $matches) !== 1) {
            return null;
        }

        return (int) $matches[1];
    }

    /**
     * The MITRE definition page for the type's CWE, or null when it has none.
     */
    public static function cweUrl(VulnerabilityType $type): ?string
    {
        $number = self::cweNumber($type);

        return $number === null ? null : sprintf(self::CWE_URL, $number);
    }
}
