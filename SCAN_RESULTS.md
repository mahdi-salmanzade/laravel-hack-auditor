# Scan Results — Real-World Test

**Scanned:** X Backend (Laravel 12, 42 controllers, production app)
**Provider:** Anthropic Claude Opus 4.6
**Command:** `php artisan hack:scan --path=app/Http/Controllers/Api/AuthController.php`
**Date:** 2026-03-20
**Scan Duration:** ~32 seconds

---

## Score: 35/100

```
╔═══════════════════════╗
║   Security Score      ║
║       35/100          ║
╚═══════════════════════╝
```

**Found 7 vulnerabilities: 1 Critical, 2 High, 3 Medium, 1 Low**

---

## Summary

The application has several significant security issues. The most critical is a test endpoint (`getTestOtp`) that generates and exposes valid OTP codes for a hardcoded email, allowing full account takeover if accessible in production. Authentication endpoints (`sendMagicLink`, `verifyCode`, `socialAuth`) lack rate limiting, making the 6-digit OTP susceptible to brute-force attacks. Sensitive data is logged (OTP codes in failed verification attempts), user enumeration is possible via the `checkEmail` endpoint which also leaks user names, and the `redirect_to` parameter is not validated against a whitelist, enabling potential open redirect attacks via the magic link flow.

---

## Vulnerabilities

### 1. CRITICAL — Sensitive Data Exposure

**Location:** `app/Http/Controllers/Api/AuthController.php:139`
**OWASP:** A02:2021 - Cryptographic Failures

The `getTestOtp()` endpoint generates a real magic link/OTP and returns the secret code in the JSON response. If this route is accessible in production, any attacker can obtain a valid OTP for the hardcoded email address and authenticate as that user without access to their email inbox.

**Vulnerable Code:**
```php
public function getTestOtp(): JsonResponse
{
    $email = 'xxxxxx@gmail.com';
    $loginToken = MagicLinkController::sendMagicLink($email);

    return response()->json([
        'success' => true,
        'email' => $email,
        'code' => $loginToken->code,
        'expires_at' => $loginToken->expires_at?->toIso8601String(),
        'message' => 'Use this code with POST /auth/verify-code to obtain a token.',
    ]);
}
```

**Fix:**
```php
public function getTestOtp(): JsonResponse
{
    if (!app()->environment('local', 'testing')) {
        abort(404);
    }

    $email = 'xxxxxx@gmail.com';
    $loginToken = MagicLinkController::sendMagicLink($email);

    return response()->json([
        'success' => true,
        'email' => $email,
        'code' => $loginToken->code,
        'expires_at' => $loginToken->expires_at?->toIso8601String(),
        'message' => 'Use this code with POST /auth/verify-code to obtain a token.',
    ]);
}
```

---

### 2. HIGH — Missing Rate Limiting (sendMagicLink)

**Location:** `app/Http/Controllers/Api/AuthController.php:26`
**OWASP:** A04:2021 - Insecure Design

The `sendMagicLink` endpoint does not appear to have rate limiting. An attacker could abuse this to spam magic link emails to any address (email bombing) or to enumerate waitlisted emails via the different error responses.

**Fix:**
```php
// In routes/api.php, apply throttle middleware to the route:
Route::post('/auth/send-magic-link', [AuthController::class, 'sendMagicLink'])
    ->middleware('throttle:5,1'); // 5 attempts per minute
```

---

### 3. HIGH — Missing Rate Limiting (verifyCode)

**Location:** `app/Http/Controllers/Api/AuthController.php:78`
**OWASP:** A04:2021 - Insecure Design

The `verifyCode` endpoint lacks rate limiting. Since the OTP is a 6-digit code, an attacker could brute-force it within the token's validity window. Without rate limiting, all 1,000,000 combinations could be tried rapidly.

**Fix:**
```php
// In routes/api.php, apply strict throttle middleware to the route:
Route::post('/auth/verify-code', [AuthController::class, 'verifyCode'])
    ->middleware('throttle:5,1'); // 5 attempts per minute
```

---

### 4. MEDIUM — Sensitive Data Exposure (OTP in logs)

**Location:** `app/Http/Controllers/Api/AuthController.php:93`
**OWASP:** A02:2021 - Cryptographic Failures

The `verifyCode` method logs the actual OTP code from the database when verification fails. This exposes valid OTP codes in log files, which could be accessed by anyone with log access, enabling authentication bypass.

**Vulnerable Code:**
```php
\Log::warning('Code verification failed', [
    'email' => $email,
    'code_provided' => $code,
    'existing_token' => LoginToken::where('email', $email)
        ->latest('created_at')
        ->first()?->only(['code', 'expires_at', 'used_at', 'created_at']),
]);
```

**Fix:**
```php
\Log::warning('Code verification failed', [
    'email' => $email,
    'existing_token' => LoginToken::where('email', $email)
        ->latest('created_at')
        ->first()?->only(['expires_at', 'used_at', 'created_at']),
]);
```

---

### 5. MEDIUM — Missing Rate Limiting (socialAuth)

**Location:** `app/Http/Controllers/Api/AuthController.php:233`
**OWASP:** A04:2021 - Insecure Design

The `socialAuth` endpoint lacks rate limiting. An attacker could repeatedly send requests with different Firebase tokens to probe for valid accounts or abuse the waitlist code verification logic.

**Fix:**
```php
// In routes/api.php, apply throttle middleware:
Route::post('/auth/social', [AuthController::class, 'socialAuth'])
    ->middleware('throttle:10,1'); // 10 attempts per minute
```

---

### 6. MEDIUM — Open Redirect

**Location:** `app/Http/Controllers/Api/AuthController.php:131`
**OWASP:** A01:2021 - Broken Access Control

The `verifyCode` response returns the user-supplied `redirect_to` value (stored via `sendMagicLink` from user input) back to the client. If the frontend blindly follows this redirect URL, an attacker can craft a magic link with a malicious `redirect_to` pointing to a phishing site. The `redirect_to` field has no URL validation or whitelist check.

**Fix:**
```php
// In the sendMagicLink method, validate redirect_to against allowed paths:
$request->validate([
    'email' => 'required|email',
    'redirect_to' => ['nullable', 'string', function ($attribute, $value, $fail) {
        $parsed = parse_url($value);
        // Only allow relative paths (no host)
        if (isset($parsed['host'])) {
            $fail('The redirect_to must be a relative path.');
        }
    }],
    'waitlist_code' => 'nullable|string|size:6',
]);
```

---

### 7. LOW — Sensitive Data Exposure (User Enumeration)

**Location:** `app/Http/Controllers/Api/AuthController.php:193`
**OWASP:** A02:2021 - Cryptographic Failures

The `checkEmail` endpoint confirms whether an email address belongs to a registered user and leaks the user's name. This enables user enumeration and can be used for targeted phishing or social engineering attacks.

**Vulnerable Code:**
```php
return response()->json([
    'exists' => $user !== null,
    'name' => $user?->name,
]);
```

**Fix:**
```php
return response()->json([
    'exists' => $user !== null,
]);
```

---

## CTF Idea

> **"OTP Heist"** — Exploit the `/auth/test-otp` endpoint to steal a valid magic code and hijack an account.

---

## What This Proves

This scan ran against a **real production Laravel backend** with 42 API controllers. Key takeaways:

1. **The AI found real vulnerabilities** — The `getTestOtp` endpoint is a genuine critical issue that could allow account takeover
2. **Contextual analysis works** — Static tools wouldn't flag "this test endpoint returns a real OTP code" because it requires understanding the business logic
3. **Actionable fixes** — Every finding includes copy-paste code to fix the issue
4. **No false positives** — All 7 findings are legitimate security concerns
5. **Fast** — Single controller scanned in ~32 seconds

---

*Generated by [Laravel Hack Auditor](https://github.com/mahdi-abazar/laravel-hack-auditor) using Anthropic Claude Opus 4.6*
