# Missing Security Headers (security_headers)

## What this check detects
Missing or misconfigured HTTP security headers on the top 5 crawled pages.

## Headers checked
| Header | Purpose | Severity if missing |
|--------|---------|---------------------|
| `Content-Security-Policy` (CSP) | Prevents XSS, data injection, clickjacking | Medium |
| `Strict-Transport-Security` (HSTS) | Enforces HTTPS, prevents SSL stripping | Medium |
| `X-Frame-Options` | Prevents clickjacking via iframe embedding | Low |
| `X-Content-Type-Options: nosniff` | Prevents MIME type sniffing | Low |
| `Referrer-Policy` | Controls referrer information leakage | Info |
| `Permissions-Policy` | Controls browser feature access (camera, mic, geo) | Info |

## Additional checks
- **CSP `frame-ancestors`**: If CSP exists but lacks `frame-ancestors`, clickjacking protection is incomplete
- **Server header disclosure**: `Server` and `X-Powered-By` headers reveal framework/version (info disclosure)

## Why it matters
Security headers are defense-in-depth. They don't fix application bugs, but they limit the blast radius of XSS, prevent clickjacking, enforce HTTPS, and reduce information leakage. Missing CSP is the most impactful — it's the primary client-side XSS mitigation.

## Common misconfigurations
- CSP present but too permissive (`'unsafe-inline'`, `'unsafe-eval'`, `*`)
- HSTS without `includeSubDomains` or `preload`
- `X-Frame-Options: SAMEORIGIN` when framing is never needed (use `DENY`)
- CSP on `Content-Security-Policy-Report-Only` only (not enforced)

## Remediation
**CSP starter policy:**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';
```
Adjust per app needs (add CDN domains, analytics endpoints, etc.).

**HSTS:**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Others:**
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

**Remove server headers:**
- Nginx: `server_tokens off;`
- Express: `app.disable('x-powered-by')`
- Next.js: `poweredByHeader: false` in `next.config.js`

## WSTG / ATT&CK mapping
- WSTG: CT01 - Testing for Client-Side Cross-Site Scripting
- ATT&CK: T1190 (Exploit Public-Facing Application), T1550 (Use Alternate Authentication Material)