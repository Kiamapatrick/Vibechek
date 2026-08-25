# Permissive CORS Configuration (cors)

## What this check detects
API endpoints that reflect arbitrary origins or allow credentials with wildcard origins, enabling cross-origin attacks.

## Test methodology
Sends `OPTIONS` (preflight) request with `Origin: https://evil.com` to discovered API endpoints. Falls back to `GET` with same origin if OPTIONS fails.

## Findings categories
| Finding | Condition | Severity |
|---------|-----------|----------|
| CORS allows credentials with wildcard | `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` | Critical |
| CORS reflects arbitrary origin with credentials | `ACAO: https://evil.com` + `ACAC: true` | Critical |
| CORS wildcard on API endpoint | `ACAO: *` (no credentials) | Medium |
| CORS origin reflection | `ACAO` reflects request `Origin` | High |

## Why it matters
- **Wildcard + credentials**: Browser blocks this combo, but its presence signals fundamental misunderstanding of CORS
- **Origin reflection**: Attacker's site can make authenticated requests to your API on behalf of a logged-in user (CSRF via CORS)
- **Wildcard on API**: Any site can read your API responses (data leakage)

## Real-world impact
- Account takeover via CSRF (if origin reflection + credentials)
- Data theft via malicious site reading API responses
- API abuse (rate limit bypass, unauthorized actions)

## Remediation
**Never** use `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` — browsers reject it.

**Use explicit allowlist:**
```python
# Python/Flask/FastAPI example
ALLOWED_ORIGINS = ["https://app.example.com", "https://admin.example.com"]

@app.middleware("http")
async def cors_middleware(request, call_next):
    origin = request.headers.get("origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
```

**Framework-specific:**
- Next.js: `next.config.js` → `async headers()` with explicit origins
- Express: `cors({ origin: ALLOWED_ORIGINS, credentials: true })`
- FastAPI: `CORSMiddleware(app, allow_origins=ALLOWED_ORIGINS, allow_credentials=True)`
- Nginx: `add_header Access-Control-Allow-Origin $http_origin` with `map` for validation
- Supabase: Dashboard → API → CORS settings → add exact origins

## WSTG / ATT&CK mapping
- WSTG: CT07 - Testing Cross-Origin Resource Sharing
- ATT&CK: T1550 (Use Alternate Authentication Material), T1190 (Exploit Public-Facing Application)