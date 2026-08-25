# Missing Rate Limiting on Auth Endpoints (rate_limiting)

## What this check detects
Authentication endpoints (login, signup, password reset, etc.) that allow unlimited requests without rate limiting, enabling credential stuffing and brute force attacks.

## Detection methodology
1. Identifies auth endpoints from:
   - Forms with actions matching patterns: `/api/auth/`, `/auth/`, `/login`, `/signup`, `/register`, `/signin`, `/password`, `/reset`, `/forgot`, `/verify`, `/magic`, `/auth/v1/`
   - Links matching same patterns
   - API endpoints from recon matching patterns
2. Filters out denylist endpoints (signup, register, password reset — to avoid creating accounts/sending emails)
3. Sends 5 rapid `POST` requests with dummy credentials to each candidate endpoint
4. Checks for rate limiting indicators:
   - HTTP 429 (Too Many Requests)
   - `Retry-After` header (case-insensitive)
4. If no rate limiting AND ≥60% requests succeed (200/201/302/401/403/422) → finding

## Why it matters
- **Credential stuffing**: Attackers test millions of leaked username/password pairs against your login endpoint
- **Brute force**: Unlimited attempts allow guessing weak passwords
- **Account enumeration**: Response differences (404 vs 401) reveal valid usernames/emails
- **DoS**: Unlimited requests can overwhelm auth service

## Real-world impact
- Account takeover via credential stuffing (billions of credentials available from breaches)
- User lockout via deliberate failed login flooding
- Password reset spam / email bombing
- API quota exhaustion

## Recommended limits
| Endpoint | Recommended limit |
|----------|-------------------|
| Login | 5 requests / minute per IP |
| Password reset / forgot | 1 request / hour per email |
| Signup | 3 requests / hour per IP |
| MFA / verify | 10 requests / minute |
| Magic link | 2 requests / hour per email |

## Remediation
**Next.js (App Router):**
```typescript
// middleware.ts
import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, '1 m'),
})

export async function middleware(request: NextRequest) {
  if (request.nextUrl.pathname.startsWith('/api/auth/login')) {
    const ip = request.ip ?? 'anonymous'
    const { success } = await ratelimit.limit(ip)
    if (!success) return new Response('Too Many Requests', { status: 429 })
  }
}
```

**Express:**
```javascript
const rateLimit = require('express-rate-limit')

const loginLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5,
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
})

app.post('/api/auth/login', loginLimiter, loginHandler)
```

**Nginx:**
```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

location /api/auth/login {
  limit_req zone=login burst=3 nodelay;
  proxy_pass ...
}
```

**Supabase:** Dashboard → Auth → Rate Limits → enable and configure

## WSTG / ATT&CK mapping
- WSTG: AT01 - Testing for Authentication Schema, AT03 - Testing for Password Guessing
- ATT&CK: T1110 (Brute Force), T1110.004 (Credential Stuffing)