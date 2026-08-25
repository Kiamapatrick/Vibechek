# Cross-Cutting Patterns (patterns)

This document covers patterns that appear across multiple checks — framework-specific auth, deployment configs, and common misconfigurations that enable multiple vulnerability classes.

## Next.js Auth Patterns

### Middleware-based protection (App Router)
```typescript
// middleware.ts
import { auth } from '@/lib/auth' // or next-auth, clerk, supabase

export async function middleware(request: NextRequest) {
  const session = await auth()
  const protectedPaths = ['/api/user', '/api/admin', '/dashboard', '/settings']
  
  if (protectedPaths.some(p => request.nextUrl.pathname.startsWith(p))) {
    if (!session) {
      return NextResponse.redirect(new URL('/login', request.url))
    }
  }
}

export const config = {
  matcher: ['/api/:path*', '/dashboard/:path*', '/settings/:path*'],
}
```

### Route handler protection (Pages Router / App Router)
```typescript
// app/api/user/profile/route.ts
import { getServerSession } from 'next-auth'
import { authOptions } from '@/lib/auth'

export async function GET() {
  const session = await getServerSession(authOptions)
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  
  // ... fetch user data
}
```

### Common Next.js misconfigurations that bypass auth
| Misconfiguration | Effect |
|------------------|--------|
| Missing `matcher` in middleware | Middleware doesn't run on API routes |
| `NEXT_PUBLIC_` prefix on secret | Secret exposed to client bundle |
| `dangerouslySetInnerHTML` with user data | XSS bypassing CSP |
| `next.config.js` `images.remotePatterns` too permissive | Image proxy abuse |

## Supabase RLS Patterns

### Minimal secure policies
```sql
-- Enable RLS
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Users can only see their own row
CREATE POLICY "Users view own data" ON users
  FOR SELECT USING (auth.uid() = id);

-- Users can only update their own row
CREATE POLICY "Users update own data" ON users
  FOR UPDATE USING (auth.uid() = id);

-- Service role bypasses RLS (for admin/api routes)
-- Use `supabase.auth.admin` or service role key server-side only
```

### Common RLS mistakes
| Mistake | Why it fails |
|---------|--------------|
| `FOR ALL USING (true)` | Disables RLS entirely |
| Missing policy on `INSERT` | Anon can create rows |
| Policy uses `auth.uid()` but table has no `user_id` column | Policy never matches |
| RLS enabled but no policies | Default deny (good) but app breaks |

## Environment Variable Patterns

### Safe vs unsafe prefixes
| Prefix | Exposure | Use for |
|--------|----------|---------|
| `NEXT_PUBLIC_` | Client bundle | Public IDs, publishable keys |
| `VITE_` | Client bundle | Public config |
| (no prefix) | Server only | Secrets, private keys, DB URLs |

### Common secret leakage vectors
- `.env` committed to git
- `.env.local` / `.env.production` in Docker image
- CI/CD logs printing env vars
- `console.log(process.env)` in client code
- Next.js `next.config.js` `env:` or `publicRuntimeConfig` including secrets

## Deployment Config Patterns

### Vercel / Netlify / Cloudflare Pages
- Environment variables in dashboard → only injected at build/runtime
- Preview deployments inherit production env vars unless overridden
- `VERCEL_ENV=production` / `CONTEXT=production` for conditional logic

### Docker
```dockerfile
# BAD: secrets baked into image
ENV DATABASE_URL=postgres://user:pass@host/db

# GOOD: secrets at runtime
# docker run -e DATABASE_URL=... image
# or use Docker secrets / Kubernetes secrets
```

### Kubernetes
```yaml
# GOOD: secret reference
env:
  - name: DATABASE_URL
    valueFrom:
      secretKeyRef:
        name: app-secrets
        key: database-url
```

## Framework-Specific Debug Leakage

| Framework | Debug env var | Production value |
|-----------|---------------|------------------|
| Next.js | `NODE_ENV`, `NEXT_DEBUG` | `production`, unset |
| Vite | `NODE_ENV`, `VITE_DEBUG` | `production`, unset |
| Django | `DEBUG` | `False` |
| Rails | `RAILS_ENV`, `config.consider_all_requests_local` | `production`, `false` |
| Laravel | `APP_DEBUG`, `APP_ENV` | `false`, `production` |
| Express | `NODE_ENV` | `production` |
| FastAPI | `DEBUG` | `False` |
| Spring Boot | `spring.profiles.active` | `prod` |

## CSP Construction Pattern

### Step-by-step CSP building
1. Start restrictive: `default-src 'self';`
2. Add script sources: `script-src 'self' https://cdn.example.com;`
3. Add style sources: `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;`
4. Add image sources: `img-src 'self' data: https://*.example.com;`
5. Add font sources: `font-src 'self' https://fonts.gstatic.com;`
6. Add connect sources: `connect-src 'self' https://api.example.com wss://ws.example.com;`
7. Add frame-ancestors: `frame-ancestors 'none';` (or `'self'` if you iframe yourself)
8. Report-only first: `Content-Security-Policy-Report-Only: ...` → monitor → enforce

### Nonce/hash for inline scripts
```html
<!-- Generate nonce per request -->
<script nonce="r4nd0mN0nc3">...</script>

<!-- CSP -->
script-src 'self' 'nonce-r4nd0mN0nc3';
```

## Error Handling Pattern (Safe by Default)

### Never expose internals in errors
```python
# BAD
@app.errorhandler(500)
def handle_error(e):
    return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500

# GOOD
@app.errorhandler(500)
def handle_error(e):
    log.exception("Internal error")  # Log full details server-side
    return jsonify({"error": "Internal server error"}), 500
```

### Custom error pages
- Return generic messages to client
- Log full details (stack trace, request context, user ID) server-side
- Include correlation ID for support debugging