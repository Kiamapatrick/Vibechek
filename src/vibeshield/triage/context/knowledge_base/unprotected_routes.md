# Unprotected API Routes (unprotected_routes)

## What this check detects
API endpoints that return sensitive data (user info, orders, payments, admin data) without requiring authentication.

## Detection logic
1. Crawler discovers API endpoints from links, scripts, forms, and API patterns (`/api/`, `/graphql`, `/rest/`, `/v1/`, `/v2/`, `/auth/`, `/user`, `/account`, `/profile`, `/settings`, `/admin`)
2. Makes unauthenticated `GET` request to each endpoint
3. Flags endpoint if:
   - Response is `2xx` or `3xx`
   - Response is JSON or contains sensitive keywords (user, email, id, token, session, orders, billing, payment, admin, dashboard)
   - No authentication indicators present (no `Set-Cookie` with session/auth, no `WWW-Authenticate`, no `Authorization: Bearer` in response, no access_token/session/id_token in JSON body)

## Why it matters
Modern frameworks (Next.js, Remix, Astro, SvelteKit) make it easy to create API routes. It's equally easy to forget middleware/auth guards on routes that should be protected. A single unprotected `/api/user/profile` or `/api/orders` leaks PII or financial data.

## Common framework blind spots
- **Next.js**: Forgot `export const middleware = authMiddleware` or `getServerSession` in route handler
- **Express**: Missing `requireAuth` middleware on route group
- **FastAPI**: Missing `Depends(get_current_user)` on endpoint
- **Supabase/PostgREST**: RLS enabled but policies allow `anon` role

## Real-world impact
- User PII harvest (emails, names, phones, addresses)
- Order history / payment method enumeration
- Admin panel data exposure
- Account takeover via password reset token leakage

## Remediation
1. **Audit**: List all API routes, mark which require auth
2. **Middleware**: Centralize auth check
   - Next.js: `middleware.ts` with `auth()` check
   - Express: `app.use('/api/', requireAuth)`
   - FastAPI: `Depends(get_current_user)` on protected routes
   - Supabase: RLS policies requiring `auth.role() = 'authenticated'`
3. **Test**: Automated check in CI that hits protected endpoints without auth → expects 401/403

## WSTG / ATT&CK mapping
- WSTG: AT01 - Testing Directory Traversal/File Include, AT02 - Testing Authorization Bypass
- ATT&CK: T1552 (Unsecured Credentials), T1005 (Data from Local System)