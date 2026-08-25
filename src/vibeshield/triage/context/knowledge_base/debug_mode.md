# Debug Mode & Verbose Errors (debug_mode)

## What this check detects
Debug features accidentally left enabled in production: verbose error pages, exposed debug endpoints, accessible source maps, debug headers.

## Detection categories

### 1. Verbose error pages
Requests `/nonexistent-page-12345` and `/api/nonexistent-12345` (404/500 responses). Flags if response contains:
- Stack traces (`stack trace`, `traceback`, `at functionName(`)
- Source file paths (`file "path", line N`)
- Exception details (`Exception:`, `Error in /`)
- Debug flags (`debug=true`, `NEXT_DEBUG`)
- Webpack internals (`__webpack_require__`, `module.exports`)

### 2. Exposed debug endpoints
Checks common debug paths: `/debug`, `/actuator`, `/health`, `/metrics`, `/_debug`, `/api/debug`, `/wp-json`, `/.well-known/`, `/server-status`, `/server-info`, `/admin/debug`, `/debug/vars`, `/debug/pprof`, `/graphql?debug`, `/console`, `/repl`, `/shell`, `/rails/info`, `/phpinfo`, `/info`, `/status`, `/metrics/prometheus`

### 3. Accessible source maps
For every `.js` script found, checks if `<script>.map` is accessible (HTTP 200)

### 4. Debug headers
Flags headers that leak debug info:
- `X-Debug-Token`
- `X-Drupal-Cache`
- `X-Powered-By` containing "debug"

## Why it matters
- **Stack traces** reveal internal code structure, library versions, file paths → aids exploit development
- **Debug endpoints** often have elevated privileges, no auth, or expose internal state
- **Source maps** let attackers reconstruct original TypeScript/React source → find secrets, logic flaws
- **Debug headers** fingerprint framework/version for targeted attacks

## Common causes
- `NODE_ENV=development` in production
- `NEXT_DEBUG=1` or `DEBUG=*` env vars set
- `NEXT_PUBLIC_DEBUG=true` in build
- Webpack `devtool: 'source-map'` in production config
- Django `DEBUG=True`
- Rails `config.consider_all_requests_local = true`
- Laravel `APP_DEBUG=true`

## Remediation
**Next.js:**
```js
// next.config.js
module.exports = {
  productionBrowserSourceMaps: false,
  // Ensure NODE_ENV=production at build/runtime
}
```

**Webpack:**
```js
// webpack.config.js
module.exports = {
  mode: 'production',
  devtool: false, // or 'hidden-source-map' for error tracking only
}
```

**General:**
- Set `NODE_ENV=production` (or framework equivalent) in production
- Remove `DEBUG`, `NEXT_DEBUG`, `APP_DEBUG` env vars from production
- Use custom error pages (Next.js: `pages/_error.js`, Express: `app.use(errorHandler)`)
- Strip source maps from production builds or host them privately (Sentry, Datadog)

## WSTG / ATT&CK mapping
- WSTG: IG04 - Enumerate Applications on Webserver, SM01 - Testing for Bypassing Authorization Schema
- ATT&CK: T1590 (Active Scanning), T1083 (File and Directory Discovery)