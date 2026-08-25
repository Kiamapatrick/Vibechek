# Outdated Dependencies with Known Vulnerabilities (outdated_deps)

## What this check detects
JavaScript dependencies in `package.json` (or inline `importmap`, `package.json` in scripts) that have known vulnerabilities per the OSV/GitHub Advisory database.

## Detection methodology
1. Extracts dependencies from:
   - `package.json` files found in crawled pages
   - Inline `importmap` with `imports`/`dependencies`
   - JavaScript bundle analysis (best-effort)
2. For each `name@version`, queries OSV.dev API for vulnerabilities
3. Compares installed version against affected version ranges

## Severity mapping
| OSV Severity | VibeShield Severity |
|--------------|---------------------|
| CRITICAL | Critical |
| HIGH | High |
| MODERATE | Medium |
| LOW | Low |

## Why it matters
Supply chain attacks are increasing. A single vulnerable dependency (e.g., `lodash@4.17.20` prototype pollution, `axios@0.21.1` SSRF) can compromise the entire application. Modern apps have 500+ transitive deps; manual tracking is impossible.

## Common high-impact vulnerable packages
| Package | Vulnerability | Impact |
|---------|---------------|--------|
| `lodash` < 4.17.21 | Prototype pollution → RCE in Node | Critical |
| `axios` < 0.21.2 | SSRF via `http.adapter` | High |
| `moment` < 2.29.2 | ReDoS via `preparseRFC2822` | Medium |
| `minimist` < 1.2.6 | Prototype pollution | High |
| `node-fetch` < 2.6.7 | Exposure of `file:` protocol | Medium |
| `jsonwebtoken` < 9.0.0 | Key confusion / algorithm confusion | Critical |

## Remediation
1. **Immediate**: `npm audit fix` or `yarn audit fix` for automated patches
2. **Manual**: Update to latest non-vulnerable major version (check changelog for breaking changes)
3. **If no fix exists**: 
   - Assess exploitability in *your* codepath (not all CVEs are exploitable in context)
   - Consider fork/patch or alternative package
   - Add to `package.json` `overrides` / `resolutions` to force patched transitive dep
4. **Prevention**: 
   - Enable Dependabot / Renovate for automated PRs
   - `npm audit` in CI pipeline (fail on high/critical)
   - Pin dependencies to exact versions (not `^` or `~`) in production lockfile

## WSTG / ATT&CK mapping
- WSTG: WSTG-CONF-06
- ATT&CK: T1190