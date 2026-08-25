# Exposed Secrets (exposed_secrets)

## What this check detects
Client-side JavaScript and HTML that contains API keys, tokens, credentials, or other secrets that should never be in browser-accessible code.

## Common patterns found
- AWS access/secret keys (`AKIA...`, `aws_secret_key=...`)
- GitHub personal access tokens (`ghp_...`, `github_token=...`)
- Stripe keys (`sk_live_...`, `pk_live_...`)
- Slack tokens (`xoxb-...`, `xoxp-...`)
- Twilio SIDs and auth tokens
- Supabase anon keys (JWT with `role: "anon"`)
- Firebase config objects with project IDs
- Generic API key assignments (`api_key = "..."`, `API_KEY: "..."`)
- `.env` files accidentally served publicly

## Why it matters
Any secret in client-side code is fully exposed to anyone who views the page source or inspects network requests. Attackers routinely scrape GitHub, npm, and live websites for these patterns. A single exposed AWS key can lead to full account compromise, crypto mining charges, or data exfiltration.

## Real-world impact
- AWS keys → full infrastructure access, massive billing
- GitHub tokens → repo access, supply chain attacks
- Stripe keys → payment fraud, customer data theft
- Database credentials → data breach

## Remediation
1. **Immediate**: Rotate the exposed key/secret in the provider's dashboard
2. **Root cause**: Move all secrets to server-side environment variables
3. **Build-time**: Use build-time substitution (Next.js `next.config.js`, Vite `import.meta.env`, Webpack `DefinePlugin`) for values that *must* be in the client bundle (e.g., public Stripe publishable key, Supabase anon key)
4. **Prevention**: Add secret scanning to CI (GitHub Secret Scanning, TruffleHog, git-secrets), use `.gitignore` for `.env*`, never commit secrets

## WSTG / ATT&CK mapping
- WSTG: WSTG-INFO-02
- ATT&CK: T1552.001