Good — this one's read-only (only http.get, no writes), so it's fine safety-wise, though I'd note the false-positive risk is high: _looks_like_sensitive_data flags anything with content-type: application/json, and _has_auth_indicators only checks Set-Cookie/WWW-Authenticate — it'll miss Bearer-token-in-header or Supabase JWT-in-body auth entirely, so it could easily flag correctly-protected endpoints as vulnerable. Worth knowing, but not urgent like the Supabase write issue.

Here's exactly what to change in supabase_firebase.py and cli.py — you write it, I'll review after.

The fix, step by step

1. Add a new CLI flag in cli.py, next to confirm_ownership (around line 41-42):

python
allow_write_tests: bool = typer.Option(
    False, "--allow-write-tests",
    help="Allow checks that write test data (e.g. Supabase RLS insert probe). Off by default.",
),

Then pass it through to wherever the scan engine gets constructed/called (look for where confirm_ownership currently flows into the scan — allow_write_tests needs to follow the same path, probably into ScannerEngine or a config/context object, since checks need access to it).

2. Trace how config reaches checks. Open scanner/engine.py and config.py — find how ReconData/HTTPClient or some shared context gets passed into check.run(recon, http). You'll likely need to either add a field to ReconData, or add a third parameter to BaseCheck.run(). Simplest: add allow_write_tests: bool = False as an attribute on whatever config/context object already flows through — check config.py first, since a global settings object is the cleanest place for a flag like this.

3. In supabase_firebase.py, change _test_supabase_rls (lines 81-157):

Replace the POST attempt with a GET first: resp = await http.get(f"{base_url}/rest/v1/{table}", headers=headers, timeout=5.0). A 200 with actual row data back is already sufficient evidence of an RLS read bypass — that's your existing elif resp.status_code == 200 branch (lines 127-154), just make it the primary path instead of the fallback.
Wrap the existing POST block (lines 90-126) in a check against your new flag — something like if self.allow_write_tests: — so it only runs when explicitly enabled. You'll need allow_write_tests accessible on self (the check instance), which means passing it in via __init__ or wherever checks get instantiated (look at engine.py for where SupabaseFirebaseCheck() gets created).
Update the docstring/description and the CLI help text to be explicit that write-tests are opt-in and why.

4. Add a warning message printed when --allow-write-tests is used — similar to the existing ownership warning in cli.py around line 73 — something like: "This will attempt to insert test data into discovered database tables. Only use this against systems you own."

5. Write a test for it — this is also your chance to close the coverage gap. A test that mocks http.get returning a row with data (should produce a HIGH finding) and one where allow_write_tests=False and a POST would have succeeded but never gets called (assert the mock's post was never invoked). That second test is actually the important one — it proves the safety gate works, not just that detection works.