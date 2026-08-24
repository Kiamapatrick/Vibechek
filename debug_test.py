import asyncio
from vibeshield.scanner.checks.supabase_firebase import SupabaseFirebaseCheck
from vibeshield.models.recon import ReconData
from unittest.mock import AsyncMock, MagicMock
import base64
import json

def make_anon_key():
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"role": "anon", "iss": "supabase"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = "fake_signature"
    return f"{header_b64}.{payload_b64}.fake_signature"

async def test():
    check = SupabaseFirebaseCheck()
    check.allow_write_tests = False
    
    recon = ReconData(target_url="https://example.com", base_url="https://example.com", pages=[])
    anon_key = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJyb2xlIjogImFub24iLCAiaXNzIjogInN1cGFiYXNlIn0.fake_signature"
    
    print("anon_key recognized:", check._is_supabase_anon_key(anon_key))
    
    mock_http = AsyncMock()
    mock_http.get = AsyncMock()
    mock_http.get.return_value = MagicMock(
        status_code=200,
        text='[{"id": 1, "email": "user@example.com"}]',
        headers={}
    )
    
    findings = await check._check_supabase(anon_key, recon, mock_http)
    print("Findings:", len(findings))
    for f in findings:
        print("  -", f.title, f.severity)

asyncio.run(test())