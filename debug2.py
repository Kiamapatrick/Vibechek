import base64
import json

key = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJyb2xlIjogImFub24iLCAiaXNzIjogInN1cGFiYXNlIn0.fake_signature"

parts = key.split(".")
print("parts:", parts)
print("len:", len(parts))

payload = parts[1]
print("payload:", payload)

payload += "=" * (-len(payload) % 4)
print("padded payload:", payload)

decoded = base64.urlsafe_b64decode(payload).decode()
print("decoded:", decoded)
print("has anon role:", '"role":"anon"' in decoded)