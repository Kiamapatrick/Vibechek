import re
from re import Pattern

SECRET_PATTERNS: list[tuple[str, Pattern]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key", re.compile(r"[A-Za-z0-9/+=]{40}")),
    ("github_token", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("github_oauth", re.compile(r"gho_[A-Za-z0-9]{36}")),
    ("github_app", re.compile(r"ghs_[A-Za-z0-9]{36}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("stripe_key", re.compile(r"sk_live_[A-Za-z0-9]{24}")),
    ("stripe_publishable", re.compile(r"pk_live_[A-Za-z0-9]{24}")),
    ("sendgrid_key", re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}")),
    ("twilio_sid", re.compile(r"AC[a-f0-9]{32}")),
    ("twilio_token", re.compile(r"[a-f0-9]{32}")),
    ("firebase_config", re.compile(r"firebaseConfig\s*=\s*\{[^}]*apiKey\s*:\s*[\"'][^\"']+[\"']")),
    ("supabase_key", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("generic_api_key", re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[\"'][^\"']{16,}[\"']")),
    ("env_assignment", re.compile(r"(?m)^[A-Z_][A-Z0-9_]*\s*=\s*[^\s#]+")),
    ("private_key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

FRAMEWORK_PATTERNS: list[tuple[str, Pattern]] = [
    ("nextjs", re.compile(r"(?i)(__NEXT_DATA__|_next/static|_next/data|next\.js|next/router)")),
    ("remix", re.compile(r"(?i)(remix|__remix_)")),
    ("astro", re.compile(r"(?i)(astro|_astro)")),
    ("vite", re.compile(r"(?i)(vite|__vite__)")),
    ("react", re.compile(r"(?i)(react\.development|react-dom|useState|useEffect)")),
    ("vue", re.compile(r"(?i)(vue\.runtime|vue\.esm|createApp)")),
    ("svelte", re.compile(r"(?i)(svelte|__svelte__)")),
]

BAAS_PATTERNS: list[tuple[str, Pattern]] = [
    ("supabase", re.compile(r"(?i)(supabase\.co|createClient\(|from ['\"]@supabase)")),
    ("firebase", re.compile(r"(?i)(firebaseapp\.com|firebaseio\.com|googleapis\.com|initializeApp|getFirestore|firebaseConfig)")),
    ("appwrite", re.compile(r"(?i)(appwrite|cloud\.appwrite\.io)")),
    ("pocketbase", re.compile(r"(?i)(pocketbase|pb_data)")),
]

VERSION_PATTERNS: list[tuple[str, Pattern]] = [
    ("npm_package", re.compile(r"([@a-z0-9_-]+)@(\d+\.\d+\.\d+)")),
    ("import_map", re.compile(r'"([^"]+)"\s*:\s*"([^"]+)"')),
    ("package_json", re.compile(r'"([^"]+)"\s*:\s*"(\^?\d+\.\d+\.\d+)"')),
]

DEBUG_ENDPOINTS = [
    "/debug", "/__debug__", "/_debug", "/admin", "/actuator", "/health",
    "/metrics", "/info", "/env", "/config", "/console", "/_profiler",
]

SECURITY_HEADERS = [
    "content-security-policy",
    "content-security-policy-report-only",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
]

CSP_DIRECTIVES = [
    "default-src", "script-src", "style-src", "img-src", "font-src",
    "connect-src", "media-src", "object-src", "frame-src", "worker-src",
    "frame-ancestors", "form-action", "base-uri", "manifest-src",
]