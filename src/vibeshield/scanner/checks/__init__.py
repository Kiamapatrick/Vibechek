from vibeshield.scanner.checks.base import BaseCheck
from vibeshield.scanner.checks.cors import CORSCheck
from vibeshield.scanner.checks.debug_mode import DebugModeCheck
from vibeshield.scanner.checks.exposed_secrets import ExposedSecretsCheck
from vibeshield.scanner.checks.outdated_deps import OutdatedDepsCheck
from vibeshield.scanner.checks.rate_limiting import RateLimitingCheck
from vibeshield.scanner.checks.security_headers import SecurityHeadersCheck
from vibeshield.scanner.checks.supabase_firebase import SupabaseFirebaseCheck
from vibeshield.scanner.checks.unprotected_routes import UnprotectedRoutesCheck

ALL_CHECKS = [
    ExposedSecretsCheck,
    SupabaseFirebaseCheck,
    UnprotectedRoutesCheck,
    SecurityHeadersCheck,
    CORSCheck,
    DebugModeCheck,
    OutdatedDepsCheck,
    RateLimitingCheck,
]

__all__ = [
    "ALL_CHECKS",
    "BaseCheck",
    "CORSCheck",
    "DebugModeCheck",
    "ExposedSecretsCheck",
    "OutdatedDepsCheck",
    "RateLimitingCheck",
    "SecurityHeadersCheck",
    "SupabaseFirebaseCheck",
    "UnprotectedRoutesCheck",
]