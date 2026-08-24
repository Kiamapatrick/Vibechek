from vibeshield.scanner.checks import ALL_CHECKS
from vibeshield.scanner.tagging import get_all_check_tags, get_tags_for_check


class TestTagging:
    def test_exposed_secrets_tags(self):
        wstg, attck = get_tags_for_check("ExposedSecretsCheck")
        assert wstg == "WSTG-INFO-02"
        assert attck == ["T1552.001"]

    def test_supabase_firebase_tags(self):
        wstg, attck = get_tags_for_check("SupabaseFirebaseCheck")
        assert wstg == "WSTG-ATHZ-02"
        assert attck == ["T1213"]

    def test_unprotected_routes_tags(self):
        wstg, attck = get_tags_for_check("UnprotectedRoutesCheck")
        assert wstg == "WSTG-ATHZ-01"
        assert attck == ["T1556.002"]

    def test_security_headers_tags(self):
        wstg, attck = get_tags_for_check("SecurityHeadersCheck")
        assert wstg == "WSTG-CONF-06"
        assert attck == ["T1598.001"]

    def test_cors_tags(self):
        wstg, attck = get_tags_for_check("CORSCheck")
        assert wstg == "WSTG-CONF-06"
        assert attck == ["T1556.002"]

    def test_debug_mode_tags(self):
        wstg, attck = get_tags_for_check("DebugModeCheck")
        assert wstg == "WSTG-INFO-02"
        assert attck == ["T1592.002"]

    def test_outdated_deps_tags(self):
        wstg, attck = get_tags_for_check("OutdatedDepsCheck")
        assert wstg == "WSTG-CONF-06"
        assert attck == ["T1190"]

    def test_rate_limiting_tags(self):
        wstg, attck = get_tags_for_check("RateLimitingCheck")
        assert wstg == "WSTG-ATHN-01"
        assert attck == ["T1110.001", "T1110.003"]

    def test_all_checks_have_tags(self):
        all_tags = get_all_check_tags()
        for check in ALL_CHECKS:
            assert check.__name__ in all_tags
            wstg, attck = all_tags[check.__name__]
            assert wstg, f"Missing WSTG tag for {check.__name__}"
            assert attck, f"Missing ATT&CK tags for {check.__name__}"