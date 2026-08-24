TAG_MAP = {
    "ExposedSecretsCheck": ("WSTG-INFO-02", ["T1552.001"]),
    "SupabaseFirebaseCheck": ("WSTG-ATHZ-02", ["T1213"]),
    "UnprotectedRoutesCheck": ("WSTG-ATHZ-01", ["T1190"]),
    "SecurityHeadersCheck": ("WSTG-CONF-06", ["T1598.001"]),
    "CORSCheck": ("WSTG-CONF-06", ["T1190"]),
    "DebugModeCheck": ("WSTG-INFO-02", ["T1592.002"]),
    "OutdatedDepsCheck": ("WSTG-CONF-06", ["T1190"]),
    "RateLimitingCheck": ("WSTG-ATHN-01", ["T1110.001", "T1110.003"]),
}

ALL_CHECK_NAMES = list(TAG_MAP.keys())


def get_tags_for_check(check_class_name: str) -> tuple[str, list[str]]:
    return TAG_MAP.get(check_class_name, ("", []))


def apply_tags_to_findings(findings: list, check_class_name: str) -> None:
    wstg_id, attck_ids = get_tags_for_check(check_class_name)
    for finding in findings:
        finding.wstg_id = wstg_id
        finding.attck_ids = attck_ids


def get_all_check_tags() -> dict:
    return {
        name: get_tags_for_check(name)
        for name in ALL_CHECK_NAMES
    }