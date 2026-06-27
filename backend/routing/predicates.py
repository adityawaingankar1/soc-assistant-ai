from typing import Dict, Any, List, Optional

ENFORCEABLE_ENTITY_TYPES = {
    "ip",
    "domain",
    "url",
    "hash",
    "sha256",
    "md5"
}


def _norm(s: str) -> str:
    return (s or "").strip().lower()


def _has_entity(
    entities: List[dict],
    entity_type: str,
    value: str = None
) -> bool:

    for e in entities or []:

        et = (
            e.get("entity_type")
            or e.get("type")
            or ""
        ).strip().lower()

        if et != entity_type:
            continue

        if value is None:
            return True

        if _norm(
            e.get("normalized")
            or e.get("value")
        ) == _norm(value):
            return True

    return False


def _normalize_internet_facing_status(
    v: Any
) -> str:

    """
    Canonical:
      true | false | unknown
    """

    if v is True:
        return "true"

    if v is False:
        return "false"

    s = _norm(str(v))

    if s in {"true", "yes", "y", "1"}:
        return "true"

    if s in {"false", "no", "n", "0"}:
        return "false"

    return "unknown"


def compute_predicates(
    normalized_alert: Dict[str, Any],
    evidence_bundle: Dict[str, Any],
    vuln_intel: Dict[str, Any],
    confidence_percent: Optional[int]
) -> Dict[str, bool]:

    asset = (
        normalized_alert or {}
    ).get("asset", {}) or {}

    entities = (
        normalized_alert or {}
    ).get("entities", []) or []

    alert_source = _norm(
        (normalized_alert or {}).get("alert_source") or ""
    )

    linked = (
        evidence_bundle or {}
    ).get("linked_evidence", {}) or {}

    linked_signals = set(
        linked.get("signals", []) or []
    )

    discovered_entities = (
        linked.get("discovered_entities", []) or []
    )

    all_entities = entities + discovered_entities

    asset_class = _norm(
        asset.get("asset_class") or "unknown"
    )

    internet_facing_status = (
        _normalize_internet_facing_status(
            asset.get("internet_facing_status")
        )
    )

    edr_available = asset.get("edr_available")

    kev_count = int(
        (
            (
                (vuln_intel or {}).get("summary")
                or {}
            ).get("kev_count")
        ) or 0
    )

    high_risk = bool(
        (
            (
                (vuln_intel or {}).get("summary")
                or {}
            ).get("high_risk")
        )
    ) or (kev_count > 0)

    text_blob = " ".join(
        [
            str(normalized_alert.get("description", "")),
            str(normalized_alert.get("additional_context", "")),
            str(normalized_alert.get("ioc_list", "")),
        ]
    ).lower()

    p: Dict[str, bool] = {}

    # =====================================================
    # ASSET PREDICATES
    # =====================================================

    p["asset_class_edge_appliance"] = (
        asset_class in {"edge_appliance", "edge"}
    )

    p["asset_class_server"] = (
        asset_class == "server"
    )

    p["asset_class_unknown"] = (
        asset_class == "unknown"
    )

    p["asset_class_endpoint_or_server"] = (
        asset_class in {"endpoint", "server"}
    )

    p["internet_facing_true_or_unknown"] = (
        internet_facing_status in {"true", "unknown"}
    )

    p["edr_available"] = (
        bool(edr_available) is True
    )

    # Backward compatibility alias
    p["internet_facing_yes_or_unknown"] = (
        p["internet_facing_true_or_unknown"]
    )

    # =====================================================
    # ENTITY PREDICATES
    # =====================================================

    p["has_cves"] = _has_entity(
        entities,
        "cve"
    )

    p["high_risk_cve"] = high_risk

    p["has_any_enforceable_iocs"] = any(
        (
            (
                e.get("entity_type")
                or e.get("type")
                or ""
            ).strip().lower()
            in ENFORCEABLE_ENTITY_TYPES
        )
        for e in all_entities
    )

    # =====================================================
    # HIGH-FIDELITY SOURCES
    # =====================================================

    p["high_fidelity_alert_source"] = any(
        x in alert_source
        for x in [
            "edr",
            "xdr",
            "defender",
            "microsoft defender",
            "mde",
            "crowdstrike",
            "falcon",
            "sentinelone",
            "carbon black",
            "trend micro",
            "sophos",
            "cylance",
        ]
    )

    # =====================================================
    # IDENTITY / IAM SIGNALS
    # =====================================================

    p["identity_telemetry_signals"] = (

        any(
            str(sig).startswith(
                (
                    "IAM_",
                    "M365_",
                    "OKTA_",
                    "ENTRA_"
                )
            )
            for sig in linked_signals
        )

        or any(
            x in alert_source
            for x in [
                "entra",
                "azuread",
                "azure ad",
                "okta",
                "m365",
                "office",
                "o365",
                "identity"
            ]
        )

        or _has_entity(entities, "oauth_app")

        or _has_entity(entities, "mailbox_rule")

        or ("IDENTITY_ANOMALY" in linked_signals)
    )

    p["identity_signals"] = (
        p["identity_telemetry_signals"]
    )

    # =====================================================
    # RANSOMWARE SIGNALS
    # =====================================================

    ransomware_text_strong = any(
        k in text_blob
        for k in [
            "mass file encryption",
            "mass encryption",
            "multiple endpoints",
            "file extensions changed",
            ".interlock",
            "ransom note",
            "volume shadow copies deleted",
            "vss deleted",
            "shadow copies deleted",
            "vssadmin delete",
            "inhibit system recovery",
            "backup services forcefully stopped",
            "service stop",
            "encryption",
            "encrypted",
            "lateral movement detected",
            "smb",
            "windows admin shares"
        ]
    )

    p["ransomware_text_strong"] = (
        ransomware_text_strong
    )

    p["ransomware_signals"] = (

        any(
            str(sig).startswith("RANSOMWARE_")
            for sig in linked_signals
        )

        or ("VSS_DELETE" in linked_signals)

        or ("MASS_FILE_RENAME" in linked_signals)

        or ("RANSOM_NOTE" in linked_signals)

        or ransomware_text_strong

        or (
            p["high_fidelity_alert_source"]
            and any(
                k in text_blob
                for k in [
                    "ransomware",
                    "encrypted",
                    "encryption"
                ]
            )
        )
    )

    # =====================================================
    # WEB ARTIFACTS
    # =====================================================

    web_hint = any(
        x in text_blob
        for x in [
            "human2.aspx",
            "x-silock",
            "webshell",
            "wwwroot"
        ]
    )

    p["web_artifact_possible"] = (
        ("WEB_ARTIFACT_POSSIBLE" in linked_signals)
        or web_hint
    )

    p["web_artifact_strong"] = (

        ("WEB_ARTIFACT_STRONG" in linked_signals)

        or (
            "human2.aspx" in text_blob
            and "x-silock" in text_blob
        )

        or _has_entity(
            entities,
            "webshell_path"
        )
    )

    # =====================================================
    # APT / ESPIONAGE SIGNALS
    # =====================================================

    apt_tradecraft = any(
        x in text_blob
        for x in [
            "volt typhoon",
            "plugx",
            "fast reverse proxy",
            "frp",
            "reverse proxy",
            "proxy tunneling",
            "stealth persistence",
            "credential compromise",
            "long dwell time",
            "ntds.dit",
            "log clearing",
            "living off the land",
            "valid accounts",
            "spearphishing",
            "dll sideloading",
            "dll side-loading",
            "traffic tunneling",
        ]
    )

    p["apt_tradecraft"] = apt_tradecraft

    # =====================================================
    # PERSISTENCE SIGNALS
    # =====================================================

    persistence_tradecraft = any(
        x in text_blob
        for x in [
            "scheduled task",
            "service creation",
            "run key",
            "startup folder",
            "reverse proxy",
            "frp",
            "tunneling",
            "log clearing",
            "wevtutil",
            "ntds.dit",
        ]
    )

    p["has_persistence_tradecraft"] = (
        persistence_tradecraft
    )

    # =====================================================
    # TUNNELING / PROXY SIGNALS
    # =====================================================

    p["has_tunneling_behavior"] = any(
        x in text_blob
        for x in [
            "fast reverse proxy",
            "frp",
            "proxy tunneling",
            "reverse proxy",
            "traffic tunneling",
            "portproxy",
            "ssh -r",
        ]
    )

    # =====================================================
    # CREDENTIAL ABUSE
    # =====================================================

    p["has_credential_abuse"] = any(
        x in text_blob
        for x in [
            "valid accounts",
            "credential compromise",
            "rdp",
            "vpn admin creds",
            "ntds.dit",
        ]
    )

    # =====================================================
    # HIGH-FIDELITY HASH DETECTION
    # =====================================================

    p["has_advisory_hash_match"] = (

        "published in public advisory"
        in text_blob

        or (
            "hash detection"
            in alert_source
        )
    )

    # =====================================================
    # CONFIDENCE GATES
    # =====================================================

    if confidence_percent is not None:

        p["confidence_ge_0_80"] = (
            confidence_percent >= 80
        )

        p["confidence_ge_0_55"] = (
            confidence_percent >= 55
        )

    else:

        p["confidence_ge_0_80"] = False

        p["confidence_ge_0_55"] = False

    p["confidence_ge_0_8"] = (
        p["confidence_ge_0_80"]
    )

    return p