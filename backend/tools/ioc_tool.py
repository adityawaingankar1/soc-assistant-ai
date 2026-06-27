from __future__ import annotations

from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import ipaddress
import json
import os
import re

from loguru import logger


class IOCTool:
    TOOL_NAME = "enrich_ioc"

    # ---- Output policy flags (production controls) ----
    # Default: do NOT output threat-actor attribution-like fields.
    ENABLE_ATTRIBUTION = os.getenv("SOC_ENABLE_ATTRIBUTION", "0").strip() == "1"
    # Default: include hash type (MD5/SHA256/etc.) since it's operationally useful.
    INCLUDE_HASH_TYPE = os.getenv("SOC_INCLUDE_HASH_TYPE", "1").strip() != "0"

    ATTR_KEYS_TO_STRIP = {
        "threat_actor",
        "actor",
        "actor_name",
        "most_likely_actor",
        "attribution",
    }

    # Pre-populated threat intel (matches your ransomware example)
    # You may keep threat_actor internally; it will be stripped from output unless ENABLE_ATTRIBUTION=1.
    MALICIOUS_IPS = {
        "185.220.101.47": {
            "reputation_score": 94,
            "threat_type": "RANSOMWARE_C2",
            "threat_actor": "Interlock",
            "campaigns": ["Municipal Infrastructure Ransomware"],
            "tags": ["c2", "tor", "ransomware"],
            "associated_malware": ["Interlock Ransomware"],
            "verdict": "MALICIOUS",
            "confidence": "HIGH",
        },
        "91.234.199.10": {
            "reputation_score": 88,
            "threat_type": "PHISHING_HOST",
            "verdict": "MALICIOUS",
            "confidence": "HIGH",
        },
    }

    MALICIOUS_DOMAINS = {
        "interlock-ransom.onion": {
            "reputation_score": 97,
            "threat_type": "RANSOMWARE_LEAK_SITE",
            "threat_actor": "Interlock",
            "campaigns": ["Municipal Infrastructure Ransomware"],
            "tags": ["ransomware", "tor-hidden-service"],
            "associated_malware": ["Interlock Ransomware"],
            "verdict": "MALICIOUS",
            "confidence": "HIGH",
        },
        "evil-domain.ru": {
            "reputation_score": 98,
            "threat_type": "MALWARE_C2",
            "verdict": "MALICIOUS",
            "confidence": "HIGH",
        },
    }

    # NOTE: sample uses 32-hex labeled "SHA256"; 32 hex is MD5-length.
    MALICIOUS_HASHES = {
        "3b4c9f2a1e8d7c6b5a4f3e2d1c0b9a87": {
            "reputation_score": 96,
            "malware_family": "Interlock Ransomware Loader",
            "threat_actor": "Interlock",
            "verdict": "MALICIOUS",
            "confidence": "VERY HIGH",
            "tags": ["ransomware", "loader", "persistence"],
            "sandbox_behavior": [
                "Creates Run key",
                "Shadow copy deletion",
                "SMB lateral movement",
            ],
        },

        # =====================================================
        # Volt Typhoon / FRP hashes (enterprise realism)
        # =====================================================
        "fd41134e8ead1c18ccad27c62a260aa6": {
            "reputation_score": 93,
            "malware_family": "FRP Persistence Client",
            "verdict": "MALICIOUS",
            "confidence": "HIGH",
            "tags": [
                "frp",
                "reverse-proxy",
                "tunneling",
                "volt-typhoon",
                "stealth-persistence",
            ],
            "sandbox_behavior": [
                "Reverse proxy tunneling",
                "Persistence",
                "Credential abuse support",
            ],
        },

        "edc0c63065e88ec96197c8d7a40662a15a812a9583dc6c82b18ecd7e43b13b70": {
            "reputation_score": 96,
            "malware_family": "FRP Client",
            "verdict": "MALICIOUS",
            "confidence": "VERY HIGH",
            "tags": [
                "volt-typhoon",
                "frp",
                "stealth-tunneling",
                "proxy",
            ],
            "sandbox_behavior": [
                "Encrypted reverse proxy",
                "Persistence",
                "Traffic tunneling",
            ],
        },

        "99b80c5ac352081a64129772ed5e1543d94cad708ba2adc46dc4ab7a0bd563f1": {
            "reputation_score": 95,
            "malware_family": "FRP Persistence Service",
            "verdict": "MALICIOUS",
            "confidence": "VERY HIGH",
            "tags": [
                "volt-typhoon",
                "frp",
                "service-persistence",
            ],
            "sandbox_behavior": [
                "Windows service persistence",
                "Proxy communication",
            ],
        },
    }

    # ---------------------------
    # Parsing / Extraction
    # ---------------------------
    @staticmethod
    def parse_ioc_list(raw: Any) -> List[Any]:
        """
        Normalizes common alert formats into a list of raw IOC entries.
        If raw is a string blob, extract structured IOCs from it.
        Returns: list[str|dict]
        """
        if raw is None:
            return []

        if isinstance(raw, list):
            return raw

        if isinstance(raw, dict):
            for k in ("iocs", "indicators", "ioc_list", "entities"):
                if k in raw and isinstance(raw[k], list):
                    return raw[k]
            return []

        if not isinstance(raw, str):
            return [str(raw)]

        s = raw.strip()
        if not s:
            return []

        # JSON-ish?
        if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
            try:
                parsed = json.loads(s)
                return IOCTool.parse_ioc_list(parsed)
            except Exception:
                pass

        extracted = IOCTool._extract_iocs_from_text(s)
        if extracted:
            return extracted

        parts = re.split(r"[,\n;]+", s)
        return [p.strip() for p in parts if p and p.strip()]

    @staticmethod
    def _extract_iocs_from_text(s: str) -> List[Dict[str, Any]]:
        """
        Deterministic multi-IOC extraction from unstructured alert text.
        - Multi-IOC blob extraction
        - Hash extraction for MD5/SHA1/SHA256/SHA512 (32/40/64/128 hex)
        - Label mismatch (e.g., "Hash (SHA256): <32hex>") still captured as hash
        """
        text = IOCTool._normalize_indicator(s)
        flat = re.sub(r"\s+", " ", text).strip()

        out: List[Dict[str, Any]] = []
        seen: set[Tuple[str, str]] = set()

        def add(t: str, v: str):
            v = (v or "").strip()
            if not v:
                return
            key = (t, v.lower())
            if key in seen:
                return
            seen.add(key)
            out.append({"type": t, "value": v})

        # Label-aware extraction (hash accepts 32/40/64/128)
        label_patterns = [
            (r"(?i)\bIP\s*:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b", "ip"),
            (
                r"(?i)\bHash\s*\(SHA256\)\s*:\s*([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})\b",
                "hash",
            ),
            (r"(?i)\bSHA256\s*:\s*([a-f0-9]{64})\b", "hash"),
            (r"(?i)\bMD5\s*:\s*([a-f0-9]{32})\b", "hash"),
            (r"(?i)\bSHA1\s*:\s*([a-f0-9]{40})\b", "hash"),
            # (Optional hardening) Domain label still constrained to strict TLD list
            (
                r"(?i)\bDomain\s*:\s*([a-z0-9\.\-\[\]\(\)]+(?:\.(?:com|net|org|io|gov|edu|ru|cn|uk|onion)))\b",
                "domain",
            ),
            (r"(?i)\bURL\s*:\s*(https?://[^\s\"'<>]+)", "url"),
            (
                r"(?i)\bFile\s*:\s*([a-z0-9_.\-]+?\.(?:exe|dll|lnk|ps1|bat|cmd|js|vbs|msi|scr|hta|sys|drv|ocx|cpl))\b",
                "file_name",
            ),
            (r"(?i)\bRegistry\s*Key\s*:\s*(HKLM\\[^\s\"'`]+)", "registry_key"),
        ]

        for pat, typ in label_patterns:
            for m in re.findall(pat, flat):
                val = IOCTool._normalize_indicator(str(m))
                if typ in ("domain", "url"):
                    val = IOCTool._normalize_defang(val)
                if typ == "hash":
                    val = val.lower()
                add(typ, val)

        # General extraction (additive)
        for m in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", flat):
            add("ip", m)

        # Hashes: MD5/SHA1/SHA256/SHA512
        for m in re.findall(r"(?i)\b[a-f0-9]{32}\b", flat):
            add("hash", m.lower())
        for m in re.findall(r"(?i)\b[a-f0-9]{40}\b", flat):
            add("hash", m.lower())
        for m in re.findall(r"(?i)\b[a-f0-9]{64}\b", flat):
            add("hash", m.lower())
        for m in re.findall(r"(?i)\b[a-f0-9]{128}\b", flat):
            add("hash", m.lower())

        for m in re.findall(r"(?i)\b(?:hxxp|https?)://[^\s\"'<>]+", flat):
            add("url", IOCTool._normalize_defang(m))
          
          
        EXECUTABLE_EXTENSIONS = {
            ".exe", ".dll", ".lnk", ".bat",
            ".cmd", ".ps1", ".js", ".vbs",
            ".msi", ".scr", ".hta", ".sys",
            ".drv", ".ocx", ".cpl"
        }
        # =====================================================
        # STRICT DOMAIN EXTRACTION
        # Prevent .exe/.dll/.lnk/.bat from becoming domains
        # =====================================================
        for m in re.findall(
            r"(?i)\b[a-z0-9][a-z0-9\-\.\[\]\(\)]*\.(?:com|net|org|io|gov|edu|ru|cn|uk|onion)\b",
            flat
        ):
            lowered = m.lower()
            if any(
                lowered.endswith(ext)
                for ext in EXECUTABLE_EXTENSIONS
            ):
                continue
            add("domain", IOCTool._normalize_defang(m).lower())

        for m in re.findall(
            r"(?i)\b[a-z0-9_.\-]+\.(?:exe|dll|lnk|ps1|bat|cmd|js|vbs|msi|scr|hta|sys|drv|ocx|cpl)\b",
            flat,
        ):
            add("file_name", m)

        for m in re.findall(r"(?i)\bHKLM\\[A-Za-z0-9_\\.\-]+(?:\\[A-Za-z0-9_\\.\-]+)*", flat):
            add("registry_key", IOCTool._normalize_indicator(m))

        return out

    @staticmethod
    def _normalize_defang(value: str) -> str:
        v = (value or "").strip()
        v = v.replace("hxxp://", "http://").replace("hxxps://", "https://")
        v = v.replace("[.]", ".").replace("(.)", ".")
        v = v.replace("[dot]", ".").replace("(dot)", ".")
        return v.strip()

    @staticmethod
    def _normalize_indicator(value: str) -> str:
        value = (value or "").strip()
        value = value.strip("`").strip('"').strip("'")
        value = IOCTool._normalize_defang(value)
        value = value.strip().rstrip(",;.")

        # strip invisible/control-ish chars that show up as odd glyphs in outputs
        for ch in ("\u200b", "\ufeff", "\ufffe", "\uffff", "\u00ad", "\u2060"):
            value = value.replace(ch, "")

        return value.strip()

    # ---------------------------
    # Classification
    # ---------------------------
    @classmethod
    def _looks_like_domain(cls, s: str) -> bool:
        s = (s or "").strip().lower()
        if not s or " " in s:
            return False
        if s.startswith("http://") or s.startswith("https://"):
            return False
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", s):
            return False

        # Strict domain matching (prevents smsvcservice.exe, brightmetricagent.exe, etc.)
        return bool(
            re.fullmatch(
                r"[a-z0-9][a-z0-9\-\.]{1,253}\.(?:com|net|org|io|gov|edu|ru|cn|uk|onion)",
                s,
            )
        )

    @classmethod
    def classify_entity(cls, value: str) -> Dict[str, Any]:
        normalized = cls._normalize_indicator(value)
        if not normalized:
            return {"value": value, "normalized": "", "entity_type": "unknown", "enrichable": False}

        if re.match(r"(?i)^CVE-\d{4}-\d{4,}$", normalized):
            return {"value": value, "normalized": normalized.upper(), "entity_type": "cve", "enrichable": False}

        if re.match(r"(?i)^(https?://)", normalized):
            return {"value": value, "normalized": normalized, "entity_type": "url", "enrichable": True}

        try:
            ipaddress.ip_address(normalized)
            return {"value": value, "normalized": normalized, "entity_type": "ip", "enrichable": True}
        except ValueError:
            pass

        hn = normalized.lower()
        if (
            re.fullmatch(r"[a-f0-9]{32}", hn)
            or re.fullmatch(r"[a-f0-9]{40}", hn)
            or re.fullmatch(r"[a-f0-9]{64}", hn)
            or re.fullmatch(r"[a-f0-9]{128}", hn)
        ):
            out: Dict[str, Any] = {
                "value": value,
                "normalized": hn,
                "entity_type": "hash",
                "enrichable": True,
            }
            if cls.INCLUDE_HASH_TYPE:
                out["hash_type"] = cls._detect_hash_type(hn)
            return out

        # =====================================================
        # Known offensive / persistence tooling names
        # (must occur BEFORE domain detection)
        # =====================================================
        if normalized.lower() in {
            "brightmetricagent.exe",
            "smsvcservice.exe",
            "frpc.exe",
            "frps.exe",
        }:
            return {
                "value": value,
                "normalized": normalized,
                "entity_type": "file_name",
                "enrichable": False,
                "known_tooling": True,
            }

        # File extension protection (expanded per instructions)
        if re.match(
            r"(?i)^.+\.(lnk|dll|exe|ps1|bat|cmd|js|vbs|msi|scr|hta|sys|drv|ocx|cpl)$",
            normalized,
        ):
            return {
                "value": value,
                "normalized": normalized,
                "entity_type": "file_name",
                "enrichable": False,
            }

        if normalized.lower().endswith(".onion") or cls._looks_like_domain(normalized):
            return {"value": value, "normalized": normalized.lower(), "entity_type": "domain", "enrichable": True}

        if re.match(r"(?i)^HKLM\\", normalized):
            return {"value": value, "normalized": normalized, "entity_type": "registry_key", "enrichable": False}

        if re.match(
            r"(?i)^[a-z0-9_.\-]+\.(exe|dll|lnk|ps1|bat|cmd|js|vbs|msi|scr|hta|sys|drv|ocx|cpl)$",
            normalized,
        ):
            return {"value": value, "normalized": normalized, "entity_type": "file_name", "enrichable": False}

        return {"value": value, "normalized": normalized, "entity_type": "unknown", "enrichable": False}

    @classmethod
    def classify_iocs(cls, raw_iocs: List[Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []

        def push(entity_type_hint: Optional[str], v: str):
            c = cls.classify_entity(v)
            if not c.get("normalized"):
                return

            # If upstream hint says "domain" but this is clearly a file name,
            # do NOT force it back into domain (prevents .exe becoming domain).
            hinted = (entity_type_hint or "").strip().lower() if entity_type_hint else None
            if hinted in {"sha256", "md5", "sha1"}:
                hinted = "hash"
            if hinted in {"hostname"}:
                hinted = "unknown"

            if hinted in {"ip", "domain", "url", "hash", "file_name", "registry_key", "cve"}:
                if not (hinted == "domain" and c.get("entity_type") == "file_name"):
                    c["entity_type"] = hinted
                    c["enrichable"] = hinted in {"ip", "domain", "url", "hash"}

            out.append(c)

        for item in raw_iocs or []:
            if isinstance(item, str):
                extracted = cls._extract_iocs_from_text(item)
                if extracted:
                    for x in extracted:
                        push(x.get("type"), x.get("value", ""))
                else:
                    push(None, item)
                continue

            if isinstance(item, dict):
                v = str(item.get("value") or item.get("indicator") or "").strip()
                t = (item.get("type") or item.get("entity_type") or item.get("indicator_type") or "").strip()
                if v:
                    extracted = cls._extract_iocs_from_text(v)
                    if extracted and len(extracted) > 1:
                        for x in extracted:
                            push(x.get("type"), x.get("value", ""))
                    else:
                        push(t or None, v)
                    continue

            push(None, str(item))

        deduped: List[Dict[str, Any]] = []
        seen = set()
        for e in out:
            key = (e.get("entity_type"), e.get("normalized"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(e)

        return deduped

    # ---------------------------
    # Alert convenience
    # ---------------------------
    def enrich_from_alert(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        raw = (
            alert.get("IOC List")
            or alert.get("ioc_list")
            or alert.get("raw_ioc_input")
            or alert.get("entities")
            or ""
        )
        parsed = self.parse_ioc_list(raw)

        if not parsed:
            for k in ("Alert Description", "alert_description", "Additional Context", "additional_context"):
                if alert.get(k):
                    parsed.extend(self.parse_ioc_list(str(alert.get(k))))

        classified = self.classify_iocs(parsed)
        return self.bulk_enrich(classified)

    # ---------------------------
    # Enrichment
    # ---------------------------
    def _strip_attribution_fields(self, d: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove attribution-like fields from tool output unless ENABLE_ATTRIBUTION is set.
        """
        if self.ENABLE_ATTRIBUTION:
            return d
        return {k: v for k, v in (d or {}).items() if k not in self.ATTR_KEYS_TO_STRIP}

    def enrich(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        logger.info(f"[IOC] Enriching {indicator_type}: {indicator}")

        indicator = self._normalize_indicator(indicator)
        indicator_type = (indicator_type or "").strip().lower()
        if not indicator:
            return self._error("indicator is required")

        dispatch = {
            "ip": self._enrich_ip,
            "domain": self._enrich_domain,
            "hash": self._enrich_hash,
            "url": self._enrich_url,
        }
        handler = dispatch.get(indicator_type)
        if not handler:
            return self._error(
                f"Unsupported indicator type: {indicator_type}",
                indicator=indicator,
                indicator_type=indicator_type,
            )

        result = handler(indicator)
        result = self._strip_attribution_fields(result)

        # Optionally remove hash_type everywhere (if you don't want it exposed)
        if not self.INCLUDE_HASH_TYPE and result.get("indicator_type") == "hash":
            result.pop("hash_type", None)

        result["tool"] = self.TOOL_NAME
        result["success"] = result.get("success", True)
        result["enriched_at"] = datetime.utcnow().isoformat()
        return result

    def bulk_enrich(self, iocs: List[Any]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []

        for ioc in iocs or []:
            if isinstance(ioc, dict):
                ind = ioc.get("indicator") or ioc.get("value") or ioc.get("normalized") or ""
                typ = ioc.get("type") or ioc.get("indicator_type") or ioc.get("entity_type") or ""
                typ = (typ or "").strip().lower()

                if typ in {"sha256", "md5", "sha1"}:
                    typ = "hash"

                if typ in {"ip", "domain", "url", "hash"}:
                    results.append(self.enrich(ind, typ))
                else:
                    results.append(
                        {
                            "tool": self.TOOL_NAME,
                            "success": True,
                            "indicator": self._normalize_indicator(ind),
                            "indicator_type": typ or "unknown",
                            "skipped": True,
                            "reason": f"Not TI-enrichable entity type: {typ or 'unknown'}",
                            "enriched_at": datetime.utcnow().isoformat(),
                            "verdict": "UNSUPPORTED_FOR_TI",
                            "malicious": None,
                            "confidence": "LOW",
                            "note": f"{typ or 'unknown'} entity captured but not supported by TI enrichment",
                        }
                    )
            else:
                classified = self.classify_entity(str(ioc))
                et = classified.get("entity_type")
                if et in {"ip", "domain", "url", "hash"}:
                    results.append(self.enrich(classified["normalized"], et))
                else:
                    results.append(
                        {
                            "tool": self.TOOL_NAME,
                            "success": True,
                            "indicator": classified.get("normalized"),
                            "indicator_type": et,
                            "skipped": True,
                            "reason": f"Not TI-enrichable entity type: {et}",
                            "enriched_at": datetime.utcnow().isoformat(),
                            "verdict": "UNSUPPORTED_FOR_TI",
                            "malicious": None,
                            "confidence": "LOW",
                            "note": f"{et} entity captured but not supported by TI enrichment",
                        }
                    )

        return results

    # ---------------------------
    # Internal enrichers
    # ---------------------------
    def _enrich_ip(self, ip: str) -> Dict[str, Any]:
        base = {"indicator": ip, "indicator_type": "ip", "malicious": False, "reputation_score": 5, "success": True}
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                base["note"] = "Private/Internal IP address — check internal threat intel"
                base["is_private"] = True
                base["verdict"] = "INTERNAL"
                base["confidence"] = "MEDIUM"
                return base
        except ValueError:
            return self._error("Invalid IP address format", indicator=ip, indicator_type="ip")

        if ip in self.MALICIOUS_IPS:
            malicious_data = self._strip_attribution_fields(self.MALICIOUS_IPS[ip])
            base.update(
                {
                    "malicious": True,
                    **malicious_data,
                    "verdict": "MALICIOUS",
                    "confidence": malicious_data.get("confidence", "HIGH"),
                    "sources": ["VirusTotal", "AbuseIPDB", "Shodan", "ThreatFox"],
                }
            )
        else:
            base.update(
                {
                    "malicious": False,
                    "reputation_score": 10,
                    "verdict": "CLEAN",
                    "confidence": "MEDIUM",
                    "note": "No known malicious activity — continue monitoring",
                    "sources": ["VirusTotal", "AbuseIPDB"],
                }
            )

        return base

    def _enrich_domain(self, domain: str) -> Dict[str, Any]:
        domain = self._normalize_defang(domain).strip().lower()
        base = {"indicator": domain, "indicator_type": "domain", "malicious": False, "reputation_score": 5, "success": True}

        if domain in self.MALICIOUS_DOMAINS:
            malicious_data = self._strip_attribution_fields(self.MALICIOUS_DOMAINS[domain])
            base.update(
                {
                    "malicious": True,
                    **malicious_data,
                    "verdict": "MALICIOUS",
                    "confidence": malicious_data.get("confidence", "HIGH"),
                    "sources": ["VirusTotal", "URLhaus", "MISP", "PhishTank"],
                }
            )
        elif self._is_suspicious_domain(domain):
            base.update(
                {
                    "malicious": False,
                    "suspicious": True,
                    "reputation_score": 45,
                    "verdict": "SUSPICIOUS",
                    "confidence": "MEDIUM",
                    "suspicion_reasons": self._get_suspicion_reasons(domain),
                    "recommendation": "Block and monitor — domain shows suspicious characteristics",
                }
            )
        else:
            base.update(
                {
                    "malicious": False,
                    "reputation_score": 8,
                    "verdict": "CLEAN",
                    "confidence": "MEDIUM",
                    "note": "No known malicious activity",
                }
            )

        return base

    def _enrich_hash(self, file_hash: str) -> Dict[str, Any]:
        normalized_hash = (file_hash or "").strip().lower()
        base: Dict[str, Any] = {
            "indicator": normalized_hash,
            "indicator_type": "hash",
            "malicious": False,
            "success": True,
        }
        if self.INCLUDE_HASH_TYPE:
            base["hash_type"] = self._detect_hash_type(normalized_hash)

        if normalized_hash in self.MALICIOUS_HASHES:
            malicious_data = self._strip_attribution_fields(self.MALICIOUS_HASHES[normalized_hash])
            base.update(
                {
                    "malicious": True,
                    **malicious_data,
                    "verdict": "MALICIOUS",
                    "confidence": malicious_data.get("confidence", "VERY HIGH"),
                    "sources": ["VirusTotal", "Hybrid Analysis", "Any.run", "Joe Sandbox"],
                }
            )
        else:
            base.update(
                {
                    "malicious": False,
                    "reputation_score": 0,
                    "av_detections": 0,
                    "av_total_engines": 70,
                    "verdict": "NOT_FOUND",
                    "confidence": "LOW",
                    "note": "Hash not found in threat intel — may be new/custom malware or clean file",
                }
            )

        return base

    def _enrich_url(self, url: str) -> Dict[str, Any]:
        url = self._normalize_defang(self._normalize_indicator(url))
        base = {"indicator": url, "indicator_type": "url", "malicious": False, "success": True}

        domain_match = re.search(r"(?i)https?://([^/]+)", url)
        if domain_match:
            domain = domain_match.group(1).lower()
            domain_result = self._enrich_domain(domain)
            if domain_result.get("malicious"):
                base.update(
                    {
                        "malicious": True,
                        "reputation_score": 95,
                        "verdict": "MALICIOUS",
                        "reason": f"Domain {domain} is known malicious",
                        "domain_enrichment": domain_result,
                        "confidence": "HIGH",
                    }
                )
                return base

        suspicious_patterns = [
            ("login", "credential-harvesting"),
            ("account-verify", "phishing"),
            ("secure-update", "phishing"),
            ("invoice", "malware-distribution"),
            (".exe", "malware-download"),
            (".zip", "malware-download"),
            ("clickfix", "social-engineering"),
            ("cloudflareaccess", "phishing"),
        ]
        for pattern, threat_type in suspicious_patterns:
            if pattern in url.lower():
                base.update(
                    {
                        "malicious": False,
                        "suspicious": True,
                        "reputation_score": 50,
                        "verdict": "SUSPICIOUS",
                        "threat_type": threat_type,
                        "matched_pattern": pattern,
                        "confidence": "MEDIUM",
                    }
                )
                return base

        base.update(
            {
                "verdict": "CLEAN",
                "reputation_score": 5,
                "note": "No known malicious patterns detected",
                "confidence": "LOW",
            }
        )
        return base

    # ---------------------------
    # Utilities
    # ---------------------------
    @staticmethod
    def _is_suspicious_domain(domain: str) -> bool:
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".onion"]
        has_suspicious_tld = any(domain.endswith(tld) for tld in suspicious_tlds)
        is_long = len(domain) > 30
        has_many_dashes = domain.count("-") > 3
        has_numbers = bool(re.search(r"\d{4,}", domain))

        # Enterprise brand impersonation (expanded per instructions)
        brand_impersonation = any(
            brand in domain
            for brand in [
                "microsoft",
                "google",
                "amazon",
                "adobe",
                "dropbox",
                "office365",
                "paypal",
                "windows",
                "microsoft365",
                "azure",
                "okta",
                "cisco",
                "vpn",
            ]
        )

        return has_suspicious_tld or (is_long and (has_many_dashes or has_numbers)) or brand_impersonation

    @staticmethod
    def _get_suspicion_reasons(domain: str) -> List[str]:
        reasons: List[str] = []
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".onion"]

        # Enterprise brand impersonation (expanded per instructions)
        if any(
            brand in domain
            for brand in [
                "microsoft",
                "google",
                "amazon",
                "office365",
                "windows",
                "microsoft365",
                "azure",
                "okta",
                "cisco",
                "vpn",
            ]
        ):
            reasons.append("Possible brand impersonation / typo-squatting")

        if any(domain.endswith(tld) for tld in suspicious_tlds):
            reasons.append("Uses free/bulletproof/anonymized TLD known for abuse")
        if len(domain) > 30:
            reasons.append("Unusually long domain name — possible DGA")
        if domain.count("-") > 3:
            reasons.append("Excessive hyphens — common in phishing domains")
        if re.search(r"\d{4,}", domain):
            reasons.append("Contains numeric sequences — common in malware C2")

        return reasons

    @staticmethod
    def _detect_hash_type(hash_str: str) -> str:
        length = len(hash_str)
        return {32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512"}.get(length, "UNKNOWN")

    def _error(self, message: str, **kwargs) -> Dict[str, Any]:
        return {
            "success": False,
            "tool": self.TOOL_NAME,
            "error": message,
            "enriched_at": datetime.utcnow().isoformat(),
            **kwargs,
        }

    def get_schema(self) -> Dict[str, Any]:
        return {
            "name": self.TOOL_NAME,
            "description": (
                "Enrich an Indicator of Compromise (IP, domain, file hash, URL) with threat intelligence "
                "data including reputation scores and malware associations."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "indicator": {"type": "string"},
                    "indicator_type": {"type": "string", "enum": ["ip", "domain", "hash", "url"]},
                },
                "required": ["indicator", "indicator_type"],
            },
        }