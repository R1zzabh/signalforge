"""Deterministic, explainable SignalForge rule engine."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

STATES = ("TRIGGERED", "NOT_TRIGGERED", "NOT_EVALUABLE", "ERROR", "DISABLED")
MITRE = {
    "T1110": ("Brute Force", "Credential Access", "Adversaries may use brute force techniques to gain access to accounts."),
    "T1046": ("Network Service Scanning", "Discovery", "Adversaries may attempt to get a listing of services running on remote hosts."),
    "T1059": ("Command and Scripting Interpreter", "Execution", "Adversaries may abuse command and script interpreters."),
    "T1071": ("Application Layer Protocol", "Command and Control", "Adversaries may communicate using application layer protocols."),
    "T1566": ("Phishing", "Initial Access", "Adversaries may send phishing messages to gain access."),
}
DEFAULT_CONFIG: dict[str, Any] = {
    "brute_force": {"suspicious_attempts": 10, "high_confidence_attempts": 20, "severe_attempts": 50, "window_seconds": 300},
    "port_scan": {"unique_ports": 10, "window_seconds": 60},
    "alert_burst": {"alert_count": 20, "window_seconds": 300},
    "multi_account": {"username_count": 5, "window_seconds": 300},
    "duplicate_window_seconds": 900,
}

def _rule(rule_id: str, name: str, category: str, description: str, condition: str,
          bucket: str, weight: int = 0, required_inputs: tuple[str, ...] = (),
          mitre: tuple[str, ...] = (), version: str = "1.0.0") -> dict[str, Any]:
    return {"id": rule_id, "rule_id": rule_id, "name": name, "category": category,
            "description": description, "condition": condition, "version": version,
            "enabled": True, "scoring_group": bucket, "bucket": bucket,
            "score_weight": weight, "weight": weight, "required_inputs": list(required_inputs),
            "mitre": list(mitre), "severity_effect": "CONTEXT" if not weight else "SCORE"}

RULES = [
    _rule("RULE-REP-001", "IOC Reputation", "Reputation", "Historical abuse confidence is a signal, not proof by itself.", "AbuseIPDB confidence bands", "Reputation", 25, ("abuseipdb",)),
    _rule("RULE-TI-001", "VirusTotal Malicious Detection", "Threat Intelligence", "Multiple engines identify the indicator as malicious.", "VirusTotal malicious detections", "Threat Intelligence", 25, ("virustotal",)),
    _rule("RULE-BHV-001", "Brute Force Detection", "Behavior", "Repeated authentication failures in a bounded window.", ">=10 failures in 5 minutes", "Behavior", 20, ("failed_attempts",), ("T1110",)),
    _rule("RULE-NET-001", "Port Scan Detection", "Network", "One source touches many destination ports quickly.", ">=10 unique ports in 60 seconds", "Behavior", 20, ("unique_ports",), ("T1046",)),
    _rule("RULE-AUTH-001", "Credential Stuffing", "Authentication", "One source retries authentication across multiple accounts.", "multiple usernames plus failures", "Behavior", 8, ("failed_attempts", "usernames"), ("T1110",)),
    _rule("RULE-AUTH-002", "Suspicious Login", "Authentication", "Contextual login anomaly based on time, source, and frequency.", "anomalous login context", "Context", 3),
    _rule("RULE-ID-001", "Impossible Travel", "Identity", "Login locations require implausible travel speed.", "known prior location plus distance/time", "Context", 5, ("previous_login", "coordinates")),
    _rule("RULE-TI-002", "Known Malicious IOC Match", "Threat Intelligence", "IOC is confirmed by provider or internal intelligence.", "confirmed malicious IOC", "Threat Intelligence", 0, ("malicious_ioc",)),
    _rule("RULE-MAL-001", "Malware Communication", "Malware", "An asset communicates with a confirmed malicious indicator.", "asset to malicious IOC", "Behavior", 8, ("malware_communication",)),
    _rule("RULE-MAL-002", "Command and Control", "Malware", "Repeated beaconing or suspicious C2 destination behavior.", "beacon pattern or C2 signal", "Behavior", 5, ("c2_signal",), ("T1071",)),
    _rule("RULE-VULN-001", "CVE Correlation", "Vulnerability", "Alert behavior relates to a component with a matching CVE.", "matching CVE exists", "Vulnerability", 5, ("cve",)),
    _rule("RULE-VULN-002", "CVSS Severity", "Vulnerability", "CVSS contributes impact context only.", "CVSS severity band", "Vulnerability", 15, ("cvss",)),
    _rule("RULE-MITRE-001", "MITRE ATT&CK Behavior Mapping", "Threat Intelligence", "Maps observed behavior to supported ATT&CK techniques.", "supported technique evidence", "Context", 0, (), ("T1110", "T1046", "T1059", "T1071", "T1566")),
    _rule("RULE-ASSET-001", "Asset Criticality", "Asset", "Criticality represents potential impact, not maliciousness.", "criticality 1-5", "Asset Impact", 10, ("asset_criticality",)),
    _rule("RULE-CORR-001", "Threat Intelligence Correlation", "Correlation", "AbuseIPDB and VirusTotal independently reinforce confidence.", "AbuseIPDB >=80 and VT >=5", "Context", 5, ("abuseipdb", "virustotal")),
    _rule("RULE-CORR-002", "Malicious IOC + Suspicious Behavior", "Correlation", "Confirmed malicious IOC and behavior share incident context.", "malicious IOC plus behavior", "Context", 0, ("malicious_ioc", "suspicious_behavior")),
    _rule("RULE-CORR-003", "Malicious IOC + Critical Asset", "Correlation", "Impact escalation requires both maliciousness and criticality.", "malicious IOC and criticality >=4", "Context", 0, ("malicious_ioc", "asset_criticality")),
    _rule("RULE-CORR-004", "Malicious IOC + Malware + Critical Asset", "Correlation", "Documented deterministic critical escalation condition.", "malicious IOC, malware, critical asset", "Context", 0, ("malicious_ioc", "malware_communication", "asset_criticality")),
    _rule("RULE-CORR-005", "Multi-IOC Correlation", "Correlation", "Related indicators are grouped by source, target, incident, and time.", "two or more related IOCs", "Context", 0, ("ioc_count",)),
    _rule("RULE-OPS-001", "Duplicate Alert Suppression", "Operations", "Normalized fingerprint identifies repeated alerts without deleting history.", "duplicate fingerprint within window", "Context", 0, ("fingerprint",)),
    _rule("RULE-OPS-002", "False Positive / Allowlist", "Operations", "Trusted sources can be suppressed, reduced, or reviewed with audit.", "allowlist match", "Context", 0, ("allowlist_match",)),
    _rule("RULE-NET-002", "Suspicious Network Service", "Network", "Observed service differs from the asset profile.", "unexpected service for asset", "Behavior", 5, ("asset_profile", "protocol")),
    _rule("RULE-NET-003", "Unusual Outbound Traffic", "Network", "Outbound connection is outside deterministic asset profile.", "unexpected external destination", "Behavior", 5, ("asset_profile", "destination")),
    _rule("RULE-ID-002", "High-Value Account Attack", "Identity", "Suspicious activity targets a privileged account.", "suspicious behavior plus privileged account", "Asset Impact", 5, ("privilege", "suspicious_behavior"), ("T1110",)),
    _rule("RULE-ASSET-002", "High-Value Asset Attack", "Asset", "Attack context targets a production or security-critical asset.", "high-value asset type", "Asset Impact", 5, ("asset_type",)),
    _rule("RULE-BHV-002", "Alert Velocity / Burst", "Behavior", "One source or IOC emits many alerts in a bounded window.", ">=20 alerts in 5 minutes", "Behavior", 5, ("alert_count",), ("T1071",)),
    _rule("RULE-AUTH-003", "Multi-Account Attack", "Authentication", "One source targets five or more usernames.", ">=5 usernames in configured window", "Behavior", 5, ("usernames",), ("T1110",)),
    _rule("RULE-VULN-003", "Vulnerability Exploitation Behavior", "Vulnerability", "Behavior and matching vulnerable service are both present.", "exploit behavior plus CVE", "Vulnerability", 5, ("exploit_behavior", "cve")),
    _rule("RULE-RESP-001", "Severity Escalation", "Response", "Applies minimum severity and critical combination overrides.", "deterministic combination escalation", "Context", 0),
    _rule("RULE-RESP-002", "Human-in-the-Loop Response", "Response", "Recommendations are separated from execution and approval.", "HIGH/CRITICAL requires review", "Context", 0),
]
RULE_BY_ID = {r["id"]: r for r in RULES}

def _provider(ti: dict[str, Any], name: str) -> dict[str, Any]:
    value = ti.get(name, {}) or {}; return value if isinstance(value, dict) else {}
def _num(value: Any, default: float = 0) -> float:
    try: return float(value)
    except (TypeError, ValueError): return default
def _malicious(a: dict[str, Any], ti: dict[str, Any]) -> bool:
    return bool(a.get("malicious_ioc") or a.get("known_malicious_ioc") or _provider(ti, "virustotal").get("malicious") or _num(_provider(ti, "virustotal").get("detections")) >= 3 or _num(_provider(ti, "abuseipdb").get("confidence")) >= 70)
def _behavior(a: dict[str, Any]) -> bool:
    return bool(a.get("suspicious_behavior") or a.get("malware_communication") or _num(a.get("failed_attempts")) >= 10 or _num(a.get("unique_ports")) >= 10 or a.get("event_type") in {"port_scan", "ssh_brute_force", "server_exploitation", "malware_communication", "credential_stuffing"})
def _state(rule: dict[str, Any], triggered: bool, reason: str, evidence: dict[str, Any], *, evaluable: bool = True, score: int = 0, confidence: str = "MEDIUM") -> dict[str, Any]:
    state = "TRIGGERED" if triggered else "NOT_TRIGGERED" if evaluable else "NOT_EVALUABLE"
    return {"rule_id": rule["id"], "id": rule["id"], "version": rule["version"], "name": rule["name"], "category": rule["category"], "state": state, "triggered": triggered, "score": score, "applied_weight": score, "severity_effect": rule["severity_effect"], "reason": reason, "evidence": evidence, "mitre": rule["mitre"][0] if len(rule["mitre"]) == 1 else rule["mitre"], "mitre_techniques": rule["mitre"], "recommendations": ["Validate the evidence and preserve related telemetry"] if triggered else [], "confidence": confidence}
def _fingerprint(a: dict[str, Any]) -> str:
    keys = ("source_ip", "destination_ip", "event_type", "ioc", "username", "destination_port")
    return hashlib.sha256("|".join(str(a.get(k, "")).lower() for k in keys).encode()).hexdigest()[:20]
def max_severity(left: str, right: str) -> str:
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}; return left if order[left] >= order[right] else right

def evaluate(alert: dict[str, Any], threat_intelligence: dict[str, Any] | None = None, config: dict[str, Any] | None = None) -> dict[str, Any]:
    a = dict(alert or {}); ti = dict(threat_intelligence or {}); cfg = {**DEFAULT_CONFIG, **(config or {})}
    abuse = _num(_provider(ti, "abuseipdb").get("confidence")); vt = _num(_provider(ti, "virustotal").get("detections")); failed = _num(a.get("failed_attempts")); ports = _num(a.get("unique_ports")); critical = int(_num(a.get("asset_criticality"), 1)); cvss = _num(_provider(ti, "nvd").get("cvss", a.get("cvss"))); malicious = _malicious(a, ti); behavior = _behavior(a); privileged = str(a.get("privilege", "")).lower() in {"admin", "root", "privileged", "domain_admin", "security_admin"} or str(a.get("username", "")).lower() in {"root", "admin", "administrator", "domain administrator", "security_admin"}
    usernames = a.get("usernames") or a.get("target_usernames") or ([] if not a.get("username") else [a.get("username")]); username_count = len(set(usernames)) if isinstance(usernames, list) else int(_num(usernames)); high_asset = str(a.get("asset_type", "")).lower() in {"production_database", "domain_controller", "authentication_server", "critical_application", "security_infrastructure"}; cve = _provider(ti, "nvd").get("cve") or a.get("cve"); exploit = bool(a.get("exploit_behavior") or a.get("event_type") in {"server_exploitation", "cve_exploit", "exploit_attempt"}); allowlisted = bool(a.get("allowlist_match") or a.get("allowlisted")); ioc_count = len(a.get("iocs", [])) if isinstance(a.get("iocs"), list) else int(_num(a.get("ioc_count"), 0)); duplicate = bool(a.get("duplicate") or a.get("is_duplicate")); missing_ti = not ti
    results: list[dict[str, Any]] = []
    def add(rid: str, trig: bool, reason: str, evidence: dict[str, Any], *, evaluable: bool = True, score: int = 0, confidence: str = "MEDIUM"):
        results.append(_state(RULE_BY_ID[rid], trig, reason, evidence, evaluable=evaluable, score=score, confidence=confidence))
    rep_score = 25 if abuse >= 90 else 20 if abuse >= 70 else 10 if abuse >= 40 else 5 if abuse >= 20 else 0; add("RULE-REP-001", rep_score > 0, f"AbuseIPDB confidence is {abuse:.0f}%.", {"abuse_confidence": abuse, "reports": _provider(ti, "abuseipdb").get("reports"), "usage_type": _provider(ti, "abuseipdb").get("usage_type")}, evaluable=not missing_ti, score=rep_score)
    vt_score = 25 if vt > 10 else 15 if vt >= 6 else 10 if vt >= 3 else 5 if vt >= 1 else 0; add("RULE-TI-001", vt_score > 0, f"VirusTotal returned {vt:.0f} malicious detections.", {"malicious_count": vt, "suspicious_count": _provider(ti, "virustotal").get("suspicious"), "total_engines": _provider(ti, "virustotal").get("total_engines")}, evaluable=not missing_ti, score=vt_score)
    brute_score = 20 if failed >= 50 else 15 if failed >= 20 else 10 if failed >= 10 else 0; add("RULE-BHV-001", brute_score > 0, f"Observed {failed:.0f} failed authentication attempts.", {"attempt_count": failed, "window_seconds": cfg["brute_force"]["window_seconds"], "source": a.get("source_ip"), "target": a.get("destination_ip"), "account": a.get("username")}, score=brute_score, confidence="HIGH" if failed >= 20 else "MEDIUM")
    scan_score = 20 if ports >= 10 else 0; add("RULE-NET-001", scan_score > 0, f"Observed {ports:.0f} unique destination ports.", {"unique_ports": ports, "window_seconds": cfg["port_scan"]["window_seconds"], "target": a.get("destination_ip")}, score=scan_score)
    add("RULE-AUTH-001", username_count >= 2 and failed >= 10, "Repeated failures span multiple usernames.", {"username_count": username_count, "failed_attempts": failed}, score=8 if username_count >= 2 and failed >= 10 else 0, confidence="HIGH" if username_count >= 5 else "MEDIUM")
    suspicious_login = bool(a.get("unusual_time") or a.get("unusual_source") or a.get("new_source") or a.get("unusual_frequency")); add("RULE-AUTH-002", suspicious_login, "Login context contains an explicit anomaly signal.", {"unusual_time": a.get("unusual_time"), "unusual_source": a.get("unusual_source"), "new_source": a.get("new_source")}, score=3 if suspicious_login else 0)
    previous = a.get("previous_login"); coords = a.get("coordinates"); impossible = bool(previous and coords and _num(a.get("travel_speed_kmh")) > 900); add("RULE-ID-001", impossible, "Required historical login context supports an impossible-travel anomaly.", {"previous_login": previous, "coordinates": coords, "travel_speed_kmh": a.get("travel_speed_kmh")}, evaluable=bool(previous and coords), score=5 if impossible else 0)
    add("RULE-TI-002", malicious, "At least one normalized provider or internal signal confirms the IOC.", {"confirmed": malicious, "provider_status": {k: _provider(ti, k).get("status") for k in ("virustotal", "abuseipdb")}}, evaluable=not missing_ti or bool(a.get("malicious_ioc")), confidence="HIGH" if malicious else "LOW")
    malware = bool(a.get("malware_communication") or (a.get("event_type") == "malware_communication" and malicious)); add("RULE-MAL-001", malware, "Asset-to-IOC communication is explicitly marked or corroborated.", {"source_asset": a.get("hostname"), "destination_ioc": a.get("source_ip"), "reputation_confirmed": malicious}, score=8 if malware else 0, confidence="HIGH" if malware and malicious else "MEDIUM")
    c2 = bool(a.get("c2_signal") or a.get("beacon_pattern") or a.get("event_type") == "c2_beacon"); add("RULE-MAL-002", c2, "Periodic or suspicious C2 behavior is present.", {"beacon_pattern": a.get("beacon_pattern"), "c2_signal": a.get("c2_signal")}, score=5 if c2 else 0, confidence="HIGH" if a.get("c2_confirmed") else "MEDIUM")
    cve = _provider(ti, "nvd").get("cve") or a.get("cve"); cv = bool(cve); add("RULE-VULN-001", cv, "A CVE is attached to the matching service or component.", {"cve": cve, "component": _provider(ti, "nvd").get("component"), "affected_version": _provider(ti, "nvd").get("affected_version")}, evaluable=bool(cve or _provider(ti, "nvd")), score=5 if cv else 0)
    cvss_score = 15 if cvss >= 9 else 10 if cvss >= 7 else 5 if cvss >= 4 else 2 if cvss > 0 else 0; add("RULE-VULN-002", cvss_score > 0, f"CVSS is {cvss:.1f}; this describes impact, not exploitability.", {"cvss": cvss, "severity": "CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7 else "MEDIUM" if cvss >= 4 else "LOW" if cvss else None}, evaluable=cvss > 0, score=cvss_score)
    mapped = [x for x in ("T1110" if failed >= 10 or username_count >= 5 else None, "T1046" if ports >= 10 else None, "T1071" if c2 else None) if x]; add("RULE-MITRE-001", bool(mapped), "Only supported techniques with matching evidence are mapped.", {"techniques": mapped})
    asset_score = {1: 0, 2: 2, 3: 5, 4: 8, 5: 10}.get(critical, 0); add("RULE-ASSET-001", critical >= 2, f"Asset criticality is {critical}/5.", {"criticality": critical}, score=asset_score)
    corr = abuse >= 80 and vt >= 5; add("RULE-CORR-001", corr, "AbuseIPDB and VirusTotal independently reinforce confidence.", {"abuse_confidence": abuse, "vt_detections": vt}, evaluable=not missing_ti, score=5 if corr else 0, confidence="HIGH" if corr else "LOW")
    add("RULE-CORR-002", malicious and behavior, "Malicious intelligence and suspicious behavior share this investigation.", {"malicious_ioc": malicious, "suspicious_behavior": behavior}, confidence="HIGH" if malicious and behavior else "MEDIUM")
    add("RULE-CORR-003", malicious and critical >= 4, "Confirmed maliciousness targets a critical asset.", {"malicious_ioc": malicious, "asset_criticality": critical}, confidence="HIGH" if malicious and critical >= 4 else "MEDIUM")
    add("RULE-CORR-004", malicious and malware and critical >= 4, "Malicious IOC, malware communication, and critical asset co-occur.", {"malicious_ioc": malicious, "malware_communication": malware, "asset_criticality": critical}, confidence="HIGH" if malicious and malware and critical >= 4 else "MEDIUM")
    add("RULE-CORR-005", ioc_count >= 2, "Multiple normalized indicators are available for correlation.", {"ioc_count": ioc_count}, evaluable=bool(a.get("iocs") is not None or a.get("ioc_count") is not None))
    add("RULE-OPS-001", duplicate, "The normalized alert fingerprint is already present in the configured time window.", {"fingerprint": a.get("fingerprint") or _fingerprint(a), "duplicate_window_seconds": cfg["duplicate_window_seconds"]})
    add("RULE-OPS-002", allowlisted, "An allowlist match is preserved for audit and policy action.", {"match": a.get("allowlist_match") or a.get("allowlist_reason"), "action": a.get("allowlist_action", "FLAG_FOR_REVIEW")})
    expected = a.get("expected_services"); observed = a.get("protocol") or a.get("service"); unexpected_service = bool(expected and observed and observed not in expected); add("RULE-NET-002", unexpected_service, "Observed service is outside the asset profile.", {"expected_services": expected, "observed_service": observed}, evaluable=bool(expected and observed), score=5 if unexpected_service else 0)
    expected_destinations = a.get("expected_destinations"); unusual_outbound = bool(a.get("external_destination") and expected_destinations is not None and a.get("destination_ip") not in expected_destinations); add("RULE-NET-003", unusual_outbound, "Outbound destination is outside the asset network profile.", {"destination": a.get("destination_ip"), "expected_destinations": expected_destinations}, evaluable=bool(expected_destinations is not None), score=5 if unusual_outbound else 0)
    add("RULE-ID-002", behavior and privileged, "Suspicious activity targets a privileged account.", {"username": a.get("username"), "privilege": a.get("privilege")}, score=5 if behavior and privileged else 0, confidence="HIGH" if behavior and privileged else "MEDIUM")
    add("RULE-ASSET-002", high_asset, "Asset type is explicitly high-value.", {"asset_type": a.get("asset_type")}, score=5 if high_asset else 0)
    alert_count = _num(a.get("alert_count")); burst = alert_count >= cfg["alert_burst"]["alert_count"]; add("RULE-BHV-002", burst, f"The source generated {alert_count:.0f} alerts in the configured window.", {"count": alert_count, "window_seconds": cfg["alert_burst"]["window_seconds"], "source": a.get("source_ip")}, evaluable="alert_count" in a, score=5 if burst else 0)
    multi = username_count >= cfg["multi_account"]["username_count"]; add("RULE-AUTH-003", multi, f"The source targeted {username_count} distinct usernames.", {"username_count": username_count, "window_seconds": cfg["multi_account"]["window_seconds"]}, evaluable=bool(usernames), score=5 if multi else 0, confidence="HIGH" if multi else "MEDIUM")
    vuln_exploit = exploit and bool(cve); add("RULE-VULN-003", vuln_exploit, "Exploit behavior and matching vulnerability evidence co-occur.", {"event_type": a.get("event_type"), "cve": cve, "cvss": cvss, "matching": vuln_exploit}, evaluable=bool(exploit or cve), score=5 if vuln_exploit else 0, confidence="HIGH" if vuln_exploit else "MEDIUM")
    bucket_caps = {"Reputation": 25, "Threat Intelligence": 25, "Behavior": 20, "Vulnerability": 15, "Asset Impact": 10, "Context": 5}; breakdown = {key: 0 for key in bucket_caps}
    for result in results:
        bucket = RULE_BY_ID[result["rule_id"]]["bucket"]
        if bucket in breakdown: breakdown[bucket] = min(bucket_caps[bucket], breakdown[bucket] + int(result["score"]))
    base_score = sum(breakdown.values()); correlation_adjustment = 0; score = min(100, base_score); severity = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 30 else "LOW"; escalation_rules: list[str] = []
    if malicious and critical >= 4: severity = max_severity(severity, "HIGH"); escalation_rules.append("RULE-CORR-003")
    if malicious and malware and critical >= 4: severity = "CRITICAL"; escalation_rules.append("RULE-CORR-004")
    if failed >= 20 and privileged: severity = max_severity(severity, "HIGH"); escalation_rules.append("RULE-RESP-001: brute force + privileged account")
    add("RULE-RESP-001", bool(escalation_rules), "Deterministic minimum/override logic applied." if escalation_rules else "No severity escalation combination matched.", {"base_score": base_score, "final_severity": severity, "escalations": escalation_rules})
    approval = severity in {"HIGH", "CRITICAL"}; add("RULE-RESP-002", approval, "Disruptive response remains approval-gated." if approval else "Low-impact response can remain advisory.", {"approval_required": approval, "status": "PENDING_APPROVAL" if approval else "RECOMMENDATION_ONLY"})
    mitre = []
    for technique in sorted(set(x for result in results for x in result["mitre"] if x in MITRE and result["state"] == "TRIGGERED")):
        name, tactic, description = MITRE[technique]; mitre.append({"id": technique, "name": name, "tactic": tactic, "description": description, "confidence": "HIGH"})
    triggered = [x for x in results if x["state"] == "TRIGGERED"]
    return {"score": score, "final_score": score, "severity": severity, "base_score": base_score, "base_severity": "CRITICAL" if base_score >= 75 else "HIGH" if base_score >= 50 else "MEDIUM" if base_score >= 30 else "LOW", "breakdown": breakdown, "bucket_breakdown": breakdown, "correlation_adjustment": correlation_adjustment, "escalation_rules": escalation_rules, "rules_evaluated": len(results), "triggered_count": len(triggered), "not_triggered_count": sum(x["state"] == "NOT_TRIGGERED" for x in results), "not_evaluable_count": sum(x["state"] == "NOT_EVALUABLE" for x in results), "rule_results": results, "triggered_rules": triggered, "mitre": mitre, "rule_versions": {r["id"]: r["version"] for r in RULES}, "effective_config": cfg, "generated_at": datetime.now(timezone.utc).isoformat()}
