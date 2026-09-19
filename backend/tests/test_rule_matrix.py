import pytest
from app.rules.engine import evaluate

BASE_TI = {"abuseipdb": {"confidence": 94}, "virustotal": {"detections": 14}, "nvd": {"cvss": 9.8, "cve": "CVE-2024-6387"}}

CASES = {
    "RULE-REP-001": ({}, BASE_TI),
    "RULE-TI-001": ({}, BASE_TI),
    "RULE-BHV-001": ({"failed_attempts": 50}, {}),
    "RULE-NET-001": ({"unique_ports": 10}, {}),
    "RULE-AUTH-001": ({"failed_attempts": 10, "usernames": ["a", "b"]}, {}),
    "RULE-AUTH-002": ({"unusual_source": True}, {}),
    "RULE-ID-001": ({"previous_login": {"country": "IN"}, "coordinates": {"country": "DE"}, "travel_speed_kmh": 1000}, {}),
    "RULE-TI-002": ({"malicious_ioc": True}, {}),
    "RULE-MAL-001": ({"malware_communication": True, "malicious_ioc": True}, {}),
    "RULE-MAL-002": ({"c2_signal": True}, {}),
    "RULE-VULN-001": ({"cve": "CVE-2024-1"}, {}),
    "RULE-VULN-002": ({}, {"nvd": {"cvss": 9.8}}),
    "RULE-MITRE-001": ({"failed_attempts": 10}, {}),
    "RULE-ASSET-001": ({"asset_criticality": 5}, {}),
    "RULE-CORR-001": ({}, BASE_TI),
    "RULE-CORR-002": ({"malicious_ioc": True, "suspicious_behavior": True}, {}),
    "RULE-CORR-003": ({"malicious_ioc": True, "asset_criticality": 4}, {}),
    "RULE-CORR-004": ({"malicious_ioc": True, "malware_communication": True, "asset_criticality": 4}, {}),
    "RULE-CORR-005": ({"iocs": [{"value": "a"}, {"value": "b"}]}, {}),
    "RULE-OPS-001": ({"duplicate": True}, {}),
    "RULE-OPS-002": ({"allowlisted": True}, {}),
    "RULE-NET-002": ({"expected_services": ["HTTPS"], "protocol": "SSH"}, {}),
    "RULE-NET-003": ({"expected_destinations": ["10.0.0.1"], "destination_ip": "203.0.113.8", "external_destination": True}, {}),
    "RULE-ID-002": ({"failed_attempts": 10, "username": "admin"}, {}),
    "RULE-ASSET-002": ({"asset_type": "domain_controller"}, {}),
    "RULE-BHV-002": ({"alert_count": 20}, {}),
    "RULE-AUTH-003": ({"usernames": ["a", "b", "c", "d", "e"]}, {}),
    "RULE-VULN-003": ({"event_type": "cve_exploit", "cve": "CVE-2024-1"}, {}),
    "RULE-RESP-001": ({"malicious_ioc": True, "malware_communication": True, "asset_criticality": 5}, BASE_TI),
    "RULE-RESP-002": ({"malicious_ioc": True, "malware_communication": True, "asset_criticality": 5}, BASE_TI),
}

@pytest.mark.parametrize("rule_id", list(CASES))
def test_positive_rule_case(rule_id):
    alert, ti = CASES[rule_id]
    result = evaluate(alert, ti)
    match = next(item for item in result["rule_results"] if item["rule_id"] == rule_id)
    assert match["state"] == "TRIGGERED", (rule_id, match)
    assert match["evidence"] is not None

@pytest.mark.parametrize("rule_id", list(CASES))
def test_negative_rule_case(rule_id):
    result = evaluate({"asset_criticality": 1}, {"abuseipdb": {"confidence": 0}, "virustotal": {"detections": 0}, "nvd": {"cvss": 0}})
    match = next(item for item in result["rule_results"] if item["rule_id"] == rule_id)
    assert match["state"] in {"NOT_TRIGGERED", "NOT_EVALUABLE"}

@pytest.mark.parametrize("rule_id", list(CASES))
def test_rule_result_is_versioned_and_explainable(rule_id):
    result = evaluate({}, {})
    match = next(item for item in result["rule_results"] if item["rule_id"] == rule_id)
    assert match["version"] and match["reason"] and "evidence" in match
