from app.main import LabEvent, ingest_lab_event, lab_health

def test_lab_mode_is_isolated():
    status = lab_health()
    assert status["environment"] == "LAB_MODE"
    assert status["isolation"] == "ISOLATED"

def test_normal_lab_event_enters_ingestion_path():
    result = ingest_lab_event(LabEvent(event_type="AUTH_SUCCESS", source_ip="172.30.0.10", username="alice", scenario="normal_login"))
    assert result["accepted"] is True
    assert result["event_id"].startswith("EVT-")
    assert result["incident"] is None

def test_vulnerability_lab_event_creates_incident_from_telemetry():
    result = ingest_lab_event(LabEvent(event_type="VULNERABILITY_EXPLOIT_ATTEMPT", source_ip="172.30.0.14", target_asset="WEB-SERVER-01", asset_criticality=3, scenario="cve_lab", cve="CVE-2024-6387", cvss=9.8))
    assert result["accepted"] is True
    assert result["incident"]["alert"]["event_type"] == "cve_exploit"
    assert result["incident"]["risk"]["rules_evaluated"] == 30

def test_lab_event_schema_retains_raw_context():
    result = ingest_lab_event(LabEvent(event_type="NETWORK_CONNECTION", source_ip="172.30.0.13", destination_port=443, protocol="TCP", target_asset="WEB-SERVER-01", scenario="port_scan"))
    assert result["accepted"] is True
    assert result["risk"]["rules_evaluated"] == 30
