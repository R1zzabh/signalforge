from app.rules.engine import evaluate

def test_critical_brute_force():
    r=evaluate({'failed_attempts':63,'asset_criticality':5},{'abuseipdb':{'confidence':94},'virustotal':{'detections':14},'nvd':{'cvss':0}})
    assert r['score']==85
    assert r['severity']=='CRITICAL'
    assert any(x['mitre']=='T1110' for x in r['triggered_rules'])

def test_port_scan():
    r=evaluate({'failed_attempts':0,'unique_ports':14,'asset_criticality':5},{'abuseipdb':{'confidence':4},'virustotal':{'detections':0},'nvd':{'cvss':0}})
    assert r['severity']=='MEDIUM'
    assert any(x['mitre']=='T1046' for x in r['triggered_rules'])

def test_benign():
    r=evaluate({'failed_attempts':0,'unique_ports':0,'asset_criticality':1},{'abuseipdb':{'confidence':4},'virustotal':{'detections':0},'nvd':{'cvss':0}})
    assert r['score']==0 and r['severity']=='LOW'
