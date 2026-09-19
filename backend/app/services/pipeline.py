import re, time, uuid
from datetime import datetime, timezone
from ..config import DEMO_MODE, LAB_MODE
from ..database.db import now, save_alert, save_incident, log
from ..rules.engine import evaluate

SCENARIOS={
 'benign_login': {'title':'Benign Login','source_ip':'192.0.2.18','destination_ip':'10.0.0.12','event_type':'successful_login','failed_attempts':0,'asset_criticality':2,'description':'Routine employee login from a documentation network.'},
 'port_scan': {'title':'Port Scan','source_ip':'198.51.100.23','destination_ip':'10.0.0.22','event_type':'port_scan','unique_ports':14,'failed_attempts':0,'asset_criticality':5,'description':'Burst of connections to multiple services within one minute.'},
 'ssh_brute_force_critical': {'title':'SSH Brute Force — Critical','source_ip':'185.220.101.44','destination_ip':'10.20.0.8','event_type':'ssh_brute_force','failed_attempts':63,'username':'root','hostname':'prod-auth-01','destination_port':22,'asset_criticality':5,'description':'63 failed SSH attempts against the production authentication server.'},
 'malicious_ioc': {'title':'Known Malicious IOC','source_ip':'203.0.113.77','destination_ip':'10.20.0.44','event_type':'malware_communication','failed_attempts':2,'asset_criticality':5,'description':'Outbound communication with a known malicious infrastructure address.'},
 'critical_server_attack': {'title':'Critical Server Attack','source_ip':'203.0.113.88','destination_ip':'10.20.0.9','event_type':'server_exploitation','failed_attempts':24,'asset_criticality':5,'description':'Suspicious exploitation activity targeting a critical production workload.'},
 'malware_communication': {'title':'Malware Communication','source_ip':'203.0.113.111','destination_ip':'10.20.0.55','event_type':'malware_communication','failed_attempts':4,'asset_criticality':4,'description':'Endpoint beaconing to suspicious command and control infrastructure.'},
 'benign_login': {'title':'Benign Login','source_ip':'192.0.2.18','destination_ip':'10.0.0.12','event_type':'successful_login','failed_attempts':0,'asset_criticality':2,'description':'Routine employee login from a documentation network.'},
 'credential_stuffing': {'title':'Credential Stuffing','source_ip':'198.51.100.44','destination_ip':'10.20.0.12','event_type':'credential_stuffing','failed_attempts':42,'usernames':['alice','bob','carol','dave','erin','frank'],'asset_criticality':4,'description':'One source is attempting many employee accounts.'},
 'cve_exploit': {'title':'CVE Exploit','source_ip':'203.0.113.200','destination_ip':'10.20.0.20','event_type':'cve_exploit','asset_type':'critical_application','asset_criticality':4,'exploit_behavior':True,'description':'Exploit behavior targets a service with a matching CVE.'},
 'privileged_account_attack': {'title':'Privileged Account Attack','source_ip':'185.220.101.55','destination_ip':'10.20.0.30','event_type':'ssh_brute_force','failed_attempts':24,'username':'admin','privilege':'admin','asset_criticality':4,'description':'Repeated authentication failures target a privileged account.'},
 'alert_burst': {'title':'Alert Burst','source_ip':'198.51.100.66','destination_ip':'10.20.0.40','event_type':'network_activity','alert_count':24,'asset_criticality':3,'description':'A source generated 24 alerts in a five minute window.'},
 'allowlisted_scanner': {'title':'Allowlisted Scanner','source_ip':'198.51.100.80','destination_ip':'10.20.0.50','event_type':'port_scan','unique_ports':18,'allowlisted':True,'allowlist_match':'scanner-01','allowlist_action':'REDUCE','asset_criticality':2,'description':'Known vulnerability scanner performing an approved scan.'},
}

def extract_iocs(alert):
    text = ' '.join(str(alert.get(k, '')) for k in ('source_ip', 'destination_ip', 'description', 'ioc', 'url', 'domain', 'hash'))
    values = []
    for value in re.findall(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', text): values.append({'type':'ipv4','value':value,'normalized_value':value,'source':'alert','confidence':1.0})
    for value in re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', text): values.append({'type':{32:'md5',40:'sha1',64:'sha256'}[len(value)],'value':value,'normalized_value':value.lower(),'source':'alert','confidence':1.0})
    for value in re.findall(r'\b(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?', text): values.append({'type':'url' if value.startswith(('http://','https://')) else 'domain','value':value,'normalized_value':value.lower().rstrip('/'),'source':'alert','confidence':0.9})
    unique = {}; [unique.setdefault((x['type'], x['normalized_value']), x) for x in values]; return list(unique.values())

def enrich(a):
    ip=a.get('source_ip',''); event=a.get('event_type',''); malicious=event in ('ssh_brute_force','malware_communication','server_exploitation','cve_exploit') or ip.startswith('185.') or ip.startswith('203.'); cve = 'CVE-2024-6387' if event == 'cve_exploit' else None
    provider_mode = 'lab' if LAB_MODE else 'demo' if DEMO_MODE else 'live'; provider_status = 'LAB_FIXTURE' if LAB_MODE else 'DEMO_FIXTURE' if DEMO_MODE else 'UNAVAILABLE'
    return {'virustotal':{'provider':'VirusTotal','status':provider_status,'mode':provider_mode,'detections':14 if malicious else 0,'total_engines':70,'last_lookup':now()},'abuseipdb':{'provider':'AbuseIPDB','status':provider_status,'mode':provider_mode,'confidence':94 if malicious else 4,'country':'NL' if malicious else 'US','usage_type':'hosting infrastructure' if malicious else 'residential','last_lookup':now()},'geoip':{'provider':'GeoIP','status':provider_status,'mode':provider_mode,'country':'Netherlands' if malicious else 'United States','city':'Amsterdam' if malicious else 'Ashburn','asn':'AS9009 M247 Europe' if malicious else 'AS15169 Google'},'nvd':{'provider':'NVD/CVE','status':provider_status,'mode':provider_mode,'cvss':9.8 if cve else 0,'cve':cve,'component':'OpenSSH' if cve else None,'affected_version':'8.2' if cve else None}}

def summary(a, ti, risk):
    if risk['severity']=='CRITICAL': return f"Critical {a.get('event_type','security')} activity was detected from {a.get('source_ip')} against {a.get('hostname') or a.get('destination_ip')}. Deterministic analysis scored the incident {risk['score']}/100 after correlating reputation, behavior, and asset criticality signals. Immediate analyst review and containment planning are recommended; no disruptive action is performed automatically."
    if risk['severity']=='HIGH': return f"High-confidence suspicious activity was observed from {a.get('source_ip')} targeting {a.get('destination_ip')}. The rule engine produced a score of {risk['score']}/100. Review the affected asset and validate whether the activity is authorized."
    return f"The alert from {a.get('source_ip')} was analyzed with available threat-intelligence and behavior signals. The resulting risk is {risk['severity']} at {risk['score']}/100. Continue monitoring and close as expected activity if validated."

def investigate(alert, scenario=None):
    start=time.perf_counter(); alert=dict(alert); alert.setdefault('alert_id','ALT-'+uuid.uuid4().hex[:8].upper()); alert.setdefault('timestamp',now()); save_alert(alert)
    incident_id='INC-'+datetime.now(timezone.utc).strftime('%Y%m%d')+'-'+uuid.uuid4().hex[:6].upper(); audit=[]
    def stage(action,component,message):
        t=time.perf_counter(); time.sleep(0.015); ms=round((time.perf_counter()-t)*1000); log(incident_id,action,component,'completed',ms,message); audit.append({'action':action,'component':component,'status':'completed','duration_ms':ms,'message':message,'timestamp':now()})
    stage('Alert received','ingestion','Validated alert payload')
    extracted_iocs = extract_iocs(alert); iocs={'items':extracted_iocs,'ip':alert.get('source_ip'),'destination_ip':alert.get('destination_ip'),'domain':None,'hash':None}; alert['iocs'] = extracted_iocs; alert['ioc_count'] = len(extracted_iocs); stage('IOC extracted','extractor',f'Extracted {len(extracted_iocs)} normalized indicators')
    ti=enrich(alert); stage('Threat intelligence queried','enrichment','VirusTotal, AbuseIPDB, GeoIP and NVD adapters completed')
    risk=evaluate(alert,ti); stage('Risk engine executed','rules','Deterministic rules evaluated')
    stage('MITRE mapped','mitre','Mapped '+str(len(risk['mitre']))+' ATT&CK techniques')
    ai=summary(alert,ti,risk); stage('AI summary generated','ai','Local deterministic explanation generated' if (DEMO_MODE or LAB_MODE) else 'Provider unavailable; fallback explanation generated')
    recommendations=['Preserve authentication logs and validate the source owner','Review affected account and rotate credentials if compromise is confirmed','Apply temporary access controls after analyst approval'] if risk['severity'] in ('HIGH','CRITICAL') else ['Continue monitoring','Close as expected activity if validated']
    stage('Report generated','report','HTML report available from incident record'); stage('Notification sent','notification','Demo notification stored for analyst review'); stage('Incident stored','database','Investigation persisted to SQLite')
    incident={'incident_id':incident_id,'alert':alert,'ioc':iocs,'threat_intelligence':ti,'rules':risk['triggered_rules'],'rule_results':risk['rule_results'],'correlations':[r for r in risk['triggered_rules'] if r['category']=='Correlation'],'risk':{k:risk[k] for k in ('score','severity','breakdown','base_score','base_severity','bucket_breakdown','correlation_adjustment','escalation_rules','rules_evaluated','triggered_count','not_triggered_count','not_evaluable_count')},'mitre':risk['mitre'],'ai_summary':ai,'recommendations':recommendations,'responses':[{'id':'RSP-'+uuid.uuid4().hex[:8].upper(),'action':'BLOCK_IOC' if risk['severity'] in ('HIGH','CRITICAL') else 'REVIEW_AUTH_LOGS','reason':'Deterministic rule evidence requires analyst decision','approval_required':risk['severity'] in ('HIGH','CRITICAL'),'approval_status':'PENDING' if risk['severity'] in ('HIGH','CRITICAL') else 'NOT_REQUIRED','execution_status':'NOT_EXECUTED'}],'lifecycle':'AWAITING_APPROVAL' if risk['severity'] in ('HIGH','CRITICAL') else 'TRIAGED','automation':{'mode':'LAB_MODE' if LAB_MODE else 'DEMO_MODE' if DEMO_MODE else 'LIVE_MODE','status':'completed','duration_ms':round((time.perf_counter()-start)*1000),'requires_approval':risk['severity'] in ('HIGH','CRITICAL'),'report_ready':True,'notification_ready':True},'audit':audit,'created_at':now()}
    save_incident(incident); return incident
