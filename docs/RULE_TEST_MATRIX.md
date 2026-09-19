# Rule test matrix

The registry contains 30 versioned definitions. Every rule returns an explicit evaluation state and evidence object. The current direct regression suite covers the legacy compatibility path; the expansion suite is tracked below for the next test pass.

| Rule ID | Name | Category | Condition | Positive case | Negative case | Missing input | Score | MITRE | Response | Test Status |
|---|---|---|---|---|---|---|---:|---|---|---|
| RULE-REP-001 | IOC Reputation | Reputation | AbuseIPDB confidence bands | 94 confidence | 4 confidence | unavailable provider | 0-25 | — | validate source | engine |
| RULE-TI-001 | VirusTotal Malicious Detection | Threat Intelligence | malicious detections | 14 detections | 0 detections | unavailable provider | 0-25 | — | review evidence | engine |
| RULE-BHV-001 | Brute Force Detection | Behavior | failures in 5 minutes | 63 failures | 2 failures | missing attempts | 0-20 | T1110 | review/contain after approval | engine |
| RULE-NET-001 | Port Scan Detection | Network | ports in 60 seconds | 14 ports | 2 ports | missing port count | 0-20 | T1046 | review scanner context | engine |
| RULE-AUTH-001 | Credential Stuffing | Authentication | many users plus failures | 20 users | one user | missing usernames | 0-8 | T1110 | review accounts | engine |
| RULE-AUTH-002 | Suspicious Login | Authentication | explicit context anomaly | new source | normal context | absent context | 0-3 | — | review login | engine |
| RULE-ID-001 | Impossible Travel | Identity | known history and speed | >900 km/h | known normal travel | no history | 0-5 | — | verify session | engine |
| RULE-TI-002 | Known Malicious IOC Match | Threat Intelligence | provider/internal confirmation | confirmed IOC | unverified IOC | provider absent | context | — | verify IOC | engine |
| RULE-MAL-001 | Malware Communication | Malware | asset to malicious IOC | malware event | normal event | no comm evidence | 0-8 | — | isolate after approval | engine |
| RULE-MAL-002 | Command and Control | Malware | beacon/C2 signal | beacon pattern | no beacon | absent signal | 0-5 | T1071 | inspect connections | engine |
| RULE-VULN-001 | CVE Correlation | Vulnerability | matching CVE | CVE attached | no CVE | NVD absent | 0-5 | — | patch review | engine |
| RULE-VULN-002 | CVSS Severity | Vulnerability | CVSS band | 9.8 | 0 | absent CVSS | 0-15 | — | impact context | engine |
| RULE-MITRE-001 | MITRE ATT&CK Behavior Mapping | Threat Intelligence | supported evidence | brute-force evidence | normal login | no behavior | context | supported only | explain | engine |
| RULE-ASSET-001 | Asset Criticality | Asset | 1-5 impact | criticality 5 | criticality 1 | missing asset | 0-10 | — | prioritize | engine |
| RULE-CORR-001 | Threat Intelligence Correlation | Correlation | AbuseIPDB + VT | 94 + 14 | 4 + 0 | provider unavailable | context | — | confidence | engine |
| RULE-CORR-002 | Malicious IOC + Suspicious Behavior | Correlation | two signals | malicious + behavior | one signal | missing signal | context | — | investigate | engine |
| RULE-CORR-003 | Malicious IOC + Critical Asset | Correlation | malicious + critical | yes | either absent | missing asset | escalation | — | minimum HIGH | engine |
| RULE-CORR-004 | Malicious IOC + Malware + Critical Asset | Correlation | critical combination | all three | one absent | missing evidence | escalation | — | CRITICAL + approval | engine |
| RULE-CORR-005 | Multi-IOC Correlation | Correlation | related indicators | 2 IOCs | 1 IOC | no IOC list | context | — | group | engine |
| RULE-OPS-001 | Duplicate Alert Suppression | Operations | fingerprint window | duplicate true | new fingerprint | no fingerprint | context | — | correlate | engine |
| RULE-OPS-002 | False Positive / Allowlist | Operations | trusted match | scanner allowlist | no match | no allowlist | context | — | suppress/reduce/review | engine |
| RULE-NET-002 | Suspicious Network Service | Network | service profile mismatch | SSH unexpected | expected SSH | no profile | 0-5 | — | review service | engine |
| RULE-NET-003 | Unusual Outbound Traffic | Network | destination profile mismatch | external DB flow | expected flow | no profile | 0-5 | — | inspect egress | engine |
| RULE-ID-002 | High-Value Account Attack | Identity | behavior + privilege | admin brute force | employee normal | no privilege | 0-5 | T1110 | approval-gated reset | engine |
| RULE-ASSET-002 | High-Value Asset Attack | Asset | named critical type | domain controller | workstation | no type | 0-5 | — | prioritize | engine |
| RULE-BHV-002 | Alert Velocity / Burst | Behavior | 20 alerts / 5 minutes | 24 alerts | 2 alerts | absent count | 0-5 | T1071 | correlate | engine |
| RULE-AUTH-003 | Multi-Account Attack | Authentication | 5 usernames | 6 users | 1 user | absent usernames | 0-5 | T1110 | review accounts | engine |
| RULE-VULN-003 | Vulnerability Exploitation Behavior | Vulnerability | exploit + CVE | exploit + CVE | CVE only | one missing | 0-5 | — | patch and contain after approval | engine |
| RULE-RESP-001 | Severity Escalation | Response | deterministic combinations | critical combination | none | missing evidence | override | — | record escalation | engine |
| RULE-RESP-002 | Human-in-the-Loop Response | Response | high/critical review | critical | low | severity absent | approval | — | require approval | engine |
