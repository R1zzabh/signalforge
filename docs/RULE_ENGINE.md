# Rule engine

Risk is capped at 100. The engine applies reputation, VirusTotal detections, brute force, port scan, correlation, asset criticality, and CVSS rules. Severity is always derived from the final score: LOW 0–29, MEDIUM 30–49, HIGH 50–74, CRITICAL 75–100. AI never changes score, severity, or triggered-rule state.
