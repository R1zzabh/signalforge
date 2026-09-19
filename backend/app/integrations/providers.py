"""Named adapters used by the service layer and easy to replace with httpx calls."""
from .base import Provider

class VirusTotalProvider(Provider): name = "VirusTotal"
class AbuseIPDBProvider(Provider): name = "AbuseIPDB"
class NVDProvider(Provider): name = "NVD"
class GeoIPProvider(Provider): name = "GeoIP"
class MitreProvider(Provider): name = "MITRE"
class OpenAIProvider(Provider): name = "OpenAI"
class OutlookProvider(Provider): name = "Outlook"
