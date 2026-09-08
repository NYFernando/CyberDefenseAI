"""
Threat Intelligence Enrichment Engine
Offline-First architecture with pre-bundled datasets and optional live API connectors
(VirusTotal, AbuseIPDB) featuring automatic silent fallback.
"""

import ipaddress
import logging
from typing import Any, Dict, Optional
import httpx

from cyberdefense.config import ABUSEIPDB_API_KEY, VT_API_KEY
from cyberdefense.models import ThreatIntelEnrichment
from cyberdefense.threat_db_data import (
    BENIGN_WHITELIST,
    KNOWN_MALICIOUS_DOMAINS,
    KNOWN_MALICIOUS_HASHES,
    KNOWN_MALICIOUS_IPS,
)

logger = logging.getLogger("cyberdefense.threat_intel")


class ThreatIntelEngine:
    def __init__(
        self,
        vt_api_key: Optional[str] = None,
        abuseipdb_api_key: Optional[str] = None,
    ):
        self.vt_api_key = vt_api_key or VT_API_KEY
        self.abuseipdb_api_key = abuseipdb_api_key or ABUSEIPDB_API_KEY
        self.http_client = httpx.AsyncClient(timeout=2.0)

    async def close(self):
        await self.http_client.aclose()

    def is_private_ip(self, ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_private or ip_obj.is_loopback
        except ValueError:
            return False

    async def enrich_ip(self, ip: Optional[str]) -> Optional[Dict[str, Any]]:
        if not ip:
            return None

        ip = ip.strip()

        # 1. Check local benign whitelist
        if ip in BENIGN_WHITELIST:
            whitelist_entry = BENIGN_WHITELIST[ip]
            return {
                "ip": ip,
                "is_malicious": False,
                "is_whitelisted": True,
                "threat_score": 0,
                "role": whitelist_entry["role"],
                "rationale": whitelist_entry["rationale"],
                "source": "local_whitelist",
            }

        # 2. Check local malicious database (high-fidelity offline match)
        if ip in KNOWN_MALICIOUS_IPS:
            intel = KNOWN_MALICIOUS_IPS[ip].copy()
            intel["ip"] = ip
            intel["source"] = "local_threat_db"
            return intel

        # 3. Optional live AbuseIPDB connector (if key provided, with silent fallback)
        if self.abuseipdb_api_key and not self.is_private_ip(ip):
            try:
                headers = {
                    "Key": self.abuseipdb_api_key,
                    "Accept": "application/json",
                }
                params = {"ipAddress": ip, "maxAgeInDays": "90"}
                resp = await self.http_client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers=headers,
                    params=params,
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    return {
                        "ip": ip,
                        "is_malicious": score >= 50,
                        "threat_score": score,
                        "threat_type": (
                            "AbuseIPDB Flagged" if score >= 50 else "Clean"
                        ),
                        "country": data.get("countryCode", "UNKNOWN"),
                        "asn": f"AS{data.get('asn', 'UNKNOWN')}",
                        "source": "abuseipdb_live",
                    }
            except Exception as ex:
                logger.debug(
                    "AbuseIPDB query failed (%s), falling back to offline DB",
                    ex,
                )

        # 4. Fallback baseline for private or unrecognized public IP
        is_priv = self.is_private_ip(ip)
        return {
            "ip": ip,
            "is_malicious": False,
            "threat_score": 5 if not is_priv else 0,
            "threat_type": "Internal Host" if is_priv else "Unrated External IP",
            "asn": "Private Network" if is_priv else "AS-UNKNOWN",
            "country": "LOCAL" if is_priv else "US",
            "source": "local_baseline",
        }

    async def enrich_hash(
        self, file_hash: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        if not file_hash:
            return None

        file_hash = file_hash.strip().lower()

        # 1. Local Threat DB match
        if file_hash in KNOWN_MALICIOUS_HASHES:
            intel = KNOWN_MALICIOUS_HASHES[file_hash].copy()
            intel["file_hash"] = file_hash
            intel["source"] = "local_threat_db"
            return intel

        # 2. Optional live VirusTotal connector (if key provided, with silent fallback)
        if self.vt_api_key and len(file_hash) in (32, 40, 64):
            try:
                headers = {"x-apikey": self.vt_api_key}
                resp = await self.http_client.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers=headers,
                )
                if resp.status_code == 200:
                    attributes = (
                        resp.json().get("data", {}).get("attributes", {})
                    )
                    stats = attributes.get("last_analysis_stats", {})
                    malicious_votes = stats.get("malicious", 0)
                    return {
                        "file_hash": file_hash,
                        "is_malicious": malicious_votes > 0,
                        "threat_level": (
                            "CRITICAL"
                            if malicious_votes > 15
                            else ("HIGH" if malicious_votes > 3 else "LOW")
                        ),
                        "malware_family": attributes.get(
                            "meaningful_name", "Unknown VT Detection"
                        ),
                        "signature_match": f"VirusTotal {malicious_votes} engines flagged",
                        "threat_score": min(malicious_votes * 3, 100),
                        "source": "virustotal_live",
                    }
            except Exception as ex:
                logger.debug(
                    "VirusTotal query failed (%s), falling back to offline DB",
                    ex,
                )

        return {
            "file_hash": file_hash,
            "is_malicious": False,
            "threat_level": "UNKNOWN",
            "threat_score": 0,
            "source": "local_baseline",
        }

    def enrich_domain(self, domain: Optional[str]) -> Optional[Dict[str, Any]]:
        if not domain:
            return None

        domain = domain.strip().lower()
        if domain in KNOWN_MALICIOUS_DOMAINS:
            intel = KNOWN_MALICIOUS_DOMAINS[domain].copy()
            intel["domain"] = domain
            intel["source"] = "local_threat_db"
            return intel

        return {
            "domain": domain,
            "is_malicious": False,
            "threat_score": 0,
            "source": "local_baseline",
        }

    async def enrich_all(
        self,
        source_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
        file_hash: Optional[str] = None,
        domain: Optional[str] = None,
    ) -> ThreatIntelEnrichment:
        src_intel = await self.enrich_ip(source_ip)
        dst_intel = await self.enrich_ip(dest_ip)
        hash_intel = await self.enrich_hash(file_hash)
        dom_intel = self.enrich_domain(domain)

        primary_provider = "local_threat_db"
        if src_intel and src_intel.get("source") == "abuseipdb_live":
            primary_provider = "abuseipdb_live"
        elif hash_intel and hash_intel.get("source") == "virustotal_live":
            primary_provider = "virustotal_live"

        geo = None
        if src_intel and "country" in src_intel:
            geo = {
                "source_country": src_intel.get("country"),
                "source_asn": src_intel.get("asn"),
            }

        return ThreatIntelEnrichment(
            source_ip_intel=src_intel,
            dest_ip_intel=dst_intel,
            file_hash_intel=hash_intel,
            domain_intel=dom_intel,
            geo_intel=geo,
            provider=primary_provider,
        )
