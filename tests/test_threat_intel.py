"""
Unit Tests for Offline-First Threat Intelligence Enrichment Engine
"""

import pytest
from cyberdefense.models import ThreatIntelEnrichment
from cyberdefense.threat_intel import ThreatIntelEngine


@pytest.fixture
def intel_engine():
    return ThreatIntelEngine()


@pytest.mark.asyncio
async def test_enrich_known_malicious_ip(intel_engine):
    intel = await intel_engine.enrich_ip("198.51.100.23")
    assert intel is not None
    assert intel["is_malicious"] is True
    assert intel["threat_score"] >= 90
    assert "Cobalt Strike" in intel["threat_type"]
    assert intel["country"] == "NL"
    assert intel["source"] == "local_threat_db"
    await intel_engine.close()


@pytest.mark.asyncio
async def test_enrich_benign_whitelisted_ip(intel_engine):
    intel = await intel_engine.enrich_ip("10.0.0.254")
    assert intel is not None
    assert intel["is_malicious"] is False
    assert intel.get("is_whitelisted") is True
    assert "Nessus" in intel["role"]
    assert intel["source"] == "local_whitelist"
    await intel_engine.close()


@pytest.mark.asyncio
async def test_enrich_private_ip(intel_engine):
    intel = await intel_engine.enrich_ip("192.168.1.100")
    assert intel is not None
    assert intel["is_malicious"] is False
    assert intel["threat_score"] == 0
    assert intel["country"] == "LOCAL"
    await intel_engine.close()


@pytest.mark.asyncio
async def test_enrich_known_malicious_hash(intel_engine):
    hash_val = "ed01ebf83334a16f6e8a7d637a9de95a4d51f21e7b402b9fef5b724867ba83c2"
    intel = await intel_engine.enrich_hash(hash_val)
    assert intel is not None
    assert intel["is_malicious"] is True
    assert intel["threat_level"] == "CRITICAL"
    assert "WannaCry" in intel["malware_family"]
    assert intel["source"] == "local_threat_db"
    await intel_engine.close()


@pytest.mark.asyncio
async def test_enrich_unknown_hash(intel_engine):
    hash_val = "0000000000000000000000000000000000000000000000000000000000000000"
    intel = await intel_engine.enrich_hash(hash_val)
    assert intel is not None
    assert intel["is_malicious"] is False
    assert intel["threat_level"] == "UNKNOWN"
    await intel_engine.close()


def test_enrich_known_malicious_domain():
    engine = ThreatIntelEngine()
    intel = engine.enrich_domain("ransom-payment-portal.onion.sh")
    assert intel is not None
    assert intel["is_malicious"] is True
    assert "Ransomware" in intel["category"]


@pytest.mark.asyncio
async def test_enrich_all_combined(intel_engine):
    enrichment: ThreatIntelEnrichment = await intel_engine.enrich_all(
        source_ip="203.0.113.50",
        file_hash="4f952f4c3bf5e15645a859e9a4e8d3568c07e05f013238645e59b20756784013",
        domain="exfil.malicious-c2.net",
    )
    assert enrichment.source_ip_intel["is_malicious"] is True
    assert enrichment.file_hash_intel["is_malicious"] is True
    assert enrichment.domain_intel["is_malicious"] is True
    assert enrichment.geo_intel["source_country"] == "RU"
    await intel_engine.close()
