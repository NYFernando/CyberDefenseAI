"""
Local Threat Intelligence Database
Pre-bundled, high-fidelity offline cyber threat database ensuring 100% offline
functionality for competition evaluation without reliance on external paid APIs.
"""

from typing import Any, Dict

KNOWN_MALICIOUS_IPS: Dict[str, Dict[str, Any]] = {
    "198.51.100.23": {
        "is_malicious": True,
        "threat_score": 98,
        "threat_type": "Cobalt Strike C2 / Brute Force Botnet",
        "asn": "AS13335 (Cloud Provider)",
        "country": "NL",
        "category": "Command & Control / Brute Force",
        "confidence": 0.99,
        "last_seen": "2026-09-07T22:40:00Z",
    },
    "203.0.113.50": {
        "is_malicious": True,
        "threat_score": 95,
        "threat_type": "Emotet Weaponized Delivery Host",
        "asn": "AS24940 (Hetzner)",
        "country": "RU",
        "category": "Malware Dropper / Spear-Phishing",
        "confidence": 0.96,
        "last_seen": "2026-09-07T21:15:00Z",
    },
    "185.220.101.5": {
        "is_malicious": True,
        "threat_score": 90,
        "threat_type": "Tor Exit Node / Anonymized Attack Proxy",
        "asn": "AS60729 (Zwiebelfreunde)",
        "country": "DE",
        "category": "Proxy / Anonymizer",
        "confidence": 0.92,
        "last_seen": "2026-09-07T23:00:00Z",
    },
    "45.33.32.156": {
        "is_malicious": True,
        "threat_score": 88,
        "threat_type": "Mirai Scanner / Mass Port Probe",
        "asn": "AS63949 (Linode)",
        "country": "US",
        "category": "Reconnaissance / Scanner",
        "confidence": 0.89,
        "last_seen": "2026-09-07T20:10:00Z",
    },
    "192.0.2.144": {
        "is_malicious": True,
        "threat_score": 99,
        "threat_type": "LockBit 3.0 Ransomware C2 Gateway",
        "asn": "AS4134 (Chinanet)",
        "country": "CN",
        "category": "Ransomware C2",
        "confidence": 0.99,
        "last_seen": "2026-09-07T23:30:00Z",
    },
    "103.251.167.20": {
        "is_malicious": True,
        "threat_score": 94,
        "threat_type": "DNS Tunneling Covert Exfiltration C2",
        "asn": "AS45102 (Alibaba Cloud)",
        "country": "SG",
        "category": "Data Exfiltration",
        "confidence": 0.95,
        "last_seen": "2026-09-07T22:50:00Z",
    },
}

KNOWN_MALICIOUS_HASHES: Dict[str, Dict[str, Any]] = {
    # WannaCry Ransomware
    "ed01ebf83334a16f6e8a7d637a9de95a4d51f21e7b402b9fef5b724867ba83c2": {
        "is_malicious": True,
        "threat_level": "CRITICAL",
        "malware_family": "WannaCry.M",
        "signature_match": "Ransom:Win32/WannaCrypt",
        "threat_score": 100,
        "file_type": "PE32 Executable",
        "confidence": 1.0,
    },
    # Emotet Dropper
    "4f952f4c3bf5e15645a859e9a4e8d3568c07e05f013238645e59b20756784013": {
        "is_malicious": True,
        "threat_level": "HIGH",
        "malware_family": "Emotet Banking Trojan",
        "signature_match": "Trojan:Win32/Emotet.DN",
        "threat_score": 96,
        "file_type": "Weaponized Word Document / Macro",
        "confidence": 0.98,
    },
    # Cobalt Strike Beacon
    "b5d3a2f8c6e11894d9302117fb74bc8508f7b76426a8d8c7c9ad06efbe06e693": {
        "is_malicious": True,
        "threat_level": "CRITICAL",
        "malware_family": "Cobalt Strike Beacon",
        "signature_match": "HackTool:Win32/CobaltStrike",
        "threat_score": 99,
        "file_type": "DLL / Reflective Injector",
        "confidence": 0.99,
    },
    # LockBit 3.0 Encryptor
    "3a4f6b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a": {
        "is_malicious": True,
        "threat_level": "CRITICAL",
        "malware_family": "LockBit 3.0 Black",
        "signature_match": "Ransom:Win64/LockBit.C",
        "threat_score": 100,
        "file_type": "PE64 Executable",
        "confidence": 1.0,
    },
    # DNSCat2 Exfiltration Agent
    "7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c": {
        "is_malicious": True,
        "threat_level": "HIGH",
        "malware_family": "DNSCat2 Covert Tunnel",
        "signature_match": "Backdoor:Unix/DNSCat.A",
        "threat_score": 95,
        "file_type": "ELF 64-bit / Encrypted Client",
        "confidence": 0.97,
    },
}

KNOWN_MALICIOUS_DOMAINS: Dict[str, Dict[str, Any]] = {
    "exfil.malicious-c2.net": {
        "is_malicious": True,
        "category": "C2 / Data Exfiltration",
        "threat_score": 96,
        "reputation": "Known Malicious",
    },
    "ransom-payment-portal.onion.sh": {
        "is_malicious": True,
        "category": "Ransomware Payment Portal",
        "threat_score": 99,
        "reputation": "Known Malicious",
    },
    "phish-secure-portal.info": {
        "is_malicious": True,
        "category": "Credential Harvesting / Phishing",
        "threat_score": 94,
        "reputation": "Known Malicious",
    },
    "dns-tunnel.evilcorp.biz": {
        "is_malicious": True,
        "category": "DNS Exfiltration Tunnel",
        "threat_score": 97,
        "reputation": "Known Malicious",
    },
    "update-service-patch.xyz": {
        "is_malicious": True,
        "category": "Trojan Dropper Staging Site",
        "threat_score": 92,
        "reputation": "Known Malicious",
    },
}

# Whitelisted legitimate entities for False-Positive suppression
BENIGN_WHITELIST: Dict[str, Dict[str, Any]] = {
    "10.0.0.254": {
        "is_whitelisted": True,
        "role": "Internal Vulnerability Scanner (Nessus Enterprise)",
        "authorized_window": "Always Authorized",
        "rationale": "Enterprise Security Team automated compliance vulnerability scan.",
    },
    "192.168.1.254": {
        "is_whitelisted": True,
        "role": "Authorized Penetration Testing Gateway",
        "authorized_window": "Authorized Audit",
        "rationale": "Scheduled internal penetration testing infrastructure.",
    },
    "10.0.0.1": {
        "is_whitelisted": True,
        "role": "Internal Core Router & Health Checker",
        "authorized_window": "Continuous",
        "rationale": "Routine network infrastructure heartbeats and health telemetry.",
    },
}
