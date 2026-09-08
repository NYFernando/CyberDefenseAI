"""
AI Triage & Incident Classification Engine
Maps security events to MITRE ATT&CK tactics/techniques, calculates dynamic severity (P1-P4),
suppresses false positives using contextual intelligence, and generates explainable AI rationale.
"""

import re
from typing import Any, Dict, Optional, Tuple
from cyberdefense.models import (
    SeverityLevel,
    ThreatIntelEnrichment,
    TriageDecision,
    UnifiedAlert,
)


class AITriageEngine:
    def __init__(self):
        # MITRE ATT&CK signature heuristic patterns
        self.technique_rules = [
            # Ransomware / Data Destruction (T1486)
            (
                re.compile(
                    r"(ransomware|vssadmin|shadowcopy|mass.?encrypt|wannacry|lockbit|\.locked|\.crypted)",
                    re.IGNORECASE,
                ),
                {
                    "tactic": "Impact",
                    "technique_id": "T1486",
                    "technique_name": "Data Encrypted for Impact",
                    "base_severity": SeverityLevel.P1,
                    "default_rec": "Immediately isolate affected host, block C2 communication, and terminate ransomware process.",
                },
            ),
            # Exploitation for RCE / Command Injection (T1203 / T1059)
            (
                re.compile(
                    r"(remote code execution|\brce\b|shellcode|exploit|cve-|cmd\.exe|/bin/sh|/bin/bash|powershell.*-enc|reverse.?shell)",
                    re.IGNORECASE,
                ),
                {
                    "tactic": "Execution",
                    "technique_id": "T1203",
                    "technique_name": "Exploitation for Client Execution",
                    "base_severity": SeverityLevel.P1,
                    "default_rec": "Quarantine victim host, terminate unauthorized shell process, and block exploit source IP.",
                },
            ),
            # Spear-Phishing / Malicious Attachment (T1566)
            (
                re.compile(
                    r"(phish|malicious attachment|macro|weaponized|emotet|invoice.*\.exe|fake.?login)",
                    re.IGNORECASE,
                ),
                {
                    "tactic": "Initial Access",
                    "technique_id": "T1566",
                    "technique_name": "Phishing",
                    "base_severity": SeverityLevel.P2,
                    "default_rec": "Revoke targeted user session tokens, delete weaponized mail artifact, and blacklist sender/hash.",
                },
            ),
            # DNS Tunneling / Exfiltration (T1048)
            (
                re.compile(
                    r"(dns.?tunnel|exfiltration|covert.?channel|high.?entropy.?dns|dnscat|data.?leak)",
                    re.IGNORECASE,
                ),
                {
                    "tactic": "Exfiltration",
                    "technique_id": "T1048",
                    "technique_name": "Exfiltration Over Alternative Protocol",
                    "base_severity": SeverityLevel.P1,
                    "default_rec": "Sinkhole malicious domain, isolate exfiltrating endpoint, and block external DNS resolver.",
                },
            ),
            # Brute Force / Credential Stuffing (T1110)
            (
                re.compile(
                    r"(brute.?force|credential.?stuff|failed password|failed login|auth.*failure|password spray)",
                    re.IGNORECASE,
                ),
                {
                    "tactic": "Credential Access",
                    "technique_id": "T1110",
                    "technique_name": "Brute Force",
                    "base_severity": SeverityLevel.P2,
                    "default_rec": "Enforce immediate firewall IP ban on attacker and initiate credential reset for targeted accounts.",
                },
            ),
            # Port Scanning / Reconnaissance (T1046)
            (
                re.compile(
                    r"(port.?scan|network.?sweep|syn.?scan|service.?discovery|\bnmap\b|\bmasscan\b|probe)",
                    re.IGNORECASE,
                ),
                {
                    "tactic": "Discovery",
                    "technique_id": "T1046",
                    "technique_name": "Network Service Discovery",
                    "base_severity": SeverityLevel.P3,
                    "default_rec": "Log telemetry for pattern analysis, evaluate edge firewall ACLs, and flag scanner for monitoring.",
                },
            ),
        ]

    def _check_false_positive(
        self, alert: UnifiedAlert, enrichment: Optional[ThreatIntelEnrichment]
    ) -> Tuple[bool, Optional[str]]:
        """
        Evaluates whether an alert matches internal authorized behavior,
        known benign scanners, or compliance test windows.
        """
        src_ip = alert.source_ip
        if enrichment and enrichment.source_ip_intel:
            if enrichment.source_ip_intel.get("is_whitelisted"):
                role = enrichment.source_ip_intel.get("role", "Authorized Infrastructure")
                return True, (
                    f"Traffic originated from whitelisted source {src_ip} ({role}). "
                    f"Suppressed as benign internal activity per security policy."
                )

        # Check payload and signature for benign scanner markers
        sig_lower = alert.signature.lower()
        if "authorized scan" in sig_lower or "nessus probe" in sig_lower:
            return True, (
                f"Alert signature explicitly indicates authorized compliance probe: '{alert.signature}'. "
                f"Suppressed by false-positive elimination filter."
            )

        return False, None

    def triage(
        self, alert: UnifiedAlert, enrichment: Optional[ThreatIntelEnrichment]
    ) -> TriageDecision:
        """
        Performs multi-layer AI triage on a normalized alert using threat intel signals,
        MITRE ATT&CK taxonomy, and contextual heuristic reasoning.
        """
        # 1. Evaluate False Positive filter
        is_fp, fp_reason = self._check_false_positive(alert, enrichment)
        if is_fp:
            return TriageDecision(
                severity=SeverityLevel.P4,
                severity_label="Low",
                is_false_positive=True,
                confidence_score=0.99,
                mitre_tactic="Discovery",
                mitre_technique_id="T1046",
                mitre_technique_name="Network Service Discovery",
                rationale=fp_reason,
                recommended_action="Log and dismiss; no automated SOAR containment needed.",
            )

        # 2. Extract context and match MITRE ATT&CK technique
        search_corpus = f"{alert.signature} {alert.process_name or ''} {alert.domain or ''} {str(alert.raw_payload)}"
        matched_rule = None
        for pattern, rule_info in self.technique_rules:
            if pattern.search(search_corpus):
                matched_rule = rule_info
                break

        if not matched_rule:
            # Default fallback for generic suspicious activity
            matched_rule = {
                "tactic": "Initial Access",
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "base_severity": SeverityLevel.P3,
                "default_rec": "Inspect ingress logs and flag IP for analyst review.",
            }

        severity = matched_rule["base_severity"]
        confidence = 0.90
        rationale_points = [
            f"Alert signature '{alert.signature}' classified under MITRE ATT&CK {matched_rule['tactic']} "
            f"({matched_rule['technique_id']}: {matched_rule['technique_name']})."
        ]

        # 3. Dynamic Severity Adjustment via Threat Intelligence Signals
        threat_score = 0
        if enrichment:
            # Check file hash intelligence
            if enrichment.file_hash_intel and enrichment.file_hash_intel.get("is_malicious"):
                f_intel = enrichment.file_hash_intel
                severity = SeverityLevel.P1
                confidence = 0.99
                threat_score = max(threat_score, f_intel.get("threat_score", 95))
                rationale_points.append(
                    f"CRITICAL Threat Intel Hit: SHA256 matches verified malware family "
                    f"'{f_intel.get('malware_family')}' (Signature: {f_intel.get('signature_match')})."
                )

            # Check source IP intelligence
            if enrichment.source_ip_intel and enrichment.source_ip_intel.get("is_malicious"):
                ip_intel = enrichment.source_ip_intel
                ip_score = ip_intel.get("threat_score", 0)
                threat_score = max(threat_score, ip_score)
                if ip_score >= 90:
                    severity = SeverityLevel.P1 if severity in (SeverityLevel.P1, SeverityLevel.P2) else SeverityLevel.P2
                    confidence = max(confidence, 0.98)
                else:
                    severity = SeverityLevel.P2 if severity == SeverityLevel.P3 else severity
                rationale_points.append(
                    f"Source IP {alert.source_ip} flagged with high threat score {ip_score}/100 "
                    f"({ip_intel.get('threat_type')}, Country: {ip_intel.get('country')}, ASN: {ip_intel.get('asn')})."
                )

            # Check domain intelligence
            if enrichment.domain_intel and enrichment.domain_intel.get("is_malicious"):
                d_intel = enrichment.domain_intel
                severity = SeverityLevel.P1
                confidence = max(confidence, 0.97)
                rationale_points.append(
                    f"Correlated domain '{alert.domain}' is blacklisted as {d_intel.get('category')} "
                    f"(Reputation: {d_intel.get('reputation')})."
                )

        # 4. Synthesize final explainable AI rationale
        severity_labels = {
            SeverityLevel.P1: "Critical",
            SeverityLevel.P2: "High",
            SeverityLevel.P3: "Medium",
            SeverityLevel.P4: "Low",
        }

        rationale_text = " | ".join(rationale_points)
        full_rationale = (
            f"[{severity.value} - {severity_labels[severity]}] {rationale_text} "
            f"Calculated confidence: {int(confidence * 100)}%."
        )

        return TriageDecision(
            severity=severity,
            severity_label=severity_labels[severity],
            is_false_positive=False,
            confidence_score=confidence,
            mitre_tactic=matched_rule["tactic"],
            mitre_technique_id=matched_rule["technique_id"],
            mitre_technique_name=matched_rule["technique_name"],
            rationale=full_rationale,
            recommended_action=matched_rule["default_rec"],
        )
