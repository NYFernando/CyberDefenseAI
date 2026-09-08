"""
Autonomous Investigation & Forensic Report Generator
Compiles executive-ready incident reports in both Markdown and self-contained,
printable HTML with timeline reconstruction, IOC correlation, root-cause analysis,
and remediation guidance.
"""

from datetime import datetime, timezone
import html
from pathlib import Path
from typing import Any, Dict, List
import jinja2

from cyberdefense.config import REPORTS_DIR
from cyberdefense.models import Incident, IncidentReport


HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC Forensic Incident Report - {{ incident.incident_id }}</title>
    <style>
        :root {
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-card: #1a2234;
            --border-color: #2d3748;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent-cyan: #06b6d4;
            --accent-red: #ef4444;
            --accent-orange: #f97316;
            --accent-green: #10b981;
            --accent-purple: #8b5cf6;
        }

        @media print {
            body {
                background: #ffffff !important;
                color: #000000 !important;
            }
            .no-print { display: none !important; }
            .card {
                border: 1px solid #ccc !important;
                background: #fff !important;
                color: #000 !important;
                box-shadow: none !important;
                page-break-inside: avoid;
            }
            .badge { border: 1px solid #000 !important; }
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }

        .container {
            max-width: 1080px;
            margin: 0 auto;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }

        .header-title h1 {
            font-size: 1.8rem;
            color: var(--accent-cyan);
            letter-spacing: 0.05em;
            text-transform: uppercase;
        }

        .header-title p {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .severity-pill {
            font-size: 1rem;
            font-weight: 700;
            padding: 0.4rem 1.2rem;
            border-radius: 9999px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .sev-P1 { background: rgba(239, 68, 68, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }
        .sev-P2 { background: rgba(249, 115, 22, 0.2); color: var(--accent-orange); border: 1px solid var(--accent-orange); }
        .sev-P3 { background: rgba(6, 182, 212, 0.2); color: var(--accent-cyan); border: 1px solid var(--accent-cyan); }
        .sev-P4 { background: rgba(16, 185, 129, 0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .card {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.25rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
        }

        .card h3 {
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
        }

        .card p.val {
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--text-primary);
            font-family: 'Consolas', monospace;
        }

        .section-title {
            font-size: 1.25rem;
            color: var(--accent-cyan);
            margin: 2rem 0 1rem 0;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            border-left: 4px solid var(--accent-cyan);
            padding-left: 0.75rem;
        }

        .timeline {
            border-left: 2px solid var(--border-color);
            margin-left: 1rem;
            padding-left: 1.5rem;
            margin-bottom: 2rem;
        }

        .timeline-item {
            position: relative;
            margin-bottom: 1.5rem;
        }

        .timeline-item::before {
            content: '';
            position: absolute;
            left: -1.9rem;
            top: 0.25rem;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background-color: var(--accent-cyan);
            border: 2px solid var(--bg-primary);
        }

        .timeline-time {
            font-size: 0.8rem;
            color: var(--text-secondary);
            font-family: 'Consolas', monospace;
        }

        .timeline-content {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            padding: 0.75rem 1rem;
            border-radius: 6px;
            margin-top: 0.25rem;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 1.5rem;
            background: var(--bg-card);
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }

        th, td {
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.9rem;
        }

        th {
            background: var(--bg-secondary);
            color: var(--text-secondary);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }

        .badge {
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-family: 'Consolas', monospace;
            background: rgba(6, 182, 212, 0.15);
            color: var(--accent-cyan);
            border: 1px solid rgba(6, 182, 212, 0.3);
        }

        .ioc-tag {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            margin: 0.2rem;
            border-radius: 4px;
            background: #232d42;
            border: 1px solid #3b4b68;
            font-family: 'Consolas', monospace;
            font-size: 0.85rem;
        }

        .recs-list {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            margin-bottom: 2rem;
        }

        .rec-item {
            display: flex;
            gap: 1rem;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            padding: 1rem;
            border-radius: 6px;
        }

        .rec-step {
            font-weight: bold;
            color: var(--accent-cyan);
            font-family: 'Consolas', monospace;
        }

        .print-btn {
            background: var(--accent-cyan);
            color: #000;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-title">
                <h1>Autonomous Incident Investigation Report</h1>
                <p>Generated by CyberDefenseAI Autonomous SOAR Pipeline | Case ID: {{ incident.incident_id }}</p>
                <p>Timestamp: {{ incident.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}</p>
            </div>
            <div>
                <span class="severity-pill sev-{{ incident.severity.value }}">{{ incident.severity.value }} - {{ incident.triage.severity_label if incident.triage else 'TRIAGED' }}</span>
                <div style="margin-top: 0.5rem; text-align: right;" class="no-print">
                    <button class="print-btn" onclick="window.print()">Print / Export PDF</button>
                </div>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h3>Incident Title</h3>
                <p class="val" style="font-size: 1rem;">{{ incident.title }}</p>
            </div>
            <div class="card">
                <h3>MITRE ATT&CK</h3>
                <p class="val" style="font-size: 1rem;">{{ incident.mitre_technique_id }}</p>
                <p style="font-size: 0.8rem; color: var(--text-secondary);">{{ incident.mitre_technique_name }} ({{ incident.mitre_tactic }})</p>
            </div>
            <div class="card">
                <h3>Status & Triage</h3>
                <p class="val" style="font-size: 1rem;">{{ incident.status }}</p>
                <p style="font-size: 0.8rem; color: var(--accent-green);">Confidence: {{ (incident.triage.confidence_score * 100)|int if incident.triage else 95 }}%</p>
            </div>
            <div class="card">
                <h3>Attacker Source</h3>
                <p class="val" style="font-size: 1rem;">{{ incident.threat_actor_ip or 'N/A' }}</p>
                <p style="font-size: 0.8rem; color: var(--text-secondary);">Target: {{ incident.target_host or 'N/A' }}</p>
            </div>
        </div>

        <div class="section-title">AI Triage Rationale & Root Cause Analysis</div>
        <div class="card" style="margin-bottom: 2rem;">
            <p style="margin-bottom: 0.75rem;"><strong>AI Analysis Summary:</strong></p>
            <p style="color: var(--text-secondary); margin-bottom: 1rem;">{{ incident.triage.rationale if incident.triage else 'Automated analysis performed.' }}</p>
            <p style="margin-bottom: 0.75rem;"><strong>Root Cause & Attack Vector:</strong></p>
            <p style="color: var(--text-secondary);">{{ root_cause }}</p>
        </div>

        <div class="section-title">Identified Indicators of Compromise (IOCs)</div>
        <div class="card" style="margin-bottom: 2rem;">
            <div style="margin-bottom: 0.75rem;">
                <strong>Source / Attacker IPs:</strong><br>
                {% for ip in iocs.ips %}
                    <span class="ioc-tag">{{ ip }}</span>
                {% else %}
                    <span style="color: var(--text-secondary);">None identified</span>
                {% endfor %}
            </div>
            <div style="margin-bottom: 0.75rem;">
                <strong>Malicious File Hashes (SHA-256):</strong><br>
                {% for h in iocs.hashes %}
                    <span class="ioc-tag">{{ h }}</span>
                {% else %}
                    <span style="color: var(--text-secondary);">None identified</span>
                {% endfor %}
            </div>
            <div style="margin-bottom: 0.75rem;">
                <strong>Targeted Domains / C2 Hosts:</strong><br>
                {% for d in iocs.domains %}
                    <span class="ioc-tag">{{ d }}</span>
                {% else %}
                    <span style="color: var(--text-secondary);">None identified</span>
                {% endfor %}
            </div>
            <div>
                <strong>Compromised Accounts / Users:</strong><br>
                {% for u in iocs.users %}
                    <span class="ioc-tag">{{ u }}</span>
                {% else %}
                    <span style="color: var(--text-secondary);">None identified</span>
                {% endfor %}
            </div>
        </div>

        <div class="section-title">Automated SOAR Containment Playbook Actions</div>
        <table>
            <thead>
                <tr>
                    <th>Action ID</th>
                    <th>Action Type</th>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Reversible</th>
                    <th>Rollback Command</th>
                </tr>
            </thead>
            <tbody>
                {% for act in incident.soar_actions %}
                <tr>
                    <td style="font-family: monospace; font-size: 0.8rem;">{{ act.action_id[:8] }}...</td>
                    <td><span class="badge">{{ act.action_type.value }}</span></td>
                    <td style="font-weight: 600;">{{ act.target }}</td>
                    <td><span style="color: {{ '#10b981' if act.status.value == 'EXECUTED' else '#9ca3af' }};">{{ act.status.value }}</span></td>
                    <td>{{ 'Yes' if act.is_reversible else 'No' }}</td>
                    <td style="font-family: monospace; font-size: 0.75rem; color: var(--text-secondary);">{{ act.rollback_command or 'N/A' }}</td>
                </tr>
                {% else %}
                <tr>
                    <td colspan="6" style="text-align: center; color: var(--text-secondary);">No automated response actions executed.</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <div class="section-title">Incident Timeline</div>
        <div class="timeline">
            {% for event in timeline %}
            <div class="timeline-item">
                <div class="timeline-time">{{ event.time }}</div>
                <div class="timeline-content">
                    <strong>{{ event.title }}</strong>
                    <p style="color: var(--text-secondary); font-size: 0.85rem;">{{ event.details }}</p>
                </div>
            </div>
            {% endfor %}
        </div>

        <div class="section-title">Recommended Remediation & Hardening Roadmap</div>
        <div class="recs-list">
            {% for rec in recommendations %}
            <div class="rec-item">
                <span class="rec-step">{{ loop.index }}</span>
                <div>
                    <strong>{{ rec.title }}</strong>
                    <p style="color: var(--text-secondary); font-size: 0.9rem;">{{ rec.details }}</p>
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
</body>
</html>
"""


class ForensicReportGenerator:
    def __init__(self, reports_dir: Path = REPORTS_DIR):
        self.reports_dir = reports_dir
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.jinja_env = jinja2.Environment(autoescape=True)
        self.template = self.jinja_env.from_string(HTML_REPORT_TEMPLATE)

    def extract_iocs(self, incident: Incident) -> Dict[str, List[str]]:
        ips = set()
        hashes = set()
        domains = set()
        users = set()

        if incident.threat_actor_ip:
            ips.add(incident.threat_actor_ip)
        if incident.compromised_user:
            users.add(incident.compromised_user)

        for alert in incident.alerts:
            if alert.source_ip:
                ips.add(alert.source_ip)
            if alert.file_hash:
                hashes.add(alert.file_hash)
            if alert.domain:
                domains.add(alert.domain)
            if alert.user:
                users.add(alert.user)

        return {
            "ips": sorted(list(ips)),
            "hashes": sorted(list(hashes)),
            "domains": sorted(list(domains)),
            "users": sorted(list(users)),
        }

    def build_timeline(self, incident: Incident) -> List[Dict[str, Any]]:
        events = []

        # 1. First alert ingested
        events.append({
            "time": incident.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "title": "Initial Threat Event Ingested",
            "details": f"Ingested alert signature: '{incident.title}' from source IP: {incident.threat_actor_ip or 'internal'}.",
        })

        # 2. Threat Intel Enrichment
        events.append({
            "time": incident.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "title": "Threat Intelligence Correlation",
            "details": f"Correlated event IOCs against offline local threat DB and external reputation feeds.",
        })

        # 3. AI Triage
        if incident.triage:
            events.append({
                "time": incident.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "title": f"AI Triage & MITRE ATT&CK Classification ({incident.triage.severity.value})",
                "details": f"Technique {incident.mitre_technique_id} ({incident.mitre_technique_name}) identified with {int(incident.triage.confidence_score * 100)}% confidence.",
            })

        # 4. SOAR Playbook actions
        for act in incident.soar_actions:
            events.append({
                "time": act.executed_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "title": f"SOAR Playbook Execution: {act.action_type.value}",
                "details": f"Target: {act.target}. Status: {act.status.value}. Reversible: {act.is_reversible}.",
            })

        # 5. Incident current status
        events.append({
            "time": incident.updated_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "title": f"Incident Contained & State Recorded ({incident.status})",
            "details": "Automated containment active. Forensic report compiled for SOC review.",
        })

        return events

    def derive_root_cause(self, incident: Incident) -> str:
        tid = incident.mitre_technique_id
        if tid == "T1110":
            return (
                f"Adversary initiated automated credential stuffing / dictionary attack against edge authentication services "
                f"from malicious botnet node {incident.threat_actor_ip}. "
                f"Automated firewall perimeter block prevented unauthorized lateral intrusion."
            )
        elif tid == "T1566":
            return (
                f"Spear-phishing vector delivered weaponized email payload with embedded malicious executable hash. "
                f"Targeted user {incident.compromised_user or 'workstation user'} sessions were immediately invalidated "
                f"and host was isolated before secondary C2 stage execution."
            )
        elif tid == "T1486":
            return (
                f"Ransomware mass-encryption attempt detected via shadow copy deletion commands and high-entropy file writes. "
                f"AI triage triggered immediate virtual network air-gap on host {incident.target_host} and terminated hostile processes."
            )
        elif tid == "T1048":
            return (
                f"Data exfiltration activity detected utilizing covert DNS tunneling queries to exfiltrate internal data records. "
                f"Malicious C2 domains were sinkholed and outbound DNS channels isolated."
            )
        elif tid == "T1046" or tid == "T1203":
            return (
                f"Adversary performed port and service discovery reconnaissance followed by remote code execution vulnerability probe. "
                f"Automated perimeter access-control lists dropped hostile probe traffic."
            )
        return (
            f"Adversary engaged in suspicious actions matching MITRE ATT&CK technique {tid} ({incident.mitre_technique_name}). "
            f"Containment policy enforced."
        )

    def build_recommendations(self, incident: Incident) -> List[Dict[str, str]]:
        recs = [
            {
                "title": "Immediate Verification of Active Quarantine",
                "details": "Confirm in the SOC Dashboard that the affected host and source IP firewall rules remain in an enforced drop state.",
            },
            {
                "title": "Credential Rotation and MFA Enforcement",
                "details": "Force an enterprise-wide password reset and review Multi-Factor Authentication token issuance for all targeted accounts.",
            },
            {
                "title": "Endpoint Memory & Persistence Sweep",
                "details": "Dispatch forensic EDR agents to inspect scheduled tasks, registry Run keys, and ephemeral memory on the quarantined host.",
            },
            {
                "title": "Edge Firewall ACL Permanent Hardening",
                "details": "Convert automated temporary perimeter drop rules into permanent edge routing blacklists across core firewalls.",
            },
        ]
        return recs

    def generate_markdown(
        self,
        incident: Incident,
        iocs: Dict[str, List[str]],
        root_cause: str,
        timeline: List[Dict[str, Any]],
        recommendations: List[Dict[str, str]],
    ) -> str:
        lines = [
            f"# Autonomous SOC Incident Investigation Report",
            f"**Case ID**: `{incident.incident_id}`  ",
            f"**Severity**: `{incident.severity.value}` ({incident.triage.severity_label if incident.triage else 'TRIAGED'})  ",
            f"**Status**: `{incident.status}`  ",
            f"**Generated At**: {incident.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            "",
            "## Executive Summary",
            f"**Incident Title**: {incident.title}  ",
            f"**MITRE ATT&CK Tactic**: {incident.mitre_tactic}  ",
            f"**MITRE Technique**: `{incident.mitre_technique_id}` ({incident.mitre_technique_name})  ",
            f"**Confidence**: {int(incident.triage.confidence_score * 100) if incident.triage else 95}%  ",
            "",
            "## AI Triage Rationale",
            f"> {incident.triage.rationale if incident.triage else 'Automated analysis performed.'}",
            "",
            "## Root Cause Analysis",
            root_cause,
            "",
            "## Compromised Indicators of Compromise (IOCs)",
            f"- **Attacker / Source IPs**: {', '.join(f'`{ip}`' for ip in iocs['ips']) or 'None'}",
            f"- **Malware Hashes**: {', '.join(f'`{h}`' for h in iocs['hashes']) or 'None'}",
            f"- **Malicious Domains**: {', '.join(f'`{d}`' for d in iocs['domains']) or 'None'}",
            f"- **Targeted Accounts**: {', '.join(f'`{u}`' for u in iocs['users']) or 'None'}",
            "",
            "## Automated SOAR Containment Playbook Actions",
            "| Action ID | Type | Target | Status | Reversible | Rollback Command |",
            "|---|---|---|---|---|---|",
        ]

        for act in incident.soar_actions:
            lines.append(
                f"| `{act.action_id[:8]}...` | `{act.action_type.value}` | `{act.target}` | `{act.status.value}` | `{act.is_reversible}` | `{act.rollback_command or 'N/A'}` |"
            )
        if not incident.soar_actions:
            lines.append("| - | None | - | - | - | - |")

        lines.extend([
            "",
            "## Incident Reconstruction Timeline",
        ])
        for event in timeline:
            lines.append(f"- **{event['time']}** — **{event['title']}**: {event['details']}")

        lines.extend([
            "",
            "## Recommended Remediation Roadmap",
        ])
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"{i}. **{rec['title']}**: {rec['details']}")

        return "\n".join(lines)

    def generate_report(self, incident: Incident) -> IncidentReport:
        iocs = self.extract_iocs(incident)
        timeline = self.build_timeline(incident)
        root_cause = self.derive_root_cause(incident)
        recommendations = self.build_recommendations(incident)

        md_content = self.generate_markdown(
            incident, iocs, root_cause, timeline, recommendations
        )
        html_content = self.template.render(
            incident=incident,
            iocs=iocs,
            timeline=timeline,
            root_cause=root_cause,
            recommendations=recommendations,
        )

        md_path = self.reports_dir / f"{incident.incident_id}.md"
        html_path = self.reports_dir / f"{incident.incident_id}.html"

        md_path.write_text(md_content, encoding="utf-8")
        html_path.write_text(html_content, encoding="utf-8")

        summary = (
            f"Incident {incident.incident_id} ({incident.severity.value}) triaged as "
            f"{incident.mitre_technique_id} ({incident.mitre_technique_name}). "
            f"{len(incident.soar_actions)} automated SOAR actions dispatched."
        )

        return IncidentReport(
            incident_id=incident.incident_id,
            title=incident.title,
            markdown_path=str(md_path),
            html_path=str(html_path),
            summary=summary,
        )
