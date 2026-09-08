"""
Alert Ingestion & Event Normalization Engine
Asynchronous queue ingesting JSON, Syslog (RFC 3164/5424), Suricata/Snort EVE & fast alerts,
and Authentication logs (Linux auth.log & Windows Security Events), normalizing them into UnifiedAlert.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, Dict, Optional, Union
import uuid

from cyberdefense.models import UnifiedAlert

logger = logging.getLogger("cyberdefense.ingestion")

# Common regex patterns for parsing
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT_PATTERN = re.compile(r"port\s+(\d+)", re.IGNORECASE)
USER_PATTERN = re.compile(r"(?:user|for invalid user|for user)\s+([a-zA-Z0-9_\-\.]+)", re.IGNORECASE)
SYSLOG_PATTERN = re.compile(
    r"^(?:<(?P<pri>\d+)>)?(?:(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T[^\s]+)\s+)?(?P<host>[^\s:]+)\s+(?P<app>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
SNORT_FAST_PATTERN = re.compile(
    r"\[\*\*\]\s+\[\d+:\d+:\d+\]\s+(?P<sig>[^\[]+?)\s+\[\*\*\]\s+(?:\[Priority:\s*(?P<prio>\d+)\])?\s*\{(?P<proto>[A-Z]+)\}\s+(?P<src_ip>[\d\.]+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>[\d\.]+):(?P<dst_port>\d+)"
)


class AlertIngestionEngine:
    def __init__(self, max_queue_size: int = 5000):
        self.queue: asyncio.Queue[UnifiedAlert] = asyncio.Queue(maxsize=max_queue_size)
        self.ingested_count: int = 0
        self.normalized_count: int = 0

    def parse_json(self, data: Dict[str, Any]) -> UnifiedAlert:
        """
        Normalizes generic JSON / REST alert dictionaries.
        """
        src_ip = (
            data.get("source_ip")
            or data.get("src_ip")
            or data.get("src")
            or data.get("client_ip")
            or data.get("attacker_ip")
            or data.get("ip")
        )
        dest_ip = (
            data.get("dest_ip")
            or data.get("dst_ip")
            or data.get("dst")
            or data.get("target_ip")
            or data.get("destination_ip")
            or data.get("host_ip")
        )
        src_port = data.get("source_port") or data.get("src_port") or data.get("sport")
        dest_port = data.get("dest_port") or data.get("dst_port") or data.get("dport")
        if src_port is not None:
            try:
                src_port = int(src_port)
            except (ValueError, TypeError):
                src_port = None
        if dest_port is not None:
            try:
                dest_port = int(dest_port)
            except (ValueError, TypeError):
                dest_port = None

        protocol = (
            data.get("protocol") or data.get("proto") or "TCP"
        ).upper()

        signature = (
            data.get("signature")
            or data.get("event_type")
            or data.get("alert_name")
            or data.get("message")
            or data.get("title")
            or "Unknown Security Event"
        )

        user = (
            data.get("user")
            or data.get("username")
            or data.get("account")
            or data.get("target_user")
        )
        proc_name = (
            data.get("process_name")
            or data.get("process")
            or data.get("image")
            or data.get("app")
        )
        pid = data.get("pid") or data.get("process_pid")
        if pid is not None:
            try:
                pid = int(pid)
            except (ValueError, TypeError):
                pid = None

        file_hash = (
            data.get("file_hash")
            or data.get("sha256")
            or data.get("hash")
            or data.get("md5")
        )
        domain = (
            data.get("domain")
            or data.get("hostname")
            or data.get("query")
            or data.get("c2_domain")
        )

        ts = datetime.now(timezone.utc)
        if "timestamp" in data:
            raw_ts = data["timestamp"]
            if isinstance(raw_ts, str):
                try:
                    ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                except ValueError:
                    ts = datetime.now(timezone.utc)
            elif isinstance(raw_ts, datetime):
                ts = raw_ts

        return UnifiedAlert(
            alert_id=str(uuid.uuid4()),
            timestamp=ts,
            source_type=data.get("source_type", "json"),
            source_ip=str(src_ip) if src_ip else None,
            dest_ip=str(dest_ip) if dest_ip else None,
            source_port=src_port,
            dest_port=dest_port,
            protocol=protocol,
            signature=str(signature),
            user=str(user) if user else None,
            process_name=str(proc_name) if proc_name else None,
            process_pid=pid,
            file_hash=str(file_hash) if file_hash else None,
            domain=str(domain) if domain else None,
            raw_payload=data,
        )

    def parse_syslog(self, text: str) -> UnifiedAlert:
        """
        Normalizes RFC 3164 or RFC 5424 Syslog strings.
        """
        match = SYSLOG_PATTERN.match(text.strip())
        app = "syslog"
        pid = None
        msg = text.strip()

        if match:
            app = match.group("app") or "syslog"
            raw_pid = match.group("pid")
            if raw_pid:
                try:
                    pid = int(raw_pid)
                except ValueError:
                    pid = None
            msg = match.group("msg") or ""

        ips = IP_PATTERN.findall(msg)
        src_ip = ips[0] if len(ips) > 0 else None
        dst_ip = ips[1] if len(ips) > 1 else "10.0.0.15"

        port_match = PORT_PATTERN.search(msg)
        src_port = int(port_match.group(1)) if port_match else None

        user_match = USER_PATTERN.search(msg)
        user = user_match.group(1) if user_match else None

        return UnifiedAlert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            source_type="syslog",
            source_ip=src_ip,
            dest_ip=dst_ip,
            source_port=src_port,
            dest_port=22 if "ssh" in app.lower() else None,
            protocol="TCP",
            signature=f"Syslog: [{app}] {msg[:80]}",
            user=user,
            process_name=app,
            process_pid=pid,
            raw_payload={"syslog_raw": text, "message": msg},
        )

    def parse_suricata_snort(self, payload: Union[Dict[str, Any], str]) -> UnifiedAlert:
        """
        Normalizes Suricata EVE JSON or Snort fast-alert strings.
        """
        if isinstance(payload, dict):
            # Suricata EVE JSON format
            alert_obj = payload.get("alert", {})
            sig = alert_obj.get("signature") or payload.get("event_type", "Suricata Alert")
            src_ip = payload.get("src_ip")
            dest_ip = payload.get("dest_ip")
            src_port = payload.get("src_port")
            dest_port = payload.get("dest_port")
            proto = payload.get("proto", "TCP")

            return UnifiedAlert(
                alert_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                source_type="suricata",
                source_ip=str(src_ip) if src_ip else None,
                dest_ip=str(dest_ip) if dest_ip else None,
                source_port=int(src_port) if src_port else None,
                dest_port=int(dest_port) if dest_port else None,
                protocol=str(proto).upper(),
                signature=f"Suricata: {sig}",
                raw_payload=payload,
            )
        else:
            # Snort Fast / text alert
            text = str(payload).strip()
            match = SNORT_FAST_PATTERN.search(text)
            if match:
                return UnifiedAlert(
                    alert_id=str(uuid.uuid4()),
                    timestamp=datetime.now(timezone.utc),
                    source_type="snort",
                    source_ip=match.group("src_ip"),
                    dest_ip=match.group("dst_ip"),
                    source_port=int(match.group("src_port")),
                    dest_port=int(match.group("dst_port")),
                    protocol=match.group("proto"),
                    signature=f"Snort: {match.group('sig').strip()}",
                    raw_payload={"snort_raw": text},
                )
            else:
                # Generic fallback using IP regex
                ips = IP_PATTERN.findall(text)
                return UnifiedAlert(
                    alert_id=str(uuid.uuid4()),
                    timestamp=datetime.now(timezone.utc),
                    source_type="snort",
                    source_ip=ips[0] if ips else None,
                    dest_ip=ips[1] if len(ips) > 1 else None,
                    signature=f"Snort Alert: {text[:80]}",
                    raw_payload={"raw": text},
                )

    def parse_auth_log(self, payload: Union[Dict[str, Any], str]) -> UnifiedAlert:
        """
        Normalizes Linux auth.log strings or Windows Security Events (4625 / 4672).
        """
        if isinstance(payload, dict):
            event_id = payload.get("EventID") or payload.get("event_id")
            sig = f"Windows Security Event {event_id}" if event_id else "Authentication Event"
            return UnifiedAlert(
                alert_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                source_type="auth_log",
                source_ip=payload.get("IpAddress") or payload.get("source_ip"),
                dest_ip=payload.get("WorkstationName") or payload.get("dest_ip") or "10.0.0.15",
                signature=sig,
                user=payload.get("TargetUserName") or payload.get("user"),
                process_name=payload.get("ProcessName", "lsass.exe"),
                raw_payload=payload,
            )

        text = str(payload).strip()
        ips = IP_PATTERN.findall(text)
        src_ip = ips[0] if ips else None
        user_match = USER_PATTERN.search(text)
        user = user_match.group(1) if user_match else None
        port_match = PORT_PATTERN.search(text)
        port = int(port_match.group(1)) if port_match else 22

        return UnifiedAlert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            source_type="auth_log",
            source_ip=src_ip,
            dest_ip="10.0.0.15",
            source_port=port,
            dest_port=22,
            protocol="TCP",
            signature="AuthLog: Authentication Failure / Credential Anomaly",
            user=user,
            process_name="sshd",
            raw_payload={"auth_raw": text},
        )

    def normalize(
        self, data: Any, source_type: Optional[str] = None
    ) -> UnifiedAlert:
        """
        Dispatches any arbitrary alert payload to its appropriate parser.
        """
        # If already a UnifiedAlert instance
        if isinstance(data, UnifiedAlert):
            return data

        # Check if JSON string
        if isinstance(data, str):
            trimmed = data.strip()
            if trimmed.startswith("{") and trimmed.endswith("}"):
                try:
                    data = json.loads(trimmed)
                except Exception:
                    pass

        # If dictionary
        if isinstance(data, dict):
            # Check if Suricata EVE
            if data.get("event_type") == "alert" or "alert" in data:
                return self.parse_suricata_snort(data)
            # Check if Windows Event Log
            if "EventID" in data or "TargetUserName" in data:
                return self.parse_auth_log(data)
            return self.parse_json(data)

        # String-based log line
        line = str(data)
        if source_type == "snort" or "[**]" in line:
            return self.parse_suricata_snort(line)
        if source_type == "auth_log" or "Failed password" in line or "invalid user" in line:
            return self.parse_auth_log(line)
        if source_type == "syslog" or SYSLOG_PATTERN.match(line):
            return self.parse_syslog(line)

        # Fallback to syslog parser
        return self.parse_syslog(line)

    async def submit(
        self, data: Any, source_type: Optional[str] = None
    ) -> UnifiedAlert:
        """
        Normalizes alert and enqueues into the asynchronous processing queue.
        """
        alert = self.normalize(data, source_type=source_type)
        await self.queue.put(alert)
        self.ingested_count += 1
        self.normalized_count += 1
        return alert

    async def get_next(self) -> UnifiedAlert:
        return await self.queue.get()
