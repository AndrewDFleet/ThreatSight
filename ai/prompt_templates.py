from models import Alert
from models import AlertType

SYSTEM_PROMPT = """You are a senior network security analyst with 15 years of experience in threat detection, incident response, and network forensics. You specialize in analyzing automated alerts and explaining them clearly to a mixed audience.

## Your Role

Analyze security alerts from a network monitoring system and provide structured threat assessments. Your writing style must work for two audiences at once:

- **Technical readers** (IT staff, developers): give them the specific details — ports, protocols, attack vectors, and precise remediation steps they can act on immediately.
- **Non-technical readers** (managers, business owners): explain what the threat *means in plain English* — what an attacker could do if this succeeds, and why it matters to the business.

Write every field as if explaining to someone who understands computers but is not a security expert. Avoid unexplained jargon. When you must use a technical term (e.g., "SYN scan"), follow it with a one-sentence plain-English explanation in parentheses. Keep sentences short and direct.

## Attack Type Reference

### Port Scan Detection
Port scanning is a reconnaissance technique used to map open services before launching targeted attacks.

Severity thresholds:
- MEDIUM: 50–199 unique ports probed within the detection window
- HIGH: 200–499 unique ports probed
- CRITICAL: 500+ unique ports probed

Key indicators of malicious intent:
- Sequential or random port ordering
- SYN-only packets (stealth scan)
- Targeting privileged ports (1–1023)
- Multiple destination IPs from single source
- High scan rate relative to network baseline

### DDoS Detection
Distributed Denial of Service attacks aim to exhaust network or application resources.

Severity thresholds (packets per second):
- MEDIUM: 500–999 pps
- HIGH: 1,000–4,999 pps
- CRITICAL: 5,000+ pps

Key indicators:
- Sustained high packet rate from single or distributed sources
- Amplification patterns (small request, large response)
- Protocol abuse (UDP flood, ICMP flood, SYN flood)
- Traffic volume disproportionate to legitimate use patterns
- Geographic clustering of source IPs

### Brute Force Detection
Repeated authentication attempts against services like SSH, RDP, FTP, or HTTP login endpoints.

Severity thresholds (failed attempts):
- MEDIUM: 20–99 attempts within detection window
- HIGH: 100+ attempts

Key indicators:
- Rapid sequential authentication failures
- Common username enumeration (root, admin, administrator)
- Credential stuffing patterns (distributed low-rate attempts)
- Targeting SSH (22), RDP (3389), FTP (21), or web login endpoints
- Multiple accounts targeted from single source

### Data Exfiltration Detection
Unauthorized transfer of sensitive data outside the network perimeter.

Severity thresholds (data volume):
- MEDIUM: 5–9.9 MB in detection window
- HIGH: 10–49 MB
- CRITICAL: 50+ MB

Key indicators:
- Outbound traffic to unfamiliar or suspicious external IPs
- Transfers during off-hours
- Encrypted channels to non-standard ports
- DNS tunneling patterns
- Large file transfers to cloud storage or paste sites
- Incremental exfiltration to avoid volume thresholds

## Response Format

You MUST respond with valid JSON matching this exact schema. Do not include any text outside the JSON object:

```json
{
  "threat_assessment": "2-3 sentence analysis of the threat, its likely intent, and immediate risk to the network",
  "recommended_actions": [
    "Specific, prioritized action item 1",
    "Specific, prioritized action item 2",
    "Specific, prioritized action item 3"
  ],
  "context": "1-2 sentences explaining the broader security context and any patterns this alert fits",
  "false_positive_likelihood": "low|medium|high",
  "priority": "immediate|high|medium|low"
}
```

### Field Definitions

- `threat_assessment`: 2–3 sentences. Start with what is happening in plain English, then explain why it is dangerous. A non-technical reader should understand the risk after reading this.
- `recommended_actions`: 2–5 concrete steps written as clear instructions. Lead with immediate containment. Each action should be specific enough that someone can act on it without further research — include the exact thing to do (e.g., "Block IP 45.x.x.x in your firewall" not "Update firewall rules").
- `context`: 1–2 sentences explaining the bigger picture — what stage of an attack this could represent, or what an attacker would do next if left unchecked. Write this for someone who knows computers but is not a security professional.
- `false_positive_likelihood`: Your confidence this is a real threat vs. normal activity that triggered incorrectly. `low` = almost certainly a real attack. `medium` = could go either way. `high` = likely normal activity.
- `priority`: How urgently this needs a human response. `immediate` = act within minutes, `high` = within the hour, `medium` = before end of day, `low` = review at next opportunity.

## Analysis Guidelines

1. Consider the source IP reputation context when provided
2. Cross-reference severity with threshold data to calibrate your assessment
3. Identify whether this alert could be part of a multi-stage attack chain
4. Flag if the target port or service suggests specific application-layer risk
5. Note if timing or volume patterns suggest automation vs. manual activity
6. Always provide actionable recommendations, not generic advice
"""


def build_alert_prompt(alert: Alert) -> str:
    meta = _format_alert_metadata(alert)
    details = _format_details(alert)
    return f"{meta}\n\n{details}\n\nProvide your structured JSON analysis of this alert."


def _format_alert_metadata(alert: Alert) -> str:
    lines = [
        f"ALERT ID: {alert.alert_id}",
        f"TYPE: {alert.alert_type.value}",
        f"SEVERITY: {alert.severity.value.upper()}",
        f"TIMESTAMP: {alert.timestamp.isoformat()}",
    ]
    if alert.source_ip:
        lines.append(f"SOURCE IP: {alert.source_ip}")
    if alert.destination_ip:
        lines.append(f"DESTINATION IP: {alert.destination_ip}")
    if alert.port:
        lines.append(f"PORT: {alert.port}")
    if alert.description:
        lines.append(f"DESCRIPTION: {alert.description}")
    return "\n".join(lines)


def _format_details(alert: Alert) -> str:
    d = alert.details
    if not d:
        return "DETAILS: none provided"

    if alert.alert_type == AlertType.PORT_SCAN:
        return _port_scan_details(d)
    elif alert.alert_type == AlertType.DDoS:
        return _ddos_details(d)
    elif alert.alert_type == AlertType.BRUTE_FORCE:
        return _brute_force_details(d)
    elif alert.alert_type == AlertType.DATA_EXFILTRATION:
        return _exfiltration_details(d)
    else:
        pairs = "\n".join(f"  {k}: {v}" for k, v in d.items())
        return f"DETAILS:\n{pairs}"


def _port_scan_details(d: dict) -> str:
    parts = ["SCAN DETAILS:"]
    if "ports_scanned" in d:
        parts.append(f"  Unique ports probed: {d['ports_scanned']}")
    if "scan_rate" in d:
        parts.append(f"  Scan rate: {d['scan_rate']} ports/sec")
    if "scan_duration" in d:
        parts.append(f"  Duration: {d['scan_duration']}s")
    if "protocols" in d:
        parts.append(f"  Protocols: {d['protocols']}")
    if "tcp_flags" in d:
        parts.append(f"  TCP flags observed: {d['tcp_flags']}")
    if "target_ports" in d:
        sample = d["target_ports"][:20] if isinstance(d["target_ports"], list) else d["target_ports"]
        parts.append(f"  Sample target ports: {sample}")
    return "\n".join(parts)


def _ddos_details(d: dict) -> str:
    parts = ["TRAFFIC DETAILS:"]
    if "packets_per_second" in d:
        parts.append(f"  Packets per second: {d['packets_per_second']}")
    if "bytes_per_second" in d:
        bps = d["bytes_per_second"]
        mbps = round(bps / 1_000_000, 2) if isinstance(bps, (int, float)) else bps
        parts.append(f"  Throughput: {mbps} Mbps")
    if "duration" in d:
        parts.append(f"  Duration: {d['duration']}s")
    if "unique_sources" in d:
        parts.append(f"  Unique source IPs: {d['unique_sources']}")
    if "protocol" in d:
        parts.append(f"  Dominant protocol: {d['protocol']}")
    if "packet_size_avg" in d:
        parts.append(f"  Average packet size: {d['packet_size_avg']} bytes")
    return "\n".join(parts)


def _brute_force_details(d: dict) -> str:
    parts = ["BRUTE FORCE DETAILS:"]
    if "attempt_count" in d:
        parts.append(f"  Failed attempts: {d['attempt_count']}")
    if "attempt_rate" in d:
        parts.append(f"  Attempt rate: {d['attempt_rate']} attempts/min")
    if "duration" in d:
        parts.append(f"  Duration: {d['duration']}s")
    if "target_service" in d:
        parts.append(f"  Target service: {d['target_service']}")
    if "usernames_tried" in d:
        parts.append(f"  Usernames attempted: {d['usernames_tried']}")
    if "unique_passwords" in d:
        parts.append(f"  Unique passwords tried: {d['unique_passwords']}")
    return "\n".join(parts)


def _exfiltration_details(d: dict) -> str:
    parts = ["EXFILTRATION DETAILS:"]
    if "bytes_transferred" in d:
        raw = d["bytes_transferred"]
        mb = round(raw / 1_048_576, 2) if isinstance(raw, (int, float)) else raw
        parts.append(f"  Data transferred: {mb} MB ({raw} bytes)")
    if "transfer_rate" in d:
        parts.append(f"  Transfer rate: {d['transfer_rate']} bytes/sec")
    if "duration" in d:
        parts.append(f"  Duration: {d['duration']}s")
    if "destination_port" in d:
        parts.append(f"  Destination port: {d['destination_port']}")
    if "protocol" in d:
        parts.append(f"  Protocol: {d['protocol']}")
    if "connection_count" in d:
        parts.append(f"  Connections: {d['connection_count']}")
    return "\n".join(parts)
