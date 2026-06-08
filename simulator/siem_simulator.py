"""
SIEM Alert Simulator
Generates realistic mock SIEM alert payloads in various vendor formats
to simulate real-world webhook traffic for testing the SOAR engine.

Usage:
    python simulator/siem_simulator.py                  # Send 5 random alerts
    python simulator/siem_simulator.py --count 10       # Send 10 alerts
    python simulator/siem_simulator.py --type brute     # Only brute force
    python simulator/siem_simulator.py --type malware   # Only malware
    python simulator/siem_simulator.py --dry-run        # Print payloads, don't send
"""

import argparse
import json
import random
import time
import uuid
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta

SOAR_ENDPOINT = "http://localhost:8000/api/v1/alerts/ingest"

# ─── Realistic IP pools ───────────────────────────────────────────────────────

MALICIOUS_IPS = [
    "185.220.101.45",  # Known Tor exit node
    "45.33.32.156",    # Known scanner (shodan)
    "198.20.69.74",    # Known scanner
    "91.191.209.4",
    "103.14.120.196",
    "194.165.16.11",
    "5.188.86.172",
    "79.124.49.65",
]

TARGET_IPS = [
    "10.0.1.50",   # Internal web server
    "10.0.1.51",   # Internal DB server
    "10.0.2.10",   # Internal SSH bastion
    "192.168.1.100",
]

HOSTNAMES = ["web-server-01", "db-master", "bastion-host", "api-gateway", "jenkins-ci"]
USERNAMES = ["root", "admin", "ubuntu", "ec2-user", "deploy", "postgres", "git"]

FILE_HASHES = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "d41d8cd98f00b204e9800998ecf8427e",
    "aabbcc112233ddeeff00112233445566778899aabbccddeeff00112233445566",
    "5f4dcc3b5aa765d61d8327deb882cf99",
]


# ─── Payload generators (different SIEM vendor formats) ──────────────────────

def make_brute_force_splunk_format() -> dict:
    """Simulates Splunk/QRadar style brute force alert (ISO timestamp, string severity)"""
    attempts = random.randint(5, 200)
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_type": "brute_force",
        "severity": random.choice(["medium", "high", "critical"]),
        "src_ip": random.choice(MALICIOUS_IPS),
        "dst_ip": random.choice(TARGET_IPS),
        "host": random.choice(HOSTNAMES),
        "user": random.choice(USERNAMES),
        "failed_attempts": attempts,
        "message": f"SSH brute force detected: {attempts} failed login attempts in 60 seconds",
    }


def make_brute_force_epoch_format() -> dict:
    """Simulates older SIEM with Unix epoch timestamp and numeric severity"""
    attempts = random.randint(10, 500)
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": int(time.time()),       # Unix epoch seconds
        "event_type": "authentication_failure",
        "severity": random.choice([5, 7, 9, 10]),   # Numeric 1-10
        "source_ip": random.choice(MALICIOUS_IPS),
        "destination_ip": random.choice(TARGET_IPS),
        "hostname": random.choice(HOSTNAMES),
        "username": random.choice(USERNAMES),
        "failed_attempts": attempts,
        "description": f"Multiple failed SSH authentication attempts ({attempts}) from single source",
    }


def make_malware_aws_cloudtrail_format() -> dict:
    """Simulates AWS CloudTrail / GuardDuty style alert"""
    return {
        "event_id": f"gd-{uuid.uuid4().hex[:8]}",
        "timestamp": int(time.time() * 1000),  # Millisecond epoch
        "alert_type": "malware_detection",
        "severity": random.choice(["high", "critical"]),
        "sourceIPAddress": random.choice(MALICIOUS_IPS),
        "dst_ip": random.choice(TARGET_IPS),
        "host": random.choice(HOSTNAMES),
        "file_hash": random.choice(FILE_HASHES),
        "message": "Malware payload detected. Suspicious file execution with known IOC hash.",
        "description": "GuardDuty: Trojan:EC2/DropPoint detected on instance.",
    }


def make_malware_custom_format() -> dict:
    """Simulates a custom in-house SIEM with non-standard field names"""
    past_time = datetime.now(timezone.utc) - timedelta(minutes=random.randint(1, 30))
    return {
        "event_id": f"INC-{random.randint(10000, 99999)}",
        "timestamp": past_time.strftime("%d/%b/%Y:%H:%M:%S +0000"),  # Apache log format
        "event_type": "exploit_attempt",
        "severity": random.choice(["7", "8", "9"]),   # Numeric as string
        "src_ip": random.choice(MALICIOUS_IPS),
        "host": random.choice(HOSTNAMES),
        "file_hash": random.choice(FILE_HASHES),
        "description": "Suspicious binary executed with known ransomware hash signature.",
    }


def make_port_scan_format() -> dict:
    """Simulates a port scan alert from network IDS"""
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "alert_type": "port_scan",
        "severity": "medium",
        "src_ip": random.choice(MALICIOUS_IPS),
        "dst_ip": random.choice(TARGET_IPS),
        "message": "Nmap-style port scan detected. 1000+ ports probed in under 10 seconds.",
    }


# ─── Alert dispatch ───────────────────────────────────────────────────────────

GENERATORS = {
    "brute": [make_brute_force_splunk_format, make_brute_force_epoch_format],
    "malware": [make_malware_aws_cloudtrail_format, make_malware_custom_format],
    "scan": [make_port_scan_format],
    "all": [
        make_brute_force_splunk_format,
        make_brute_force_epoch_format,
        make_malware_aws_cloudtrail_format,
        make_malware_custom_format,
        make_port_scan_format,
    ]
}


def send_alert(payload: dict, dry_run: bool = False) -> None:
    """Sends a single alert to the SOAR ingestion endpoint."""
    print(f"\n{'='*60}")
    print(f"[SIMULATOR] Sending payload:")
    print(json.dumps(payload, indent=2))

    if dry_run:
        print("[DRY RUN] Not sending to SOAR endpoint.")
        return

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            SOAR_ENDPOINT,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            response_body = json.loads(resp.read().decode("utf-8"))
            print(f"[SOAR RESPONSE] {json.dumps(response_body, indent=2)}")

    except urllib.error.URLError as e:
        print(f"[ERROR] Could not reach SOAR endpoint: {e}")
        print(f"        Make sure the SOAR engine is running on {SOAR_ENDPOINT}")


def main():
    parser = argparse.ArgumentParser(description="SIEM Alert Simulator for SOAR testing")
    parser.add_argument("--count", type=int, default=5, help="Number of alerts to send")
    parser.add_argument(
        "--type", choices=["brute", "malware", "scan", "all"],
        default="all", help="Type of alert to simulate"
    )
    parser.add_argument("--dry-run", action="store_true", help="Print payloads without sending")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between alerts (seconds)")
    args = parser.parse_args()

    generators = GENERATORS[args.type]
    print(f"\n[SIMULATOR] Sending {args.count} '{args.type}' alerts to SOAR engine...")

    for i in range(args.count):
        gen_fn = random.choice(generators)
        payload = gen_fn()
        print(f"\n[{i+1}/{args.count}] Using generator: {gen_fn.__name__}")
        send_alert(payload, dry_run=args.dry_run)
        if i < args.count - 1:
            time.sleep(args.delay)

    print(f"\n[SIMULATOR] Done. Sent {args.count} alerts.")


if __name__ == "__main__":
    main()
