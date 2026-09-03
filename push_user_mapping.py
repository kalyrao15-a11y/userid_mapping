#!/usr/bin/env python3
"""Push static User-IP mappings to a PAN NGFW via XML API.

Reads PAN_HOSTNAME and PAN_API_KEY from .env, then POSTs mappings.xml
as type=user-id. No commit is required; the mapping is applied immediately.

Usage:
    python push_user_mapping.py
    python push_user_mapping.py --dry-run
    python push_user_mapping.py --file mappings.xml
    python push_user_mapping.py --clear
    python push_user_mapping.py --clear-ip 192.0.2.10
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

import requests
import urllib3
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
DEFAULT_MAPPINGS = ROOT / "mappings.xml"
CLEAR_XMLAPI_UID_MESSAGE = """<uid-message>
  <version>1.0</version>
  <type>update</type>
  <payload>
    <logout>
      <all/>
    </logout>
  </payload>
</uid-message>"""


def load_config() -> dict:
    load_dotenv(ROOT / ".env")
    hostname = os.getenv("PAN_HOSTNAME", "").strip()
    api_key = os.getenv("PAN_API_KEY", "").strip()
    vsys = os.getenv("PAN_VSYS", "vsys1").strip() or "vsys1"
    verify_ssl = os.getenv("PAN_VERIFY_SSL", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    missing = [name for name, value in (("PAN_HOSTNAME", hostname), ("PAN_API_KEY", api_key)) if not value]
    if missing:
        raise SystemExit(
            f"Missing {', '.join(missing)} in .env. Copy .env.example to .env and fill in values."
        )
    if api_key in {"your-xml-api-key-here", "changeme"}:
        raise SystemExit("PAN_API_KEY in .env is still the placeholder. Replace it with the firewall API key.")

    return {
        "hostname": hostname.rstrip("/"),
        "api_key": api_key,
        "vsys": vsys,
        "verify_ssl": verify_ssl,
    }


def load_uid_message(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"Mappings file not found: {path}")
    uid_xml = path.read_text(encoding="utf-8").strip()
    if "<uid-message" not in uid_xml or "<login" not in uid_xml and "<logout" not in uid_xml:
        raise SystemExit(f"{path} must contain a uid-message with login and/or logout entries.")
    return uid_xml


def format_mappings(uid_xml: str) -> list[str]:
    root = ET.fromstring(uid_xml)
    payload = root.find("payload")
    if payload is None:
        return []

    lines: list[str] = []
    for action in ("login", "logout"):
        section = payload.find(action)
        if section is None:
            continue
        if section.find("all") is not None:
            lines.append(f"  {action}  all XML API entries")
            continue
        for entry in section.findall("entry"):
            name = entry.get("name") or "(no user)"
            ip = entry.get("ip") or ""
            timeout = entry.get("timeout")
            extra = f"  timeout={timeout}" if timeout is not None else ""
            lines.append(f"  {action}  {name}  {ip}{extra}")
    return lines


def print_mappings(uid_xml: str) -> None:
    lines = format_mappings(uid_xml)
    if not lines:
        return
    print("Mappings:")
    for line in lines:
        print(line)


def push_mapping(config: dict, uid_xml: str) -> str:
    url = f"https://{config['hostname']}/api/"
    data = {
        "type": "user-id",
        "key": config["api_key"],
        "vsys": config["vsys"],
        "cmd": uid_xml,
    }

    if not config["verify_ssl"]:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        response = requests.post(url, data=data, verify=config["verify_ssl"], timeout=30)
    except requests.RequestException as exc:
        raise SystemExit(f"XML API request failed: {exc}") from exc

    if response.status_code != 200:
        raise SystemExit(f"XML API HTTP {response.status_code}: {response.text.strip()}")

    text = response.text.strip()
    if 'status="success"' not in text and "status='success'" not in text:
        raise SystemExit(f"XML API rejected the mapping:\n{text}")
    return text


def main() -> None:
    parser = argparse.ArgumentParser(description="Push static User-IP mappings to a PAN NGFW via XML API.")
    parser.add_argument("--file", type=Path, default=DEFAULT_MAPPINGS, help="Path to mappings.xml")
    parser.add_argument("--dry-run", action="store_true", help="Print the uid-message XML and do not send it")
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Remove all User-IP mappings created via the XML API (logout all)",
    )
    parser.add_argument(
        "--clear-ip",
        metavar="IP",
        help="Remove the XML API mapping for a specific IP address",
    )
    args = parser.parse_args()

    if args.clear and args.clear_ip:
        raise SystemExit("--clear and --clear-ip are mutually exclusive.")

    if args.clear:
        uid_xml = CLEAR_XMLAPI_UID_MESSAGE
    elif args.clear_ip:
        uid_xml = (
            "<uid-message>\n"
            "  <version>1.0</version>\n"
            "  <type>update</type>\n"
            "  <payload>\n"
            "    <logout>\n"
            f'      <entry ip="{args.clear_ip}"/>\n'
            "    </logout>\n"
            "  </payload>\n"
            "</uid-message>"
        )
    else:
        uid_xml = load_uid_message(args.file)

    if args.dry_run:
        print(uid_xml)
        return

    config = load_config()
    if args.clear:
        print(f"Clearing all XML API User-ID mappings on {config['hostname']} ({config['vsys']})...")
        accepted = "Firewall cleared all XML API User-ID mappings."
    elif args.clear_ip:
        print(f"Clearing XML API User-ID mapping for {args.clear_ip} on {config['hostname']} ({config['vsys']})...")
        accepted = f"Firewall cleared XML API User-ID mapping for {args.clear_ip}."
    else:
        print(f"Pushing User-ID mapping from {args.file.name} to {config['hostname']} ({config['vsys']})...")
        accepted = "Firewall accepted the User-ID mapping."
    result = push_mapping(config, uid_xml)
    print(accepted)
    print_mappings(uid_xml)
    print(result)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
