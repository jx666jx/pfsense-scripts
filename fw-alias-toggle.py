"""
fw-alias-toggle.py

Toggle the current system's IPv4 address in a pfSense firewall alias.
- Add the current system if the IP is absent from alias, else remove the current system if present in alias.
- PATCH the updated alias with apply=true.

Required environment variables:
- pfSense API key:    PFS_API_KEY
- pfSense Alias ID:   PFS_ALIAS_ID
- pfSense IP: PFS_IP
"""

import os
import sys
import json
import socket
from typing import Tuple, List, Dict, Any, Optional
import requests
import urllib3

# Suppress insecure TLS warnings (equivalent to curl -k)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10

# ANSI colors
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RESET = "\033[0m"


def print_error(msg: str) -> None:
    """Print an error message in RED to stderr."""
    print(f"{RED}{msg}{RESET}", file=sys.stderr)


def get_local_ip_towards(host: str, port: int = 80) -> str:
    """Determine the local IPv4 used to reach `host` by opening a UDP socket (no packets sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((host, port))
        return s.getsockname()[0]


def find_alias_obj(data: Any, alias_id: str) -> Dict[str, Any]:
    """Return the alias dict by id from common pfSense API response shapes."""
    alias_id = str(alias_id)

    # Unwrap {"data": ...} if present
    if isinstance(data, dict) and "data" in data:
        data = data["data"]

    # Normalize to iterable of dicts
    items = data if isinstance(data, list) else [data] if isinstance(data, dict) else []

    for item in items:
        if isinstance(item, dict) and str(item.get("id")) == alias_id:
            return item

    raise ValueError("Alias id not found in response")


def normalize_addr_detail(alias_obj: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Return aligned (addresses, details). Ensure both lists have equal length."""
    addresses = list(alias_obj.get("address") or [])
    details = list(alias_obj.get("detail") or [])
    if len(details) < len(addresses):
        details.extend([""] * (len(addresses) - len(details)))
    elif len(details) > len(addresses):
        details = details[: len(addresses)]
    return addresses, details


def toggle_ip(
    addresses: List[str], details: List[str], ip: str, hostname: str
) -> Tuple[List[str], List[str], str]:
    """Toggle ip in alias. If present, remove all occurrences; if absent, append with detail."""
    if ip in addresses:
        # Remove all entries matching `ip` while preserving alignment of address/detail pairs
        pairs = [(a, d) for a, d in zip(addresses, details) if a != ip]
        new_addresses = [a for a, _ in pairs]
        new_details = [d for _, d in pairs]
        return new_addresses, new_details, f"{YELLOW}removed"
    else:
        addresses.append(ip)
        details.append(f"{hostname} - added by touchdesigner")
        return addresses, details, f"{GREEN}added"


def _getenv_any(*names: str) -> Optional[str]:
    """Return the first non-empty environment variable among `names`."""
    for name in names:
        val = os.getenv(name)
        if val:
            return val
    return None


def main():
    # Read env with flexible names
    pfs_api_key = os.getenv("PFS_API_KEY")
    pfs_alias_id = os.getenv("PFS_ALIAS_ID")
    pfs_ip = os.getenv("PFS_IP")

    # Validate required env
    missing = []
    if not pfs_api_key:
        missing.append("PFS_API_KEY")
    if not pfs_alias_id:
        missing.append("PFS_ALIAS_ID")
    if not pfs_ip:
        missing.append("PFS_IP")
    if missing:
        print_error("ERROR: Missing required env var(s): " + ", ".join(missing))
        sys.exit(1)

    base_url = f"https://{pfs_ip}/api/v2/firewall/alias"

    hostname = socket.gethostname()
    try:
        my_ip = get_local_ip_towards(pfs_ip, 80)
    except OSError as e:
        print_error(f"ERROR: Could not determine local IP: {e}")
        sys.exit(2)

    session = requests.Session()
    session.verify = False  # insecure, equivalent to curl -k
    session.headers.update({"X-API-Key": pfs_api_key})

    # GET alias
    try:
        resp = session.get(base_url, params={"id": str(pfs_alias_id)}, timeout=TIMEOUT)
    except requests.RequestException as e:
        print_error(f"ERROR: GET request failed: {e}")
        sys.exit(3)

    if resp.status_code != 200:
        print_error(f"ERROR: GET returned {resp.status_code}: {resp.text}")
        sys.exit(4)

    try:
        data = resp.json()
    except json.JSONDecodeError as e:
        snippet = resp.text[:500].replace("\n", "\\n")
        print_error(f"ERROR: Failed to parse JSON: {e}. Raw: {snippet}")
        sys.exit(5)

    try:
        alias_obj = find_alias_obj(data, pfs_alias_id)
    except ValueError as e:
        print_error(f"ERROR: {e}")
        sys.exit(6)

    addresses, details = normalize_addr_detail(alias_obj)

    # Toggle IP
    addresses_updated, details_updated, action = toggle_ip(
        addresses, details, my_ip, hostname
    )

    # PATCH update
    payload = {
        "id": str(pfs_alias_id),
        "address": addresses_updated,
        "detail": details_updated,
        "apply": True,
    }

    try:
        patch_resp = session.patch(base_url, json=payload, timeout=TIMEOUT)
    except requests.RequestException as e:
        print_error(f"ERROR: PATCH request failed: {e}")
        sys.exit(7)

    if patch_resp.status_code not in (200, 201, 204):
        print_error(
            f"ERROR: PATCH returned {patch_resp.status_code}: {patch_resp.text}"
        )
        sys.exit(8)

    print(f"{GREEN}Success:{RESET} {action} {my_ip} ({hostname}){RESET}")


if __name__ == "__main__":
    main()
