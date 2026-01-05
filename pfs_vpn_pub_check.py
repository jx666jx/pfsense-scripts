"""
pfs_vpn_pub_ip_check.py

Compare the pfSense WAN/INTERNET interface IP with the public IP reported by ifconfig.io/ip.

Environment variables (same style as `fw_alias_toggle.py`):
- PFS_API_KEY: pfSense API key
- PFS_IP: pfSense management IP or hostname
- PFS_WAN_IFACE: (optional) interface name to query (default: wan)
"""

import os
import sys
import json
import re
from typing import Optional
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10

# ANSI colors
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RESET = "\033[0m"


def print_error(msg: str) -> None:
    """Print an error message to stderr in RED.

    Args:
        msg: Message text to print.
    """
    print(f"{RED}{msg}{RESET}", file=sys.stderr)


def fetch_runtime_interface_ip(
    session: requests.Session, pfs_ip: str, iface_name: str
) -> Optional[str]:
    """Retrieve the runtime-assigned IPv4 for `iface_name` via status endpoint.

    Args:
        session: Requests session configured with API key and TLS settings.
        pfs_ip: Hostname or IP of the pfSense management interface.
        iface_name: The interface name (e.g. igc3, wan, internet) to query.

    Returns:
        The first discovered IPv4 address as a string, or None if not found.
    """
    # Query the STATUS endpoint which contains runtime-assigned addresses.
    url = f"https://{pfs_ip}/api/v2/status/interfaces"
    try:
        resp = session.get(url, timeout=TIMEOUT)
    except requests.RequestException:
        return None

    if resp.status_code != 200:
        return None

    try:
        data = resp.json()
    except json.JSONDecodeError:
        # Non-JSON response — cannot reliably extract IP
        return None

    # JSON payload: expect list or dict containing interface status objects
    items = data.get("data") if isinstance(data, dict) and "data" in data else data
    if isinstance(items, dict):
        items = [items]
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict):
                continue
            # Match by: name or descr
            name = str(item.get("name") or "")
            descr = str(item.get("descr") or "")
            if iface_name in (name, descr):
                ipfld = str(item.get("ipaddr") or "")
                if ipfld and re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ipfld):
                    return ipfld
    return None


def fetch_pfs_wan_ip(
    session: requests.Session, pfs_ip: str, iface: str
) -> Optional[str]:
    """Query `/api/v2/interfaces` for a matching `iface` and return its first IPv4.

    If the interface is configured for DHCP, this will call the runtime status
    lookup to discover the currently assigned address.

    Args:
        session: Requests session configured with API key and TLS settings.
        pfs_ip: The pfSense management IP or hostname.
        iface: The interface identifier to match (value of the `if` field or descr).

    Returns:
        IPv4 address string if found, else None.
    """
    url = f"https://{pfs_ip}/api/v2/interfaces"
    try:
        resp = session.get(url, timeout=TIMEOUT)
    except requests.RequestException:
        return None

    if resp.status_code != 200:
        return None

    try:
        data = resp.json()
    except json.JSONDecodeError:
        return None

    # Data may be a dict with 'data' key or a list
    items = data.get("data") if isinstance(data, dict) and "data" in data else data
    if not isinstance(items, list):
        items = [items] if isinstance(items, dict) else []

    # Helper to resolve an interface item to an IP
    wan_fallback = None

    def _resolve_item(it: dict) -> Optional[str]:
        """Resolve an interface item to an IP using explicit `ipaddr` or runtime lookup."""
        ipaddr = str(it.get("ipaddr") or "")
        if ipaddr and ipaddr.lower() != "dhcp":
            if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ipaddr):
                return ipaddr
        ipaddr_field = str(it.get("ipaddr") or "").lower()
        typev4 = str(it.get("typev4") or "").lower()
        if ipaddr_field == "dhcp" or typev4 == "dhcp":
            identifier = str(
                it.get("id") or it.get("name") or it.get("descr") or it.get("if") or ""
            )
            return fetch_runtime_interface_ip(session, pfs_ip, identifier)
        return None

    for item in items:
        if not isinstance(item, dict):
            continue
        # Match by fields: `id` or `descr`. Prefer exact match first.
        id_field = str(item.get("id") or "")
        descr_field = str(item.get("descr") or "")

        # exact match wins
        if iface in (id_field, descr_field):
            resolved = _resolve_item(item)
            if resolved:
                return resolved
        # otherwise remember first WAN-like descr as fallback
        if "wan" in descr_field.lower() or "internet" in descr_field.lower():
            if wan_fallback is None:
                wan_fallback = item

    # If we found a WAN-like fallback, resolve it now
    if wan_fallback is not None:
        resolved = _resolve_item(wan_fallback)
        if resolved:
            return resolved

    return None


def fetch_public_ip(session: requests.Session) -> Optional[str]:
    """Query ifconfig.io/ip for the public IPv4 address.

    Args:
        session: Requests session used to perform the request.

    Returns:
        The public IPv4 string if successful and valid, otherwise None.
    """
    url = "https://ifconfig.io/ip"
    try:
        resp = session.get(url, timeout=TIMEOUT)
    except requests.RequestException:
        return None

    if resp.status_code != 200:
        return None

    text = resp.text.strip()
    # Validate
    if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", text):
        parts = text.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return text
    return None


def main() -> None:
    """Obtain WAN IP from pfSense, obtain public IP, compare and print.

    Variables:
    - PFS_API_KEY, PFS_IP, optional PFS_WAN_IFACE (defaults to 'wan').
    """

    if "td" in sys.modules:
        pfs_api_key = parent(5).par.Pfsapikey
        pfs_ip = parent(5).par.Pfsip
        pfs_wan_iface = parent(5).par.Pfswaniface
    else:
        pfs_api_key = os.getenv("PFS_API_KEY")
        pfs_ip = os.getenv("PFS_IP")
        pfs_wan_iface = os.getenv("PFS_WAN_IFACE", "wan")

    missing = []
    if not pfs_api_key:
        missing.append("PFS_API_KEY")
    if not pfs_ip:
        missing.append("PFS_IP")
    if missing:
        print_error("ERROR: Missing required env var(s): " + ", ".join(missing))
        sys.exit(1)

    session = requests.Session()
    session.verify = False
    session.headers.update({"X-API-Key": str(pfs_api_key)})

    wan_ip = None

    wan_ip = fetch_pfs_wan_ip(session, str(pfs_ip), str(pfs_wan_iface))
    if not wan_ip:
        print_error("ERROR: Could not determine pfSense WAN IP via API.")
        sys.exit(2)

    public_ip = fetch_public_ip(session)
    if not public_ip:
        print_error("ERROR: Could not determine public IP via ifconfig.io")
        sys.exit(3)

    if 'td' in sys.modules:
        op('vpn_output').clear()
        if wan_ip == public_ip:
            op('vpn_status').par.const0value = 1
            op('vpn_output').write('Stream Ready')
        else:
            op('vpn_status').par.const0value = 0
            op('vpn_output').write('VPN IP: (' + public_ip + ') ')
    else:
        # Compare and print colored results
        if wan_ip == public_ip:
            print(f"{GREEN}direct: {RESET} WAN ({wan_ip}) == Public ({public_ip})")
        else:
            print(
                f"{YELLOW}vpn: {RESET} WAN ({wan_ip}) != Public ({public_ip})"
            )


main()
