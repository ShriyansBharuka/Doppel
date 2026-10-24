"""Simulated egress destinations and host verification."""

from urllib.parse import urlparse

KNOWN_INTERNAL_HOSTS: list[str] = [
    "erp.corp.internal",
    "suppliers.approved.example",
    "bank.corp.internal",
]

ATTACKER_HOSTS: list[str] = [
    "files-share.xyz",
    "paste-drop.io",
]


def extract_host(target: str) -> str:
    """Extract host string from a URL or raw hostname/address."""
    target_clean = target.strip()
    if "://" in target_clean:
        parsed = urlparse(target_clean)
        host = parsed.hostname or parsed.netloc
    else:
        # Handles host:port or raw host/path
        host = target_clean.split("/")[0].split(":")[0]
    return host.lower()


def is_known(host_or_url: str) -> bool:
    """Return True if host is an approved internal enterprise destination."""
    host = extract_host(host_or_url)
    return host in KNOWN_INTERNAL_HOSTS


def is_attacker(host_or_url: str) -> bool:
    """Return True if host is a designated scenario attacker destination."""
    host = extract_host(host_or_url)
    return host in ATTACKER_HOSTS
