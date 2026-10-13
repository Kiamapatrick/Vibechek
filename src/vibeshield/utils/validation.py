import ipaddress
import socket
from urllib.parse import urlparse


def unwrap_ipv4_mapped(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Unwrap IPv4-mapped IPv6 addresses (::ffff:127.0.0.1 -> 127.0.0.1)."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def is_allowed_target(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool) -> bool:
    """Check if an IP address is allowed as a scan target.

    Allowed: global unicast addresses (public internet)
    Rejected unless allow_private=True: loopback, private, link-local, multicast, reserved, metadata (169.254.169.254)
    """
    ip = unwrap_ipv4_mapped(ip)

    if not ip.is_global:
        return bool(allow_private)

    return True


def validate_target(url: str, allow_private: bool = False) -> tuple[bool, str | None]:
    """Validate a URL target against SSRF protections.

    Args:
        url: The URL to validate (must be http or https)
        allow_private: If True, allow private/internal IP addresses (for local development)

    Returns:
        Tuple of (is_valid, error_message). If valid, error_message is None.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return False, f"Scheme '{parsed.scheme}' not allowed. Only http and https are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "No hostname in URL"

    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        return False, f"Failed to resolve hostname '{hostname}': {e}"

    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        if not is_allowed_target(ip, allow_private):
            return False, f"Target resolves to disallowed address: {ip}"

    return True, None


def validate_target_or_raise(url: str, allow_private: bool = False) -> None:
    """Validate a URL target, raising ValueError if invalid."""
    valid, error = validate_target(url, allow_private)
    if not valid:
        raise ValueError(error)