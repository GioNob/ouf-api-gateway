import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin


class SouthboundDenied(RuntimeError): pass


@dataclass(frozen=True)
class RegisteredEndpoint:
    scheme: str
    host: str
    port: int
    allowed_cidrs: tuple[str, ...] = ()


def _forbidden(ip: ipaddress._BaseAddress) -> bool:
    return ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved


def validate_destination(url: str, registered: RegisteredEndpoint, resolver=socket.getaddrinfo) -> tuple[str, ...]:
    parsed=urlparse(url)
    if parsed.username or parsed.password or parsed.fragment: raise SouthboundDenied("UNSAFE_URL_COMPONENT")
    if parsed.scheme != registered.scheme or parsed.hostname != registered.host or (parsed.port or (443 if parsed.scheme=='https' else 80)) != registered.port:
        raise SouthboundDenied("UNREGISTERED_ENDPOINT")
    if parsed.scheme != 'https': raise SouthboundDenied("TLS_REQUIRED")
    try: answers=resolver(parsed.hostname,registered.port,type=socket.SOCK_STREAM)
    except OSError as exc: raise SouthboundDenied("DNS_RESOLUTION_FAILED") from exc
    ips=tuple(sorted({item[4][0] for item in answers}))
    if not ips: raise SouthboundDenied("DNS_RESOLUTION_EMPTY")
    networks=tuple(ipaddress.ip_network(cidr) for cidr in registered.allowed_cidrs)
    for raw in ips:
        ip=ipaddress.ip_address(raw)
        if _forbidden(ip): raise SouthboundDenied("FORBIDDEN_ADDRESS_CLASS")
        if ip.is_private and not networks: raise SouthboundDenied("PRIVATE_ADDRESS_UNREGISTERED")
        if networks and not any(ip in network for network in networks): raise SouthboundDenied("DNS_REBINDING_OR_CIDR_MISMATCH")
    return ips


def validate_redirect(current_url: str, location: str, registered: RegisteredEndpoint, resolver=socket.getaddrinfo) -> str:
    target=urljoin(current_url,location)
    validate_destination(target,registered,resolver)
    return target
