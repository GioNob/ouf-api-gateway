import socket
import pytest
from tools.southbound_security import RegisteredEndpoint,SouthboundDenied,validate_destination,validate_redirect


def resolver_for(*ips):
    return lambda host,port,type=None:[(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,port)) for ip in ips]


def endpoint(cidrs=()):return RegisteredEndpoint('https','sue.example.local',443,cidrs)

def test_registry_bound_endpoint_accepts_registered_public_resolution():validate_destination('https://sue.example.local/api',endpoint(),resolver_for('8.8.8.8'))
@pytest.mark.parametrize('url',["https://attacker.example/api","http://sue.example.local/api","https://sue.example.local:444/api"])
def test_client_cannot_replace_host_scheme_or_port(url):
    with pytest.raises(SouthboundDenied):validate_destination(url,endpoint(),resolver_for('8.8.8.8'))
@pytest.mark.parametrize('ip',["127.0.0.1","169.254.169.254","0.0.0.0","224.0.0.1"])
def test_forbidden_address_classes(ip):
    with pytest.raises(SouthboundDenied,match='FORBIDDEN_ADDRESS_CLASS'):validate_destination('https://sue.example.local/',endpoint(),resolver_for(ip))
def test_unregistered_private_address_denied():
    with pytest.raises(SouthboundDenied,match='PRIVATE_ADDRESS_UNREGISTERED'):validate_destination('https://sue.example.local/',endpoint(),resolver_for('10.20.30.40'))
def test_registered_private_cidr_allowed():validate_destination('https://sue.example.local/',endpoint(('10.20.30.0/24',)),resolver_for('10.20.30.40'))
def test_dns_rebinding_answer_outside_registered_cidr_denied():
    with pytest.raises(SouthboundDenied,match='DNS_REBINDING'):validate_destination('https://sue.example.local/',endpoint(('10.20.30.0/24',)),resolver_for('10.20.30.40','10.99.0.1'))
def test_redirect_changing_host_is_denied():
    with pytest.raises(SouthboundDenied,match='UNREGISTERED_ENDPOINT'):validate_redirect('https://sue.example.local/a','https://attacker.example/b',endpoint(),resolver_for('8.8.8.8'))
