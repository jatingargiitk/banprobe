import ipaddress

import pytest

from banprobe.inputs import (InputError, jail_list, parse_docker_ps, parse_fail2ban,
                             parse_ip_list, parse_ipset_save)

from conftest import ROOT


def test_fail2ban_status_with_overview():
    text = (ROOT / "examples" / "server" / "fail2ban.txt").read_text()
    bans, notes = parse_fail2ban(text)
    assert [(str(b.ip), b.jail) for b in bans] == [
        ("198.51.100.23", "sshd"), ("192.0.2.44", "wordpress"), ("203.0.113.7", "wordpress")]
    assert jail_list(text) == ["sshd", "wordpress"]
    assert notes == []


def test_fail2ban_ipv6_noted_and_empty_list():
    bans, notes = parse_fail2ban("Status for the jail: a\n`- Actions\n   `- Banned IP list:\t2001:db8::1 192.0.2.1\n"
                                 "Status for the jail: b\n`- Actions\n   `- Banned IP list:\t\n")
    assert [(str(b.ip), b.jail) for b in bans] == [("192.0.2.1", "a")]
    assert notes == ["2001:db8::1 (a): IPv6 is not checked"]


def test_fail2ban_garbage():
    with pytest.raises(InputError):
        parse_fail2ban("Sorry but the jail 'x' does not exist\n")
    with pytest.raises(InputError):
        parse_fail2ban("Status for the jail: a\n   `- Banned IP list:\tnot-an-ip\n")


def test_docker_ps():
    pubs, notes = parse_docker_ps(
        "web\t0.0.0.0:8080->80/tcp, [::]:8080->80/tcp\n"
        "dns\t0.0.0.0:53->53/udp\n"
        "db\t127.0.0.1:5432->5432/tcp\n"
        "range\t0.0.0.0:9000-9001->9000-9001/tcp\n"
        "pinned\t203.0.113.10:8443->443/tcp\n"
        "plain\t6379/tcp\n")
    assert [(p.container, p.host_ip, p.host_port, p.container_port) for p in pubs] == [
        ("web", "0.0.0.0", 8080, 80), ("range", "0.0.0.0", 9000, 9000),
        ("range", "0.0.0.0", 9001, 9001), ("pinned", "203.0.113.10", 8443, 443)]
    assert notes == ["dns 0.0.0.0:53->53/udp: only TCP is checked",
                     "db 127.0.0.1:5432->5432/tcp: published on loopback only, not reachable from other hosts"]


def test_ipset_save():
    sets = parse_ipset_save(
        "create f2b-web hash:ip family inet hashsize 1024 maxelem 65536 timeout 600\n"
        "add f2b-web 203.0.113.7 timeout 581\n"
        "create f2b-net hash:net family inet hashsize 1024 maxelem 65536\n"
        "add f2b-net 198.51.100.0/24\n"
        "create f2b-web6 hash:ip family inet6 hashsize 1024 maxelem 65536\n"
        "create pairs hash:ip,port family inet\n")
    assert sets == {"f2b-web": [ipaddress.ip_network("203.0.113.7/32")],
                    "f2b-net": [ipaddress.ip_network("198.51.100.0/24")]}


def test_ip_list():
    assert [str(b.ip) for b in parse_ip_list("192.0.2.1, 192.0.2.2 192.0.2.3")] == [
        "192.0.2.1", "192.0.2.2", "192.0.2.3"]
    with pytest.raises(InputError):
        parse_ip_list("192.0.2.1,nope")
