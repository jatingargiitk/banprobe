import ipaddress

import pytest

from banprobe.rules import parse
from banprobe.sim import Context, Packet, match, simulate

SRC = ipaddress.IPv4Address("203.0.113.7")


def rule(spec):
    rs = parse(f"*filter\n:INPUT ACCEPT [0:0]\n:x - [0:0]\n-A INPUT {spec}\nCOMMIT\n")
    return rs.chain("filter", "INPUT").rules[0]


def m(spec, **kw):
    pkt = Packet(src=SRC, dport=kw.pop("dport", 8080), **kw)
    return match(rule(spec), pkt, Context())[0]


@pytest.mark.parametrize("spec,expected", [
    ("-s 203.0.113.0/24 -j DROP", True),
    ("! -s 203.0.113.0/24 -j DROP", False),
    ("-s 198.51.100.1/32 -j DROP", False),
    ("-p udp -j DROP", False),
    ("-p all -j DROP", True),
    ("-p tcp -m multiport --dports 22,8000:8100 -j DROP", True),
    ("-p tcp -m multiport ! --dports 8000:8100 -j DROP", False),
    ("-p tcp -m tcp --dport 80 -j DROP", False),
    ("-p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j DROP", True),
    ("-p tcp -m tcp ! --syn -j DROP", False),
    ("-p tcp -m tcp --sport 1024:65535 -j DROP", True),
    ("-p tcp -m tcp --sport 53 -j DROP", False),
    ("-p tcp -m tcp --sport 40000:50000 -j DROP", None),
    ("-m conntrack --ctstate NEW -j DROP", True),
    ("-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", False),
    ("-m state --state INVALID -j DROP", False),
    ("-m iprange --src-range 203.0.113.1-203.0.113.9 -j DROP", True),
    ("-m addrtype --dst-type LOCAL -j DROP", True),
    ("-m addrtype --src-type LOCAL -j DROP", False),
    ("-m recent --rcheck --seconds 60 --name x --rsource -j DROP", None),
    ("-m comment --comment \"ban list\" -s 203.0.113.7/32 -j DROP", True),
    ("-i lo -j ACCEPT", False),
    ("-i docker0 -j ACCEPT", False),
    ("-i eth0 -j ACCEPT", None),
    ("-i + -j ACCEPT", True),
    ("-d 127.0.0.0/8 -j ACCEPT", False),
    ("-d 192.0.2.10/32 -j ACCEPT", None),
    ("-s 203.0.113.7/32 -m limit --limit 1/s -j DROP", None),
    ("-s 198.51.100.1/32 -m limit --limit 1/s -j DROP", False),   # a definite miss wins
])
def test_match(spec, expected):
    assert m(spec) is expected


def test_iface_and_dst_when_known():
    assert m("-i eth0 -j ACCEPT", in_iface="eth0") is True
    assert m("-i eth+ -j ACCEPT", in_iface="eth1") is True
    assert m("-i eth0 -j ACCEPT", in_iface="ens3") is False
    assert m("-d 192.0.2.10/32 -j ACCEPT", dst=ipaddress.IPv4Address("192.0.2.10")) is True


def test_goto_returns_to_callers_caller():
    rs = parse("*filter\n:INPUT ACCEPT [0:0]\n:a - [0:0]\n:b - [0:0]\n"
               "-A INPUT -j a\n-A INPUT -s 203.0.113.7/32 -j DROP\n"
               "-A a -g b\n-A a -j ACCEPT\n"
               "-A b -s 198.51.100.0/24 -j ACCEPT\nCOMMIT\n")
    res = simulate([rs], Packet(src=SRC, dport=22), Context())
    assert res.verdict == "BLOCKED"
    assert res.decider.entered == ["INPUT", "a", "b"]
    assert res.decider.rule.line == 6


def test_unknown_target_is_inconclusive():
    rs = parse("*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -j CROWDSEC_CHAIN\nCOMMIT\n")
    res = simulate([rs], Packet(src=SRC, dport=22), Context())
    assert res.verdict == "INCONCLUSIVE"
    assert res.decider.reason == "target CROWDSEC_CHAIN is not understood"


def test_redirect_goes_to_input():
    rs = parse("*nat\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -p tcp -m tcp --dport 80 "
               "-j REDIRECT --to-ports 8080\nCOMMIT\n*filter\n:INPUT ACCEPT [0:0]\n"
               "-A INPUT -p tcp -m tcp --dport 8080 -s 203.0.113.7/32 -j DROP\nCOMMIT\n")
    res = simulate([rs], Packet(src=SRC, dport=80), Context())
    assert res.route == "INPUT" and res.verdict == "BLOCKED"
