import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

from banprobe.rules import parse  # noqa: E402

# Docker 28 layout, one container 172.18.0.2:80 published as :8080 on br-app
DOCKER28 = """\
*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A PREROUTING -d 172.18.0.2/32 ! -i br-app -j DROP
COMMIT
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER - [0:0]
:DOCKER-BRIDGE - [0:0]
:DOCKER-CT - [0:0]
:DOCKER-FORWARD - [0:0]
:DOCKER-ISOLATION-STAGE-1 - [0:0]
:DOCKER-ISOLATION-STAGE-2 - [0:0]
:DOCKER-USER - [0:0]
:f2b-web - [0:0]
{input}
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-FORWARD
-A DOCKER -d 172.18.0.2/32 ! -i br-app -o br-app -p tcp -m tcp --dport 80 -j ACCEPT
-A DOCKER ! -i br-app -o br-app -j DROP
-A DOCKER-BRIDGE -o br-app -j DOCKER
-A DOCKER-CT -o br-app -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DOCKER-FORWARD -j DOCKER-CT
-A DOCKER-FORWARD -j DOCKER-ISOLATION-STAGE-1
-A DOCKER-FORWARD -j DOCKER-BRIDGE
-A DOCKER-FORWARD -i br-app -j ACCEPT
-A DOCKER-ISOLATION-STAGE-1 -i br-app ! -o br-app -j DOCKER-ISOLATION-STAGE-2
-A DOCKER-ISOLATION-STAGE-2 -o br-app -j DROP
{user}
{f2b}
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:DOCKER - [0:0]
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
-A POSTROUTING -s 172.18.0.0/16 ! -o br-app -j MASQUERADE
{nat}
COMMIT
"""

BAN_RULES = """\
-A f2b-web -s 203.0.113.7/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-web -j RETURN"""

DNAT_8080 = "-A DOCKER ! -i br-app -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.18.0.2:80"


def docker28(input="", user="", f2b=BAN_RULES, nat=DNAT_8080):
    text = DOCKER28.format(input=input, user=user, f2b=f2b, nat=nat)
    return "\n".join(l for l in text.splitlines() if l.strip()) + "\n"


@pytest.fixture
def write(tmp_path):
    def _write(name, text):
        p = tmp_path / name
        p.write_text(text, encoding="utf-8")
        return str(p)
    return _write


def ruleset(text, name="test.rules"):
    return parse(text, name)
