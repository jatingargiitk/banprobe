"""Rulesets saved by tests/e2e/real_packets.sh on a GitHub ubuntu-24.04 runner
(Docker 28.0.4, iptables-nft 1.8.10, fail2ban 1.0.2), where a real curl from the
banned address got the page (input-8080, docker-user-8080) or was refused
(docker-user-80). Offline, banprobe must give the same verdicts."""

import json

import pytest

from banprobe.cli import main

from conftest import FIX

RUNNER = FIX / "runner"


@pytest.mark.parametrize("name,verdict,code", [
    ("input-8080", "REACHABLE", 1),
    ("docker-user-8080", "REACHABLE", 1),
    ("docker-user-80", "BLOCKED", 0),
])
def test_runner_snapshot(capsys, name, verdict, code):
    got = main(["--iptables-save", str(RUNNER / f"{name}.rules"),
                "--fail2ban", str(RUNNER / f"{name}.fail2ban.txt"), "--json"])
    d = json.loads(capsys.readouterr().out)
    assert got == code
    (r,) = d["results"]
    assert (r["ip"], r["jail"], r["host_port"], r["dnat_to"], r["verdict"]) == (
        "10.200.0.2", "web", 8080, "172.17.0.2:80", verdict)
    assert r["route"] == "FORWARD"
