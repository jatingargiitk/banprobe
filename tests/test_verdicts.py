"""End-to-end through the CLI on realistic iptables-save files."""

import json

import pytest

from banprobe.cli import main

from conftest import BAN_RULES, DNAT_8080, FIX, docker28

INPUT_HOOK = "-A INPUT -p tcp -m multiport --dports 8080 -j f2b-web"
USER_HOOK_80 = "-A DOCKER-USER -p tcp -m multiport --dports 80 -j f2b-web"
F2B = str(FIX / "fail2ban-web.txt")


def run(capsys, *args):
    code = main(list(args) + ["--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["exit_code"] == code
    return code, data


def probe(capsys, write, text, *extra, f2b=True):
    path = write("iptables-save.txt", text)
    args = ["--iptables-save", path] + (["--fail2ban", F2B] if f2b else []) + list(extra)
    return run(capsys, *args)


def test_input_jail_does_not_cover_docker_port(capsys, write):
    code, d = probe(capsys, write, docker28(input=INPUT_HOOK))
    assert code == 1
    (r,) = d["results"]
    assert (r["ip"], r["jail"], r["host_port"], r["dnat_to"], r["route"], r["verdict"]) == (
        "203.0.113.7", "web", 8080, "172.18.0.2:80", "FORWARD", "REACHABLE")
    assert r["walks"][-1]["chains"] == ["FORWARD", "DOCKER-USER", "DOCKER-FORWARD", "DOCKER-CT",
                                        "DOCKER-ISOLATION-STAGE-1", "DOCKER-BRIDGE", "DOCKER"]
    assert r["walks"][-1]["rule"]["text"].endswith("--dport 80 -j ACCEPT")
    assert "hooked from INPUT" in r["why"] and "goes through FORWARD" in r["why"]
    assert "chain = DOCKER-USER" in r["fix"] and "`port = 80`" in r["fix"]


def test_docker_user_with_container_port_blocks(capsys, write):
    code, d = probe(capsys, write, docker28(user=USER_HOOK_80))
    assert code == 0
    (r,) = d["results"]
    assert r["verdict"] == "BLOCKED"
    assert r["walks"][-1]["chains"] == ["FORWARD", "DOCKER-USER", "f2b-web"]
    assert r["walks"][-1]["verdict"] == "REJECT"


def test_docker_user_with_host_port_misses(capsys, write):
    code, d = probe(capsys, write, docker28(
        user="-A DOCKER-USER -p tcp -m multiport --dports 8080 -j f2b-web"))
    assert code == 1
    r = d["results"][0]
    assert "already has the container port 80" in r["why"]
    assert "--ctorigdstport 8080" in r["fix"]


def test_ctorigdstport_hook_blocks(capsys, write):
    code, d = probe(capsys, write, docker28(
        user="-A DOCKER-USER -p tcp -m conntrack --ctorigdstport 8080 -j f2b-web"))
    assert code == 0 and d["results"][0]["verdict"] == "BLOCKED"


def test_allports_hook_blocks(capsys, write):
    code, d = probe(capsys, write, docker28(user="-A DOCKER-USER -p tcp -j f2b-web"))
    assert code == 0 and d["results"][0]["verdict"] == "BLOCKED"


IPSET_HOOK = ("-A DOCKER-USER -p tcp -m multiport --dports 80 -m set --match-set f2b-web src "
              "-j REJECT --reject-with icmp-port-unreachable")
IPSET = ("create f2b-web hash:ip family inet hashsize 1024 maxelem 65536 timeout 600\n"
         "add f2b-web 203.0.113.7 timeout 551\n")


def test_ipset_without_members_is_inconclusive(capsys, write):
    code, d = probe(capsys, write, docker28(user=IPSET_HOOK, f2b=""))
    assert code == 2
    r = d["results"][0]
    assert r["verdict"] == "INCONCLUSIVE"
    assert "--match-set f2b-web src" in r["inconclusive"]
    assert "pass --ipset-save" in r["inconclusive"]


def test_ipset_with_members_blocks(capsys, write):
    ipset = write("ipset.txt", IPSET)
    code, d = probe(capsys, write, docker28(user=IPSET_HOOK, f2b=""), "--ipset-save", ipset)
    assert code == 0 and d["results"][0]["verdict"] == "BLOCKED"


def test_ipset_missing_ip_is_explained(capsys, write):
    ipset = write("ipset.txt", IPSET.splitlines()[0] + "\n")
    code, d = probe(capsys, write, docker28(user=IPSET_HOOK, f2b=""), "--ipset-save", ipset)
    assert code == 1
    assert d["results"][0]["why"].startswith("203.0.113.7 is not in ipset f2b-web")


def test_unevaluable_rule_is_inconclusive_and_named(capsys, write):
    code, d = probe(capsys, write, docker28(
        user="-A DOCKER-USER -m limit --limit 5/min -j DROP\n" + USER_HOOK_80))
    assert code == 2
    r = d["results"][0]
    assert r["inconclusive"].startswith("-A DOCKER-USER -m limit --limit 5/min -j DROP")
    assert "`-m limit --limit 5/min` can't be evaluated" in r["inconclusive"]


def test_unknown_match_on_log_rule_does_not_matter(capsys, write):
    code, d = probe(capsys, write, docker28(
        user="-A DOCKER-USER -m limit --limit 5/min -j LOG --log-prefix \"fwd \"\n" + USER_HOOK_80))
    assert code == 0


def test_unparseable_rule_is_inconclusive(capsys, write):
    code, d = probe(capsys, write, docker28(user="-A DOCKER-USER -s\n" + USER_HOOK_80))
    assert code == 2
    assert "could not parse this rule (-s is missing its argument)" in d["results"][0]["inconclusive"]


def test_accept_before_hook(capsys, write):
    code, d = probe(capsys, write, docker28(
        user="-A DOCKER-USER -s 203.0.113.0/24 -j ACCEPT\n" + USER_HOOK_80))
    assert code == 1
    assert "lets it through before the f2b-web hook" in d["results"][0]["why"]


def test_hook_matches_but_ip_missing_from_chain(capsys, write):
    code, d = probe(capsys, write, docker28(user=USER_HOOK_80, f2b="-A f2b-web -j RETURN"))
    assert code == 1
    assert d["results"][0]["why"].startswith("203.0.113.7 is not in f2b-web")


def test_no_hooks_at_all(capsys, write):
    code, d = probe(capsys, write, docker28(f2b=""), "--banned", "198.51.100.9", f2b=False)
    assert code == 1
    r = d["results"][0]
    assert r["jail"] is None
    assert r["why"].startswith("no rule references f2b-web (as a chain or an ipset)")


def test_userland_proxy_no_dnat_goes_through_input(capsys, write):
    # dockerd --iptables=false: no DNAT, docker-proxy listens on the host
    code, d = probe(capsys, write, docker28(input=INPUT_HOOK, nat=""), "--port", "8080")
    assert code == 0
    r = d["results"][0]
    assert r["route"] == "INPUT" and r["verdict"] == "BLOCKED"
    code, d = probe(capsys, write, docker28(user=USER_HOOK_80, nat=""), "--port", "80")
    assert code == 1
    assert d["results"][0]["fix"] == "set `chain = INPUT` for [web] in jail.local"


def test_jail_ports_scope(capsys, write):
    code, d = probe(capsys, write, docker28(input="-A INPUT -p tcp -m multiport --dports 22 -j f2b-web"))
    assert code == 0
    assert d["results"] == []
    assert d["skipped"] == [{"ip": "203.0.113.7", "jail": "web", "host_port": 8080,
                             "reason": "jail web only covers port(s) 22"}]


def test_interface_rule_needs_in_iface(capsys, write):
    text = docker28(user="-A DOCKER-USER -i eth0 -s 203.0.113.0/24 -j DROP")
    code, d = probe(capsys, write, text)
    assert code == 2
    assert "pass --in-iface" in d["results"][0]["inconclusive"]
    code, d = probe(capsys, write, text, "--in-iface", "eth0")
    assert code == 0
    code, d = probe(capsys, write, text, "--in-iface", "ens3")
    assert code == 1


def test_pinned_publish_address_comes_from_the_dnat_rule(capsys, write):
    text = docker28(user=USER_HOOK_80, nat=DNAT_8080.replace("-A DOCKER !", "-A DOCKER -d 203.0.113.10/32 !"))
    code, d = probe(capsys, write, text, "--port", "8080")
    assert code == 0
    assert (d["results"][0]["host_ip"], d["results"][0]["dnat_to"]) == ("203.0.113.10", "172.18.0.2:80")


def test_destination_rule_needs_host_ip(capsys, write):
    text = docker28(input="-A INPUT -d 203.0.113.10/32 -p tcp -m tcp --dport 22 -j DROP", nat="")
    code, d = probe(capsys, write, text, "--port", "22", "--banned", "192.0.2.1", f2b=False)
    assert code == 2
    assert "pass --host-ip" in d["results"][0]["inconclusive"]
    code, d = probe(capsys, write, text, "--port", "22", "--banned", "192.0.2.1",
                    "--host-ip", "203.0.113.10", f2b=False)
    assert code == 0
    code, d = probe(capsys, write, text, "--port", "22", "--banned", "192.0.2.1",
                    "--host-ip", "203.0.113.11", f2b=False)
    assert code == 1


def test_docker26_layout_real_save(capsys, write):
    nft = (FIX / "box-nft.rules").read_text()
    nft = nft.replace(":DOCKER-USER - [0:0]\n", ":DOCKER-USER - [0:0]\n:f2b-web - [0:0]\n")
    nft = nft.replace("-A FORWARD -j DOCKER-USER\n",
                      "-A INPUT -p tcp -m multiport --dports 8080 -j f2b-web\n-A FORWARD -j DOCKER-USER\n")
    nft = nft.replace("-A DOCKER-USER -j RETURN\n", "-A DOCKER-USER -j RETURN\n" + BAN_RULES + "\n")
    code, d = probe(capsys, write, nft)
    r = d["results"][0]
    assert code == 1 and r["dnat_to"] == "172.17.0.2:80"
    assert r["walks"][-1]["chains"] == ["FORWARD", "DOCKER-USER", "DOCKER-ISOLATION-STAGE-1", "DOCKER"]


def test_legacy_tables_warning_makes_reachable_inconclusive(capsys, write):
    text = "# Warning: iptables-legacy tables present, use iptables-legacy-save to see them\n" + \
        docker28(input=INPUT_HOOK)
    code, d = probe(capsys, write, text)
    assert code == 2
    assert d["results"][0]["inconclusive"] == "iptables-legacy tables are present and were not read"


def test_nft_plus_legacy_real_saves_both_apply(capsys):
    # captured on one host: Docker 26 rules in nft, stale Docker 28 rules in legacy
    code, d = run(capsys, "--iptables-save", str(FIX / "box-nft.rules"),
                  "--iptables-save", str(FIX / "box-legacy.rules"),
                  "--docker-ps", str(FIX / "box-docker-ps.txt"), "--banned", "10.200.0.2")
    assert code == 0
    (r,) = d["results"]
    assert r["container"] == "bp-web" and r["verdict"] == "BLOCKED"
    assert r["walks"][-1]["ruleset"].endswith("box-legacy.rules")
    assert r["walks"][-1]["rule"]["text"] == "-A DOCKER ! -i docker0 -o docker0 -j DROP"


def test_input_policy_drop_and_explicit_ip(capsys, write):
    text = docker28(nat="").replace(":INPUT ACCEPT", ":INPUT DROP")
    code, d = probe(capsys, write, text, "--ip", "192.0.2.1", "--port", "22", f2b=False)
    assert code == 0
    assert d["results"][0]["walks"][-1]["verdict"] == "POLICY-DROP"


def test_text_output_and_exit_codes(capsys, write):
    path = write("s.txt", docker28(input=INPUT_HOOK))
    assert main(["--iptables-save", path, "--fail2ban", F2B]) == 1
    out = capsys.readouterr().out
    assert "REACHABLE    203.0.113.7     web        :8080 -> 172.18.0.2:80" in out
    assert out.rstrip().endswith("1 checked: 1 reachable, 0 blocked, 0 inconclusive")


@pytest.mark.parametrize("args,msg", [
    (["--iptables-save", "/nonexistent"], "No such file"),
    (["--iptables-save", str(FIX / "fail2ban-web.txt"), "--banned", "192.0.2.1"],
     "not iptables-save output"),
    (["--iptables-save", str(FIX / "box-nft.rules")], "pass --fail2ban FILE"),
    (["--iptables-save", str(FIX / "box-nft.rules"), "--ip", "nope"], "not an IPv4"),
])
def test_input_errors_exit_3(capsys, args, msg):
    assert main(args) == 3
    assert msg in capsys.readouterr().err


def test_usage_error_exit_3(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--port", "x"])
    assert e.value.code == 3
