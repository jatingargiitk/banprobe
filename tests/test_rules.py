import pytest

from banprobe.rules import ParseError, parse

from conftest import FIX


def test_parses_real_docker26_save():
    rs = parse((FIX / "box-nft.rules").read_text(), "box-nft.rules")
    assert set(rs.tables) == {"filter", "nat"}
    fwd = rs.chain("filter", "FORWARD")
    assert fwd.policy == "ACCEPT"
    assert [r.target for r in fwd.rules][:2] == ["DOCKER-USER", "DOCKER-ISOLATION-STAGE-1"]
    dnat = [r for r in rs.rules("nat") if r.target == "DNAT"][0]
    assert dnat.target_args == {"--to-destination": "172.17.0.2:80"}
    assert dnat.where() == "box-nft.rules:36"
    neg = [c for c in dnat.conds if c.opt == "-i"][0]
    assert neg.neg and neg.args == ["docker0"]


def test_parses_real_docker28_legacy_save():
    rs = parse((FIX / "box-legacy.rules").read_text())
    assert rs.chain("filter", "FORWARD").policy == "DROP"
    assert "DOCKER-FORWARD" in rs.tables["filter"]
    assert rs.chain("filter", "DOCKER-USER").policy is None


def test_negation_modules_and_target_args():
    rs = parse("*filter\n:INPUT ACCEPT [0:0]\n"
               "-A INPUT -p tcp -m multiport --dports 80,443,8000:8100 "
               "-m set ! --match-set f2b-x src -m comment --comment \"allow web\" "
               "-j REJECT --reject-with tcp-reset\nCOMMIT\n")
    r = rs.chain("filter", "INPUT").rules[0]
    assert [(c.module, c.opt, c.args, c.neg) for c in r.conds] == [
        (None, "-p", ["tcp"], False),
        ("multiport", "--dports", ["80,443,8000:8100"], False),
        ("set", "--match-set", ["f2b-x", "src"], True),
        ("comment", "--comment", ["allow web"], False),
    ]
    assert r.target == "REJECT" and r.target_args == {"--reject-with": "tcp-reset"}


def test_counters_prefix_and_goto():
    rs = parse("*filter\n:INPUT ACCEPT [5:300]\n:x - [0:0]\n[12:720] -A INPUT -g x\nCOMMIT\n")
    r = rs.chain("filter", "INPUT").rules[0]
    assert r.target == "x" and r.goto


def test_broken_rule_is_kept_with_error():
    rs = parse("*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -s\n-A INPUT -p tcp \"unterminated\nCOMMIT\n")
    errs = [r.error for r in rs.chain("filter", "INPUT").rules]
    assert errs[0] == "-s is missing its argument"
    assert errs[1].startswith("cannot tokenize")


@pytest.mark.parametrize("text", ["", "hello world\n", "-A INPUT -j DROP\n"])
def test_not_iptables_save(text):
    with pytest.raises(ParseError):
        parse(text)


def test_legacy_warning_detected():
    rs = parse("# Warning: iptables-legacy tables present, use iptables-legacy-save to see them\n"
               "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
    assert rs.legacy_present
