"""banprobe command line."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import __version__
from . import inputs as inp
from .inputs import Ban, InputError, Published
from .probe import render_text, run, to_json
from .rules import ParseError, Ruleset, parse
from .sim import Context, bridges_from

EXIT_ERROR = 3


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="banprobe",
        description="Check whether IPs banned by fail2ban can still open TCP connections "
                    "to Docker-published ports, by walking the iptables ruleset.",
        epilog="exit codes: 0 every checked connection is blocked; 1 a banned IP can "
               "reach a port; 2 nothing reachable, but some verdicts are inconclusive; "
               "3 usage or input error. Without --iptables-save it reads the live "
               "host (read-only; needs root).")
    src = p.add_argument_group("saved inputs (otherwise read live)")
    src.add_argument("--iptables-save", metavar="FILE", action="append", default=[],
                     help="iptables-save output; give it twice for nft and legacy tables")
    src.add_argument("--ipset-save", metavar="FILE", help="`ipset save` output")
    src.add_argument("--fail2ban", metavar="FILE",
                     help="`fail2ban-client status <jail>` output, one or more jails")
    src.add_argument("--docker-ps", metavar="FILE",
                     help="`docker ps --format '{{.Names}}\\t{{.Ports}}'` output")
    sel = p.add_argument_group("what to check")
    sel.add_argument("--banned", metavar="IPS", action="append", default=[],
                     help="banned IPv4 addresses, comma or space separated (no jail)")
    sel.add_argument("--ip", metavar="IP", help="check only this source IP")
    sel.add_argument("--port", metavar="PORT", type=int, action="append", default=[],
                     help="check this host TCP port (repeatable)")
    sel.add_argument("--host-ip", metavar="IP",
                     help="the host address clients connect to (default: unknown)")
    sel.add_argument("--in-iface", metavar="NAME",
                     help="interface the traffic arrives on (default: unknown, or "
                          "`ip route get` in live mode)")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--version", action="version", version=f"banprobe {__version__}")
    return p


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise InputError(f"{path}: {e.strerror}")


def _dnat_ports(rulesets: List[Ruleset]) -> List[Published]:
    """Published ports, from Docker's `-j DNAT` rules in the nat table."""
    out, seen = [], set()
    for rs in rulesets:
        for r in rs.rules("nat"):
            if r.target != "DNAT" or r.error:
                continue
            if any(c.opt == "-p" and c.args[0] != "tcp" for c in r.conds):
                continue
            dports = [c.args[0] for c in r.conds if c.opt == "--dport" and not c.neg]
            dsts = [c.args[0] for c in r.conds if c.opt == "-d" and not c.neg]
            if len(dports) != 1 or not dports[0].isdigit():
                continue
            hip = dsts[0].split("/")[0] if dsts else "0.0.0.0"
            if ipaddress.ip_address(hip).is_loopback:
                continue
            to = r.target_args.get("--to-destination", "")
            cport = to.rpartition(":")[2]
            hp = int(dports[0])
            if (hip, hp) not in seen:
                seen.add((hip, hp))
                out.append(Published(hp, int(cport) if cport.isdigit() else hp, "", hip))
    return out


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _main(args)
    except (InputError, ParseError) as e:
        print(f"banprobe: {e}", file=sys.stderr)
        return EXIT_ERROR


def _main(args) -> int:
    live = not args.iptables_save
    notes: List[str] = []

    # rulesets
    if live:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise InputError("reading the live ruleset needs root (sudo banprobe), "
                             "or pass --iptables-save FILE")
        saves = inp.live_iptables()
    else:
        saves = [(f, _read(f)) for f in args.iptables_save]
    rulesets = [parse(text, name) for name, text in saves]
    if len(rulesets) == 1 and rulesets[0].legacy_present:
        notes.append("iptables-save says iptables-legacy tables are present too; pass "
                     "`iptables-legacy-save` output as a second --iptables-save. Until then "
                     "a REACHABLE verdict is reported as INCONCLUSIVE")

    ipset_text = _read(args.ipset_save) if args.ipset_save else (inp.live_ipset() if live else None)
    ctx = Context(ipsets=inp.parse_ipset_save(ipset_text) if ipset_text is not None else None,
                  bridges=bridges_from(rulesets))

    # bans
    bans: List[Ban] = []
    if args.fail2ban:
        b, n = inp.parse_fail2ban(_read(args.fail2ban))
        bans += b
        notes += n
    for spec in args.banned:
        bans += inp.parse_ip_list(spec)
    if not args.fail2ban and not args.banned and not args.ip:
        if not live:
            raise InputError("pass --fail2ban FILE, --banned IPS or --ip IP with saved rulesets")
        b, n = inp.parse_fail2ban(inp.live_fail2ban())
        bans += b
        notes += n
    if args.ip:
        try:
            ip = ipaddress.IPv4Address(args.ip)
        except ValueError:
            raise InputError(f"--ip {args.ip!r} is not an IPv4 address")
        bans = [b for b in bans if b.ip == ip] or [Ban(ip, None)]

    # ports
    pubs: List[Published]
    dnat = _dnat_ports(rulesets)
    if args.port:
        by_port = {p.host_port: p for p in dnat}
        pubs = [by_port.get(p, Published(p, p, "")) for p in args.port]
    else:
        ps_text = _read(args.docker_ps) if args.docker_ps else (inp.live_docker() if live else None)
        if ps_text is not None:
            pubs, n = inp.parse_docker_ps(ps_text)
            notes += n
            for p in pubs:   # container port from the DNAT rule when docker ps is terse
                for d in dnat:
                    if d.host_port == p.host_port and p.host_ip == d.host_ip:
                        p.container_port = d.container_port
        else:
            pubs = dnat
    if args.host_ip:
        hip = ipaddress.IPv4Address(args.host_ip)
        ctx.host_ips.append(hip)
        for p in pubs:
            if p.host_ip == "0.0.0.0":
                p.host_ip = str(hip)

    # where traffic arrives
    iface: Dict[str, Optional[str]] = {}
    for b in bans:
        iface[str(b.ip)] = args.in_iface
        if live and not args.in_iface:
            dev, srcip = inp.live_route(str(b.ip))
            iface[str(b.ip)] = dev
            if srcip and not args.host_ip and ipaddress.IPv4Address(srcip) not in ctx.host_ips:
                ctx.host_ips.append(ipaddress.IPv4Address(srcip))

    rep = run(rulesets, ctx, bans, pubs, iface)
    rep.notes += notes
    if len(rulesets) == 1 and rulesets[0].legacy_present:
        for p in rep.probes:
            if p.result.verdict == "REACHABLE":
                p.result.verdict = "INCONCLUSIVE"
                p.inconclusive = "iptables-legacy tables are present and were not read"
                p.why = p.fix = ""

    sources = [rs.source for rs in rulesets]
    if args.json:
        print(json.dumps(to_json(rep, sources), indent=2))
    else:
        if not bans:
            print("no banned IPs")
        elif not pubs:
            print("no published TCP ports found")
        header = []
        if bans and pubs:
            where = f"on {args.in_iface}" if args.in_iface else (
                "on the interface `ip route get` names" if live else "on an unknown interface")
            to = args.host_ip or ("the address `ip route get` names" if live else "any host address")
            header.append(f"new TCP connections from {len(bans)} banned IP(s) to "
                          f"{len(pubs)} published port(s), arriving {where}, sent to {to}")
        sys.stdout.write(render_text(rep, sources, header))
    return rep.exit_code


if __name__ == "__main__":
    sys.exit(main())
