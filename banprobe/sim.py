"""Walk one new inbound TCP connection through a parsed iptables ruleset.

Every match returns True, False or None (cannot be decided from the ruleset).
A rule whose verdict matters and whose match is None makes the result
INCONCLUSIVE, naming that rule; nothing is guessed.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .rules import Rule, Ruleset

IPv4 = ipaddress.IPv4Address
Net = ipaddress.IPv4Network

# Linux default net.ipv4.ip_local_port_range: the client's source port
EPHEMERAL = (32768, 60999)

# targets that never end the walk; an undecidable match on them doesn't matter
NONTERMINAL = {"LOG", "NFLOG", "ULOG", "MARK", "CONNMARK", "TOS", "DSCP", "TCPMSS",
               "CHECKSUM", "CT", "NOTRACK", "AUDIT", "TRACE", "TTL", "CLASSIFY",
               "SECMARK", "CONNSECMARK", None}
BLOCKING = {"DROP", "REJECT", "TARPIT"}
# interface names an inbound packet from another host never arrives on
_INTERNAL_IFACES = ("lo", "docker0", "docker_gwbridge", "br-", "veth")


class Unknown(Exception):
    pass


@dataclass
class Packet:
    src: IPv4
    dport: int
    dst: Optional[IPv4] = None        # None: a host address we don't know
    in_iface: Optional[str] = None
    out_iface: Optional[str] = None
    out_iface_known: bool = False
    local_dst: bool = True            # dst is one of the host's own addresses
    dnat: bool = False
    orig_dst: Optional[IPv4] = None
    orig_dport: int = 0
    proto: str = "tcp"

    def __post_init__(self):
        self.orig_dst = self.dst
        self.orig_dport = self.dport


@dataclass
class Context:
    ipsets: Optional[Dict[str, List[Net]]] = None   # None: no `ipset save` given
    bridges: List[Tuple[Net, str]] = field(default_factory=list)
    host_ips: List[IPv4] = field(default_factory=list)


@dataclass
class Walk:
    """Result of walking one builtin chain."""
    table: str
    hook: str
    source: str
    verdict: str                      # ACCEPT DROP REJECT DNAT REDIRECT POLICY-* UNKNOWN NONE
    rule: Optional[Rule] = None
    reason: str = ""
    path: List[str] = field(default_factory=list)
    evaluated: List[Tuple[Rule, bool]] = field(default_factory=list)
    entered: List[str] = field(default_factory=list)


# ----------------------------------------------------------------- matching

def _net(s: str) -> Net:
    return ipaddress.ip_network(s, strict=False)


def _ports(spec: str) -> List[Tuple[int, int]]:
    out = []
    for part in spec.split(","):
        if ":" in part:
            a, b = part.split(":", 1)
            out.append((int(a or 0), int(b or 65535)))
        else:
            p = int(part)
            out.append((p, p))
    return out


def _in_ports(port: int, spec: str) -> bool:
    return any(a <= port <= b for a, b in _ports(spec))


def _sport(spec: str) -> Optional[bool]:
    lo, hi = EPHEMERAL
    rngs = _ports(spec)
    if any(a <= lo and hi <= b for a, b in rngs):
        return True
    if all(b < lo or a > hi for a, b in rngs):
        return False
    return None


def _iface(pattern: str, name: Optional[str], inbound: bool) -> Optional[bool]:
    if pattern == "+":
        return True
    if name is not None:
        if pattern.endswith("+"):
            return name.startswith(pattern[:-1])
        return name == pattern
    if inbound:
        base = pattern.rstrip("+")
        if any(base == x or base.startswith(x) for x in _INTERNAL_IFACES):
            return False
    return None


def _dst_match(net: Net, addr: Optional[IPv4], local: bool, ctx: Context) -> Optional[bool]:
    if addr is not None:
        return addr in net
    # unknown host address: it isn't loopback (the packet came from another
    # host) and we assume it isn't inside a Docker bridge subnet
    if net.subnet_of(_net("127.0.0.0/8")):
        return False
    if any(net.subnet_of(b) for b, _ in ctx.bridges):
        return False
    if local and ctx.host_ips:
        return any(ip in net for ip in ctx.host_ips)
    return None


def _ctstates(states: str, pkt: Packet) -> bool:
    have = {"NEW"} | ({"DNAT"} if pkt.dnat else set())
    return bool(have & {s.upper() for s in states.split(",")})


def _cond(c, pkt: Packet, ctx: Context) -> Optional[bool]:
    opt, a, mod = c.opt, c.args, c.module
    if opt == "-s":
        return pkt.src in _net(a[0])
    if opt == "-d":
        return _dst_match(_net(a[0]), pkt.dst, pkt.local_dst, ctx)
    if opt == "-p":
        return a[0].lower() in ("tcp", "6", "all", "0")
    if opt == "-i":
        return _iface(a[0], pkt.in_iface, inbound=True)
    if opt == "-o":
        if not pkt.out_iface_known:
            return None
        return _iface(a[0], pkt.out_iface, inbound=False)
    if mod == "comment":
        return True
    if mod in ("tcp", None, "udp") and opt in ("--dport", "--sport", "--syn", "--tcp-flags"):
        if opt == "--dport":
            return _in_ports(pkt.dport, a[0])
        if opt == "--sport":
            return _sport(a[0])
        if opt == "--syn":
            return True
        mask = {f for f in a[0].upper().split(",")}
        comp = {f for f in a[1].upper().split(",")}
        if "ALL" in mask:
            mask = {"SYN", "ACK", "FIN", "RST", "URG", "PSH"}
        if "NONE" in comp:
            comp = set()
        return (mask & {"SYN"}) == comp
    if mod == "multiport":
        if opt == "--dports":
            return _in_ports(pkt.dport, a[0])
        if opt == "--sports":
            return _sport(a[0])
        if opt == "--ports":
            sp = _sport(a[0])
            return True if _in_ports(pkt.dport, a[0]) else sp
    if mod in ("conntrack", "state"):
        if opt in ("--ctstate", "--state"):
            return _ctstates(a[0], pkt)
        if opt == "--ctorigdstport":
            return _in_ports(pkt.orig_dport, a[0])
        if opt == "--ctorigdst":
            return _dst_match(_net(a[0]), pkt.orig_dst, True, ctx)
        if opt == "--ctorigsrc":
            return pkt.src in _net(a[0])
        if opt == "--ctorigsrcport":
            return _sport(a[0])
        if opt == "--ctproto":
            return a[0].lower() in ("tcp", "6")
        if opt == "--ctdir":
            return a[0].upper() == "ORIGINAL"
    if mod == "addrtype" and opt in ("--dst-type", "--src-type"):
        types = {t.upper() for t in a[0].split(",")}
        if opt == "--dst-type":
            if "LOCAL" in types and pkt.local_dst:
                return True
            if "UNICAST" in types:
                return True
            if types <= {"LOCAL", "BROADCAST", "MULTICAST", "ANYCAST", "BLACKHOLE",
                         "UNREACHABLE", "PROHIBIT", "NAT"}:
                return False
            return None
        if "UNICAST" in types:
            return True
        if types <= {"LOCAL", "BROADCAST", "MULTICAST", "ANYCAST", "BLACKHOLE",
                     "UNREACHABLE", "PROHIBIT"}:
            return False
        return None
    if mod == "set" and opt == "--match-set":
        name, flags = a
        if ctx.ipsets is None or name not in ctx.ipsets:
            return None
        if flags == "src":
            return any(pkt.src in n for n in ctx.ipsets[name])
        if flags == "dst" and pkt.dst is not None:
            return any(pkt.dst in n for n in ctx.ipsets[name])
        return None
    if mod == "iprange" and opt in ("--src-range", "--dst-range"):
        lo, hi = (IPv4(x) for x in a[0].split("-"))
        if opt == "--src-range":
            return lo <= pkt.src <= hi
        if pkt.dst is None:
            return None
        return lo <= pkt.dst <= hi
    return None


def _describe(c) -> str:
    s = ("! " if c.neg else "") + " ".join([c.opt] + c.args)
    return (f"-m {c.module} " + s) if c.module else s


def match(rule: Rule, pkt: Packet, ctx: Context) -> Tuple[Optional[bool], str]:
    unknown = []
    for c in rule.conds:
        try:
            r = _cond(c, pkt, ctx)
        except ValueError:
            r = None
        if r is not None and c.neg:
            r = not r
        if r is False:
            return False, ""
        if r is None:
            unknown.append(c)
    if unknown:
        return None, _unknown_reason(unknown[0], pkt, ctx)
    return True, ""


def _unknown_reason(c, pkt: Packet, ctx: Context) -> str:
    d = _describe(c)
    if c.opt == "-i":
        return f"`{d}`: the interface the traffic arrives on is unknown (pass --in-iface)"
    if c.opt == "-o":
        return f"`{d}`: the output interface is unknown"
    if c.opt in ("-d", "--ctorigdst"):
        return f"`{d}`: the host address the traffic is sent to is unknown (pass --host-ip)"
    if c.opt == "--match-set":
        if ctx.ipsets is None:
            return f"`{d}`: ipset members unknown (pass --ipset-save FILE)"
        return f"`{d}`: ipset {c.args[0]} is not in the ipset save (or not a src set)"
    if c.opt in ("--sport", "--sports", "--ctorigsrcport", "--ports"):
        return f"`{d}`: depends on the client's source port"
    return f"`{d}` can't be evaluated from the ruleset"


# ----------------------------------------------------------------- walking

class _Done(Exception):
    def __init__(self, verdict: str, rule: Optional[Rule], reason: str = ""):
        self.verdict, self.rule, self.reason = verdict, rule, reason


def _run(rs: Ruleset, table: str, name: str, pkt: Packet, ctx: Context, w: Walk,
         depth: int) -> str:
    """Returns 'RETURN' when the chain falls through or returns; raises _Done."""
    if depth > 32:
        raise _Done("UNKNOWN", None, f"chain nesting deeper than 32 at {name}")
    ch = rs.chain(table, name)
    w.path.append(name)
    w.entered.append(name)
    for rule in ch.rules:
        if rule.error:
            raise _Done("UNKNOWN", rule, f"could not parse this rule ({rule.error})")
        m, why = match(rule, pkt, ctx)
        if m is None:
            if rule.target in NONTERMINAL:
                continue
            raise _Done("UNKNOWN", rule, why)
        w.evaluated.append((rule, m))
        if not m:
            continue
        t = rule.target
        if t in NONTERMINAL:
            continue
        if t == "RETURN":
            w.path.pop()
            return "RETURN"
        if t in ("ACCEPT",) or t in BLOCKING:
            raise _Done(t, rule)
        if t in ("DNAT", "REDIRECT") and table == "nat":
            raise _Done(t, rule)
        if t in ("SNAT", "MASQUERADE", "NETMAP") and table == "nat":
            raise _Done("ACCEPT", rule)
        if rs.chain(table, t) is not None and rs.chain(table, t).policy is None:
            _run(rs, table, t, pkt, ctx, w, depth + 1)
            if rule.goto:
                w.path.pop()
                return "RETURN"
            continue
        raise _Done("UNKNOWN", rule, f"target {t} is not understood")
    w.path.pop()
    return "RETURN"


def walk(rs: Ruleset, table: str, hook: str, pkt: Packet, ctx: Context) -> Walk:
    w = Walk(table, hook, rs.source, "NONE")
    ch = rs.chain(table, hook)
    if ch is None:
        return w
    try:
        _run(rs, table, hook, pkt, ctx, w, 0)
        w.verdict = "POLICY-" + (ch.policy or "ACCEPT")
        w.path = [hook]
    except _Done as d:
        w.verdict, w.rule, w.reason = d.verdict, d.rule, d.reason
    return w


@dataclass
class Result:
    verdict: str                      # BLOCKED REACHABLE INCONCLUSIVE
    route: str = ""                   # INPUT or FORWARD
    dnat_to: Optional[Tuple[str, int]] = None
    dnat_walk: Optional[Walk] = None
    walks: List[Walk] = field(default_factory=list)
    decider: Optional[Walk] = None    # the walk that decided (or was unknown)
    packet: Optional[Packet] = None


def _apply_dnat(pkt: Packet, rule: Rule, ctx: Context) -> Optional[str]:
    if rule.target == "REDIRECT":
        port = rule.target_args.get("--to-ports", "")
        if port:
            if not port.isdigit():
                return "REDIRECT to a port range"
            pkt.dport = int(port)
        pkt.dnat = True
        return None
    to = rule.target_args.get("--to-destination", "")
    host, _, port = to.partition(":") if to.count(":") == 1 else (to, "", "")
    if not host or "-" in host or "-" in port or (port and not port.isdigit()):
        return f"DNAT target {to!r} (ranges or IPv6) is not supported"
    pkt.dst = IPv4(host)
    if port:
        pkt.dport = int(port)
    pkt.dnat = True
    pkt.local_dst = pkt.dst in _net("127.0.0.0/8") or pkt.dst in ctx.host_ips
    return None


def simulate(rulesets: Sequence[Ruleset], pkt: Packet, ctx: Context) -> Result:
    res = Result("REACHABLE", packet=pkt)
    unknown: Optional[Walk] = None

    def stage(table: str, hook: str) -> Optional[Result]:
        nonlocal unknown
        for rs in rulesets:
            w = walk(rs, table, hook, pkt, ctx)
            if w.verdict == "NONE":
                continue
            res.walks.append(w)
            if w.verdict in BLOCKING or w.verdict == "POLICY-DROP":
                res.verdict, res.decider = "BLOCKED", w
                return res
            if w.verdict == "UNKNOWN" and unknown is None:
                unknown = w
        return None

    for table in ("raw", "mangle"):
        if stage(table, "PREROUTING"):
            return res
    for rs in rulesets:
        w = walk(rs, "nat", "PREROUTING", pkt, ctx)
        if w.verdict == "NONE":
            continue
        if w.verdict == "UNKNOWN":
            res.walks.append(w)
            res.verdict, res.decider = "INCONCLUSIVE", w
            return res
        if w.verdict in ("DNAT", "REDIRECT"):
            err = _apply_dnat(pkt, w.rule, ctx)
            res.walks.append(w)
            if err:
                w.verdict, w.reason = "UNKNOWN", err
                res.verdict, res.decider = "INCONCLUSIVE", w
                return res
            res.dnat_walk = w
            res.dnat_to = (str(pkt.dst) if pkt.dst else "host", pkt.dport)
            break
        if w.verdict in BLOCKING:
            res.walks.append(w)
            res.verdict, res.decider = "BLOCKED", w
            return res
    res.route = "INPUT" if pkt.local_dst else "FORWARD"
    if res.route == "FORWARD":
        for net, iface in ctx.bridges:
            if pkt.dst in net:
                pkt.out_iface, pkt.out_iface_known = iface, True
                break
    for table in ("mangle", "filter"):
        if stage(table, res.route):
            return res
    if unknown is not None:
        res.verdict, res.decider = "INCONCLUSIVE", unknown
        return res
    filt = [w for w in res.walks if w.table == "filter"]
    res.decider = filt[-1] if filt else None
    return res


def bridges_from(rulesets: Sequence[Ruleset]) -> List[Tuple[Net, str]]:
    """Docker bridge subnets, from `-s SUBNET ! -o BRIDGE -j MASQUERADE` rules."""
    out = []
    for rs in rulesets:
        for r in rs.rules("nat"):
            if r.chain != "POSTROUTING" or r.target != "MASQUERADE" or r.error:
                continue
            src = [c for c in r.conds if c.opt == "-s" and not c.neg]
            oif = [c for c in r.conds if c.opt == "-o" and c.neg]
            if src and oif:
                net = _net(src[0].args[0])
                if net.prefixlen < 32 and (net, oif[0].args[0]) not in out:
                    out.append((net, oif[0].args[0]))
    return out
