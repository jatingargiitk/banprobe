"""Probe each banned IP against each published port and explain the verdict."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .inputs import Ban, Published
from .rules import Rule, Ruleset
from .sim import Context, Packet, Result, Walk, simulate, _in_ports

PORT_OPTS = ("--dport", "--dports", "--ports")


@dataclass
class Probe:
    ban: Ban
    pub: Published
    result: Result
    why: str = ""
    fix: str = ""
    inconclusive: str = ""


@dataclass
class Skip:
    ban: Ban
    pub: Published
    reason: str


@dataclass
class Report:
    probes: List[Probe] = field(default_factory=list)
    skipped: List[Skip] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def count(self, verdict: str) -> int:
        return sum(p.result.verdict == verdict for p in self.probes)

    @property
    def exit_code(self) -> int:
        if self.count("REACHABLE"):
            return 1
        if self.count("INCONCLUSIVE"):
            return 2
        return 0


def f2b_names(jail: Optional[str], rulesets: Sequence[Ruleset]) -> List[str]:
    if jail is not None:
        return [f"f2b-{jail}"]
    names = set()
    for rs in rulesets:
        for chains in rs.tables.values():
            names.update(n for n in chains if n.startswith("f2b-"))
        for r in rs.rules():
            for c in r.conds:
                if c.opt == "--match-set" and c.args[0].startswith("f2b-"):
                    names.add(c.args[0])
    return sorted(names)


def hooks(names: List[str], rulesets: Sequence[Ruleset]) -> List[Rule]:
    """Rules outside the f2b chains that send traffic into them."""
    out = []
    for rs in rulesets:
        for r in rs.rules("filter"):
            if r.chain in names or r.error:
                continue
            if r.target in names or any(c.opt == "--match-set" and c.args[0] in names
                                        for c in r.conds):
                out.append(r)
    return out


def hook_ports(rule: Rule) -> Optional[str]:
    """The destination ports a hook covers, or None for all ports."""
    specs = [c.args[0] for c in rule.conds if c.opt in PORT_OPTS and not c.neg]
    return ",".join(specs) if specs else None


def in_scope(hks: List[Rule], pub: Published) -> Optional[str]:
    """None if the jail is meant to cover this port, else the reason it isn't."""
    if not hks:
        return None
    specs = []
    for h in hks:
        spec = hook_ports(h)
        if spec is None:
            return None
        if _in_ports(pub.host_port, spec):
            return None
        # past the DNAT (FORWARD, DOCKER-USER) the port is the container port
        if h.chain != "INPUT" and _in_ports(pub.container_port, spec):
            return None
        specs.append(spec)
    return "only covers port(s) " + ",".join(dict.fromkeys(specs))


def _label(names: List[str]) -> str:
    return names[0] if len(names) == 1 else "the f2b-* chains"


def _hooked_from(hks: List[Rule]) -> str:
    chains = list(dict.fromkeys(h.chain for h in hks))
    where = ", ".join(h.where() for h in hks)
    return f"{'/'.join(chains)} ({where})"


def explain(p: Probe, names: List[str], hks: List[Rule]) -> None:
    res, pub, ban = p.result, p.pub, p.ban
    ip, hp, cp = ban.ip, pub.host_port, res.packet.dport
    jail = ban.jail or "<jail>"
    label = _label(names)
    if res.verdict == "INCONCLUSIVE":
        w = res.decider
        if w.rule is not None:
            p.inconclusive = f"{w.rule.text}  ({w.rule.where()}): {w.reason}"
        else:
            p.inconclusive = w.reason
        return
    if res.verdict != "REACHABLE":
        return
    hook_ids = {id(h) for h in hks}
    evaluated = [(r, m) for w in res.walks for r, m in w.evaluated if id(r) in hook_ids]
    entered = {c for w in res.walks if w.table == "filter" for c in w.entered}
    dnat = res.dnat_to is not None and res.route == "FORWARD"
    to = f"{res.dnat_to[0]}:{res.dnat_to[1]}" if res.dnat_to else ""

    if not hks:
        p.why = (f"no rule references {label} (as a chain or an ipset), so nothing "
                 f"in this ruleset enforces the ban")
        p.fix = (f"check `fail2ban-client get {jail} actions` and fail2ban.log: the ban "
                 f"action may have failed, or it bans with nftables, which banprobe doesn't read")
        return

    if not evaluated:
        visited = [h for h in hks if h.chain in entered]
        if visited:
            h = visited[0]
            d = res.decider.rule
            at = f"{d.chain} {d.target} at {d.where()}" if d else f"{res.decider.hook} policy"
            p.why = (f"{at} lets it through before the {label} hook at {h.where()} is reached")
            p.fix = (f"move the {label} hook above it (`iptables -I {h.chain} 1 ...`), "
                     f"or restart fail2ban after the rule that is inserted above it")
            return
        if dnat:
            p.why = (f"{label} is hooked from {_hooked_from(hks)}, but :{hp} is DNATed "
                     f"to {to}, so the connection goes through FORWARD and never passes "
                     f"{'/'.join(dict.fromkeys(h.chain for h in hks))}")
            p.fix = f"set `chain = DOCKER-USER` for [{jail}] in jail.local"
            specs = [hook_ports(h) for h in hks]
            if hp != cp and all(s is not None and not _in_ports(cp, s) for s in specs):
                p.fix += (f"; in DOCKER-USER the port is already the container port, so use "
                          f"`port = {cp}` (or match the host port with "
                          f"`-m conntrack --ctorigdstport {hp}`)")
            return
        p.why = (f"{label} is hooked from {_hooked_from(hks)}, but this connection is "
                 f"delivered locally through INPUT (no DNAT for :{hp})")
        p.fix = f"set `chain = INPUT` for [{jail}] in jail.local"
        return

    missed = [r for r, m in evaluated if not m]
    matched = [r for r, m in evaluated if m]
    if not matched:
        h = missed[0]
        sets = [c.args[0] for c in h.conds if c.opt == "--match-set"]
        spec = hook_ports(h)
        if sets:
            p.why = f"{ip} is not in ipset {sets[0]}, although fail2ban lists it as banned"
            p.fix = f"`fail2ban-client reload {jail}` re-applies its bans"
        elif spec is not None and not _in_ports(cp, spec) and dnat:
            p.why = (f"the {label} hook at {h.where()} matches port(s) {spec}, but in "
                     f"{h.chain} this connection already has the container port {cp} "
                     f"(host port {hp}, DNATed to {to})")
            p.fix = (f"use `port = {cp}` for [{jail}], or match the host port with "
                     f"`-m conntrack --ctorigdstport {hp}`")
        else:
            p.why = f"the {label} hook at {h.where()} doesn't match this connection"
        return
    if any(n in entered for n in names):
        p.why = (f"{ip} is not in {label}: fail2ban lists it as banned, but the chain "
                 f"has no rule that matches it")
        p.fix = f"`fail2ban-client reload {jail}` re-applies its bans"
        return
    d = res.decider.rule
    p.why = f"the {label} hook matched, but {d.where() if d else 'the policy'} accepts it"


def run(rulesets: Sequence[Ruleset], ctx: Context, bans: List[Ban], pubs: List[Published],
        in_iface: Optional[Dict[str, Optional[str]]] = None) -> Report:
    rep = Report()
    for ban in bans:
        names = f2b_names(ban.jail, rulesets)
        hks = hooks(names, rulesets)
        for pub in pubs:
            reason = in_scope(hks, pub)
            if reason is not None:
                rep.skipped.append(Skip(ban, pub, f"jail {ban.jail} {reason}"))
                continue
            dst = None if pub.host_ip == "0.0.0.0" else ipaddress.IPv4Address(pub.host_ip)
            iface = (in_iface or {}).get(str(ban.ip))
            pkt = Packet(src=ban.ip, dport=pub.host_port, dst=dst, in_iface=iface)
            res = simulate(rulesets, pkt, ctx)
            pr = Probe(ban, pub, res)
            explain(pr, names, hks)
            rep.probes.append(pr)
    return rep


# ---------------------------------------------------------------- output

def _walk_line(w: Walk, multi: bool) -> str:
    chain = " -> ".join(w.entered) if w.entered else w.hook
    if w.verdict.startswith("POLICY-"):
        v = f"policy {w.verdict[7:]}"
    elif w.verdict == "DNAT":
        v = f"DNAT to {w.rule.target_args.get('--to-destination')} ({w.rule.where()})"
    elif w.verdict == "UNKNOWN":
        v = f"can't decide at {w.rule.where()}" if w.rule else "can't decide"
    else:
        v = f"{w.verdict} ({w.rule.where()})"
    pre = f"[{w.source}] " if multi and w.rule is None else ""
    return f"{pre}{w.table} {chain}: {v}"


def _shown_walks(res: Result) -> List[Walk]:
    out = []
    for w in res.walks:
        if w.table in ("raw", "mangle") and w.verdict.startswith("POLICY-") or \
                w.table == "nat" and w.verdict.startswith("POLICY-"):
            continue
        out.append(w)
    return out


def target_text(p: Probe) -> str:
    r = p.result
    s = f":{p.pub.host_port}"
    if p.pub.host_ip != "0.0.0.0":
        s = f"{p.pub.host_ip}:{p.pub.host_port}"
    if r.dnat_to:
        who = f"{p.pub.container} " if p.pub.container else ""
        s += f" -> {who}{r.dnat_to[0]}:{r.dnat_to[1]}"
    elif p.pub.container:
        s += f" ({p.pub.container})"
    return s


def render_text(rep: Report, sources: List[str], header: List[str]) -> str:
    multi = len(sources) > 1
    out = []
    out.extend(header)
    if header:
        out.append("")
    for p in rep.probes:
        jail = p.ban.jail or "-"
        out.append(f"{p.result.verdict:<12} {str(p.ban.ip):<15} {jail:<10} {target_text(p)}")
        walks = _shown_walks(p.result)
        for i, w in enumerate(walks):
            out.append(("  path: " if i == 0 else "        ") + _walk_line(w, multi))
        if p.inconclusive:
            out.append(f"  rule: {p.inconclusive}")
        if p.why:
            out.append(f"  why:  {p.why}")
        if p.fix:
            out.append(f"  fix:  {p.fix}")
    for s in rep.skipped:
        out.append(f"{'skipped':<12} {str(s.ban.ip):<15} {s.ban.jail or '-':<10} "
                   f":{s.pub.host_port}: {s.reason}")
    for n in rep.notes:
        out.append(f"note: {n}")
    if rep.probes or rep.skipped:
        out.append("")
    line = (f"{len(rep.probes)} checked: {rep.count('REACHABLE')} reachable, "
            f"{rep.count('BLOCKED')} blocked, {rep.count('INCONCLUSIVE')} inconclusive")
    if rep.skipped:
        line += f"; {len(rep.skipped)} skipped (port outside the jail's ports)"
    out.append(line)
    return "\n".join(out) + "\n"


def _walk_json(w: Walk) -> dict:
    d = {"table": w.table, "hook": w.hook, "ruleset": w.source, "chains": w.entered,
         "verdict": w.verdict}
    if w.rule is not None:
        d["rule"] = {"where": w.rule.where(), "chain": w.rule.chain, "text": w.rule.text}
    if w.reason:
        d["reason"] = w.reason
    return d


def to_json(rep: Report, sources: List[str]) -> dict:
    return {
        "rulesets": sources,
        "results": [{
            "ip": str(p.ban.ip), "jail": p.ban.jail,
            "host_ip": p.pub.host_ip, "host_port": p.pub.host_port, "proto": "tcp",
            "container": p.pub.container or None,
            "dnat_to": (f"{p.result.dnat_to[0]}:{p.result.dnat_to[1]}"
                        if p.result.dnat_to else None),
            "route": p.result.route or None,
            "verdict": p.result.verdict,
            "walks": [_walk_json(w) for w in p.result.walks],
            "why": p.why or None, "fix": p.fix or None,
            "inconclusive": p.inconclusive or None,
        } for p in rep.probes],
        "skipped": [{"ip": str(s.ban.ip), "jail": s.ban.jail, "host_port": s.pub.host_port,
                     "reason": s.reason} for s in rep.skipped],
        "notes": rep.notes,
        "summary": {"reachable": rep.count("REACHABLE"), "blocked": rep.count("BLOCKED"),
                    "inconclusive": rep.count("INCONCLUSIVE"), "skipped": len(rep.skipped)},
        "exit_code": rep.exit_code,
    }
