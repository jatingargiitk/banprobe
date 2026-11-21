"""Read fail2ban, Docker and ipset state, from saved files or (read-only) live."""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


class InputError(ValueError):
    pass


@dataclass
class Ban:
    ip: ipaddress.IPv4Address
    jail: Optional[str]       # None when given with --banned/--ip


@dataclass
class Published:
    host_port: int
    container_port: int
    container: str
    host_ip: str = "0.0.0.0"


def parse_fail2ban(text: str) -> Tuple[List[Ban], List[str]]:
    """Output of `fail2ban-client status <jail>` for one or more jails
    (concatenated), optionally preceded by `fail2ban-client status`.
    Returns bans and notes (IPv6 bans are noted and skipped)."""
    bans: List[Ban] = []
    notes: List[str] = []
    jail = None
    seen_jail = False
    for line in text.splitlines():
        m = re.match(r"\s*Status for the jail:\s*(\S+)", line)
        if m:
            jail, seen_jail = m.group(1), True
            continue
        m = re.match(r"[\s|`-]*Banned IP list:\s*(.*)$", line)
        if m:
            if jail is None:
                raise InputError("'Banned IP list' before any 'Status for the jail:' line")
            for tok in m.group(1).split():
                try:
                    ip = ipaddress.ip_address(tok)
                except ValueError:
                    raise InputError(f"jail {jail}: {tok!r} is not an IP address")
                if ip.version == 6:
                    notes.append(f"{tok} ({jail}): IPv6 is not checked")
                    continue
                bans.append(Ban(ip, jail))
    if not seen_jail:
        raise InputError("no 'Status for the jail:' section found "
                         "(expected `fail2ban-client status <jail>` output)")
    return bans, notes


def parse_ip_list(text: str) -> List[Ban]:
    out = []
    for tok in re.split(r"[\s,]+", text.strip()):
        if not tok:
            continue
        try:
            ip = ipaddress.ip_address(tok)
        except ValueError:
            raise InputError(f"{tok!r} is not an IP address")
        if ip.version == 6:
            raise InputError(f"{tok}: IPv6 is not supported")
        out.append(Ban(ip, None))
    return out


def jail_list(text: str) -> List[str]:
    m = re.search(r"Jail list:\s*(.*)$", text, re.M)
    if not m:
        raise InputError("no 'Jail list:' in `fail2ban-client status` output")
    return [j.strip() for j in m.group(1).split(",") if j.strip()]


def _expand(spec: str) -> List[int]:
    if "-" in spec:
        a, b = spec.split("-", 1)
        return list(range(int(a), int(b) + 1))
    return [int(spec)]


def parse_docker_ps(text: str) -> Tuple[List[Published], List[str]]:
    """Output of `docker ps --format '{{.Names}}\\t{{.Ports}}'`."""
    pubs: List[Published] = []
    notes: List[str] = []
    seen = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        name, _, ports = line.partition("\t")
        if not _:
            name, _, ports = line.strip().partition(" ")
        for part in ports.split(","):
            part = part.strip()
            if "->" not in part:
                continue
            host, cont = part.split("->", 1)
            cport, _, proto = cont.partition("/")
            if proto != "tcp":
                notes.append(f"{name} {part}: only TCP is checked")
                continue
            if host.startswith("[") or host.startswith(":::") or host.count(":") > 1:
                continue  # IPv6 listener
            hip, _, hport = host.rpartition(":")
            hip = hip or "0.0.0.0"
            if ipaddress.ip_address(hip).is_loopback:
                notes.append(f"{name} {part}: published on loopback only, not reachable from other hosts")
                continue
            hps, cps = _expand(hport), _expand(cport)
            if len(cps) == 1:
                cps = cps * len(hps)
            for hp, cp in zip(hps, cps):
                key = (hip, hp)
                if key not in seen:
                    seen.add(key)
                    pubs.append(Published(hp, cp, name, hip))
    return pubs, notes


def parse_ipset_save(text: str) -> Dict[str, List[ipaddress.IPv4Network]]:
    """Output of `ipset save` (hash:ip / hash:net sets; others are left empty
    and so are treated as unknown when matched)."""
    sets: Dict[str, List[ipaddress.IPv4Network]] = {}
    types: Dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "create":
            types[parts[1]] = parts[2]
            if parts[2] in ("hash:ip", "hash:net", "bitmap:ip") and "inet6" not in parts:
                sets[parts[1]] = []
        elif len(parts) >= 3 and parts[0] == "add" and parts[1] in sets:
            if "nomatch" in parts:
                del sets[parts[1]]   # nomatch entries: don't model, treat as unknown
                continue
            try:
                sets[parts[1]].append(ipaddress.ip_network(parts[2], strict=False))
            except ValueError:
                del sets[parts[1]]
    return sets


# ---------------------------------------------------------------- live mode

def _run(cmd: List[str], what: str, stderr: Optional[List[str]] = None) -> str:
    if shutil.which(cmd[0]) is None:
        raise InputError(f"{cmd[0]} not found; {what}")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        raise InputError(f"`{' '.join(cmd)}` timed out")
    if p.returncode != 0:
        msg = (p.stderr or p.stdout).strip().splitlines()
        raise InputError(f"`{' '.join(cmd)}` failed: {msg[-1] if msg else p.returncode}; {what}")
    if stderr is not None:
        stderr.append(p.stderr)
    return p.stdout


def live_iptables() -> List[Tuple[str, str]]:
    err: List[str] = []
    out = _run(["iptables-save"], "run as root, or pass --iptables-save FILE", err)
    saves = [("iptables-save", out)]
    legacy = "iptables-legacy tables present" in out + "".join(err)
    if legacy and not shutil.which("iptables-legacy-save"):
        saves[0] = ("iptables-save", "# Warning: iptables-legacy tables present\n" + out)
    elif legacy:
        saves.append(("iptables-legacy-save",
                      _run(["iptables-legacy-save"], "pass --iptables-save twice")))
    return saves


def live_fail2ban() -> str:
    hint = "run as root, or pass --fail2ban FILE / --banned IPS"
    status = _run(["fail2ban-client", "status"], hint)
    parts = [status]
    for jail in jail_list(status):
        parts.append(_run(["fail2ban-client", "status", jail], hint))
    return "\n".join(parts)


def live_docker() -> Optional[str]:
    if shutil.which("docker") is None:
        return None
    return _run(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"],
                "pass --docker-ps FILE or --port")


def live_ipset() -> Optional[str]:
    if shutil.which("ipset") is None:
        return None
    try:
        return _run(["ipset", "save"], "")
    except InputError:
        return None


def live_route(ip: str) -> Tuple[Optional[str], Optional[str]]:
    """(interface, local source address) the host would use to reach ip."""
    if shutil.which("ip") is None:
        return None, None
    try:
        out = _run(["ip", "-4", "route", "get", ip], "")
    except InputError:
        return None, None
    dev = re.search(r"\bdev (\S+)", out)
    src = re.search(r"\bsrc (\S+)", out)
    return (dev.group(1) if dev else None), (src.group(1) if src else None)
