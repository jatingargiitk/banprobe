"""Parser for `iptables-save` output (iptables-legacy and iptables-nft)."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional

BUILTIN = {
    "raw": ("PREROUTING", "OUTPUT"),
    "mangle": ("PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"),
    "nat": ("PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"),
    "filter": ("INPUT", "FORWARD", "OUTPUT"),
    "security": ("INPUT", "FORWARD", "OUTPUT"),
}

# options that take more than one argument / no argument
_NARGS = {"--tcp-flags": 2, "--match-set": 2, "--syn": 0, "-f": 0, "--fragment": 0,
          "--rcheck": 0, "--update": 0, "--set": 0, "--remove": 0, "--rsource": 0,
          "--rdest": 0, "--log-uid": 0, "--log-tcp-sequence": 0, "--log-tcp-options": 0,
          "--log-ip-options": 0, "--random": 0, "--persistent": 0, "--random-fully": 0,
          "--notrack": 0, "--return-nomatch": 0, "--update-counters": 0,
          "--update-subcounters": 0, "--physdev-is-in": 0, "--physdev-is-out": 0,
          "--physdev-is-bridged": 0, "--reap": 0, "--mask": 1}

_ALIASES = {"--source": "-s", "--src": "-s", "--destination": "-d", "--dst": "-d",
            "--protocol": "-p", "--in-interface": "-i", "--out-interface": "-o",
            "--jump": "-j", "--goto": "-g", "--match": "-m", "--destination-port": "--dport",
            "--source-port": "--sport", "--destination-ports": "--dports",
            "--source-ports": "--sports"}


class ParseError(ValueError):
    pass


@dataclass
class Cond:
    module: Optional[str]   # None for core options (-s, -d, -p, -i, -o)
    opt: str
    args: List[str]
    neg: bool = False


@dataclass
class Rule:
    table: str
    chain: str
    line: int
    text: str
    source: str
    conds: List[Cond] = field(default_factory=list)
    target: Optional[str] = None
    goto: bool = False
    target_args: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None   # set when the rule could not be parsed

    def where(self) -> str:
        return f"{self.source}:{self.line}"


@dataclass
class Chain:
    name: str
    policy: Optional[str]   # None for user chains
    rules: List[Rule] = field(default_factory=list)


@dataclass
class Ruleset:
    source: str
    tables: Dict[str, Dict[str, Chain]] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    legacy_present: bool = False

    def chain(self, table: str, name: str) -> Optional[Chain]:
        return self.tables.get(table, {}).get(name)

    def rules(self, table: Optional[str] = None):
        for tname, chains in self.tables.items():
            if table and tname != table:
                continue
            for ch in chains.values():
                yield from ch.rules


def _parse_rule(table: str, chain: str, tokens: List[str], line: int, text: str,
                source: str) -> Rule:
    rule = Rule(table, chain, line, text, source)
    module: Optional[str] = None
    neg = False
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok == "!":
            neg = True
            i += 1
            continue
        tok = _ALIASES.get(tok, tok)
        if tok == "-m":
            if i + 1 >= n:
                raise ParseError("-m without module")
            module = tokens[i + 1]
            i += 2
            continue
        if tok in ("-j", "-g"):
            if i + 1 >= n:
                raise ParseError(f"{tok} without target")
            rule.target = tokens[i + 1]
            rule.goto = tok == "-g"
            i += 2
            while i < n:  # target options
                opt = tokens[i]
                if not opt.startswith("--"):
                    raise ParseError(f"unexpected {opt!r} after target")
                if i + 1 < n and not tokens[i + 1].startswith("--"):
                    rule.target_args[opt] = tokens[i + 1]
                    i += 2
                else:
                    rule.target_args[opt] = ""
                    i += 1
            break
        if not tok.startswith("-"):
            raise ParseError(f"unexpected {tok!r}")
        if tok in ("-s", "-d", "-p", "-i", "-o"):
            nargs = 1
            mod = None
        else:
            nargs = _NARGS.get(tok)
            if nargs is None:
                nargs = 1 if i + 1 < n and not tokens[i + 1].startswith("-") \
                    and tokens[i + 1] != "!" else 0
            mod = module
        if nargs and i + nargs >= n:
            raise ParseError(f"{tok} is missing its argument")
        args = tokens[i + 1:i + 1 + nargs]
        rule.conds.append(Cond(mod, tok, args, neg))
        neg = False
        i += 1 + nargs
    if neg:
        raise ParseError("dangling '!'")
    return rule


def parse(text: str, source: str = "<iptables-save>") -> Ruleset:
    rs = Ruleset(source)
    table: Optional[str] = None
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            if "iptables-legacy tables present" in line:
                rs.legacy_present = True
            continue
        if line.startswith("*"):
            table = line[1:].strip()
            rs.tables.setdefault(table, {})
            for b in BUILTIN.get(table, ()):
                rs.tables[table].setdefault(b, Chain(b, "ACCEPT"))
            continue
        if line == "COMMIT":
            table = None
            continue
        if table is None:
            raise ParseError(f"{source}:{lineno}: not iptables-save output "
                             f"(line outside a table): {line[:60]!r}")
        if line.startswith(":"):
            parts = line[1:].split()
            name = parts[0]
            policy = parts[1] if len(parts) > 1 and parts[1] != "-" else None
            rs.tables[table][name] = Chain(name, policy)
            continue
        line = re.sub(r"^\[\d+:\d+\]\s*", "", line)  # iptables-save -c counters
        if line.startswith("-A ") or line.startswith("-I "):
            try:
                tokens = shlex.split(line)
            except ValueError as e:
                tokens = None
                err = f"cannot tokenize: {e}"
            chain_name = line.split()[1]
            ch = rs.tables[table].setdefault(chain_name, Chain(chain_name, None))
            if tokens is None:
                ch.rules.append(Rule(table, chain_name, lineno, line, source, error=err))
                continue
            try:
                rule = _parse_rule(table, chain_name, tokens[2:], lineno, line, source)
            except ParseError as e:
                rule = Rule(table, chain_name, lineno, line, source, error=str(e))
            ch.rules.append(rule)
            continue
        raise ParseError(f"{source}:{lineno}: not iptables-save output: {line[:60]!r}")
    if not rs.tables:
        raise ParseError(f"{source}: no tables found (is this iptables-save output?)")
    return rs
