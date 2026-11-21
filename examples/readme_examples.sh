#!/usr/bin/env bash
# Re-runs every command shown in README.md and records its output (and exit
# code) under examples/out/. CI runs this and fails if anything changed;
# tests/test_readme.py checks each recorded output appears in README.md.
set -u
cd "$(dirname "$0")"
mkdir -p out

record() {  # record NAME DIR -- command...
  local name="$1" dir="$2"; shift 3
  local out="$PWD/out/$name.txt"
  (cd "$dir" && "$@") > "$out" 2>&1
  echo "exit $?" >> "$out"
}

for d in server docker-user fixed; do
  record "$d" "$d" -- banprobe --iptables-save iptables-save.txt --fail2ban fail2ban.txt --docker-ps docker-ps.txt
done
echo "recorded: $(ls out | tr '\n' ' ')"
