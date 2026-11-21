#!/usr/bin/env bash
# Real fail2ban + Docker + packets, for a throwaway VM / CI runner with sudo.
#
# Runs nginx published as :8080, puts a client with address 10.200.0.2 in a
# network namespace, bans that address with fail2ban, and for each jail
# configuration checks that banprobe's verdict matches what a real TCP
# connection from 10.200.0.2 to 10.200.0.1:8080 does:
#   1. no ban                                   -> connection works
#   2. banaction chain INPUT,       port = 8080 -> banprobe REACHABLE, curl works
#   3. banaction chain DOCKER-USER, port = 8080 -> banprobe REACHABLE, curl works
#   4. banaction chain DOCKER-USER, port = 80   -> banprobe BLOCKED,   curl fails
#   5. unban                                    -> connection works
# It changes the firewall and fail2ban config: do not run it on a real server.
set -euo pipefail

BANNED=10.200.0.2
HOST=10.200.0.1
OUT=${OUT:-e2e-out}
BANPROBE=$(command -v banprobe)
mkdir -p "$OUT"

log() { printf '\n== %s\n' "$*"; }

curl_from_banned() {  # prints the HTTP status, or "failed"
  sudo ip netns exec bp curl -s -o /dev/null -m 5 -w '%{http_code}' "http://$HOST:8080/" || echo failed
}

probe() {  # probe NAME EXPECTED_EXIT
  local name=$1 want=$2 got=0
  sudo iptables-save > "$OUT/$name.iptables-save.txt" 2>&1
  sudo fail2ban-client status web > "$OUT/$name.fail2ban.txt"
  sudo "$BANPROBE" > "$OUT/$name.banprobe.txt" 2>&1 || got=$?
  cat "$OUT/$name.banprobe.txt"
  if [ "$got" != "$want" ]; then
    echo "FAIL: banprobe exit $got, expected $want"; exit 1
  fi
}

expect_curl() {  # expect_curl ok|blocked
  local status
  status=$(curl_from_banned)
  echo "curl from $BANNED -> $HOST:8080: $status"
  case "$1" in
    ok) [ "$status" = 200 ] || { echo "FAIL: expected HTTP 200"; exit 1; } ;;
    blocked) case "$status" in *failed|000) ;; *) echo "FAIL: expected no connection"; exit 1 ;; esac ;;
  esac
}

jail() {  # jail CHAIN PORT
  sudo tee /etc/fail2ban/jail.local > /dev/null <<JAIL
[DEFAULT]
bantime = 1h

[web]
enabled = true
filter = banprobe-web
logpath = /var/log/banprobe-web.log
backend = polling
port = $2
banaction = iptables-multiport[chain="$1"]
JAIL
  sudo fail2ban-client unban --all > /dev/null 2>&1 || true
  sudo systemctl stop fail2ban
  # fail2ban can leave f2b-web and its hook behind on stop; the next start then
  # fails to create the chain and keeps banning through the old hook
  sudo iptables-save | grep -E '^-A [A-Z-]+ .*-j f2b-web$' | sed 's/^-A/-D/' |
    while read -r rule; do sudo iptables $rule; done
  sudo iptables -F f2b-web 2> /dev/null && sudo iptables -X f2b-web
  sudo rm -f /var/lib/fail2ban/fail2ban.sqlite3
  sudo systemctl start fail2ban
  for _ in $(seq 30); do sudo fail2ban-client ping > /dev/null 2>&1 && break; sleep 1; done
  sudo fail2ban-client status web > /dev/null
  sudo fail2ban-client set web banip "$BANNED" > /dev/null
  sudo fail2ban-client status web | grep -q "Banned IP list:.*$BANNED"
}

log "setup"
docker version --format 'docker {{.Server.Version}}' | tee "$OUT/versions.txt"
sudo iptables --version | tee -a "$OUT/versions.txt"
fail2ban-client --version | head -1 | tee -a "$OUT/versions.txt"
docker rm -f bp-web > /dev/null 2>&1 || true
docker run -d --name bp-web -p 8080:80 nginx:alpine > /dev/null
for _ in $(seq 30); do curl -sf -o /dev/null http://127.0.0.1:8080/ && break; sleep 1; done

sudo ip netns add bp
sudo ip link add bp-host type veth peer name bp-peer
sudo ip link set bp-peer netns bp
sudo ip addr add "$HOST/24" dev bp-host
sudo ip link set bp-host up
sudo ip -n bp addr add "$BANNED/24" dev bp-peer
sudo ip -n bp link set bp-peer up
sudo ip -n bp link set lo up

sudo rm -f /etc/fail2ban/jail.d/defaults-debian.conf
printf '[Definition]\nfailregex = ^bad request from <HOST>$\n' | sudo tee /etc/fail2ban/filter.d/banprobe-web.conf > /dev/null
sudo touch /var/log/banprobe-web.log

log "1. no ban"
expect_curl ok

log "2. chain = INPUT, port = 8080"
jail INPUT 8080
probe input-8080 1
grep -Eq "^REACHABLE +$BANNED +web +:8080 -> bp-web 172\.17\.[0-9.]+:80$" "$OUT/input-8080.banprobe.txt"
grep -q "hooked from INPUT" "$OUT/input-8080.banprobe.txt"
expect_curl ok

log "3. chain = DOCKER-USER, port = 8080"
jail DOCKER-USER 8080
probe docker-user-8080 1
grep -Eq "^REACHABLE +$BANNED +web +:8080 -> bp-web" "$OUT/docker-user-8080.banprobe.txt"
grep -q "already has the container port 80" "$OUT/docker-user-8080.banprobe.txt"
expect_curl ok

log "4. chain = DOCKER-USER, port = 80"
jail DOCKER-USER 80
probe docker-user-80 0
grep -Eq "^BLOCKED +$BANNED +web +:8080 -> bp-web" "$OUT/docker-user-80.banprobe.txt"
expect_curl blocked

log "5. unban"
sudo fail2ban-client set web unbanip "$BANNED" > /dev/null
probe unbanned 0
grep -q "^no banned IPs" "$OUT/unbanned.banprobe.txt"
expect_curl ok

log "all verdicts matched real connections"
