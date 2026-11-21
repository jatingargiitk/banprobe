# banprobe

Check whether IPs that fail2ban has banned can still reach your Docker-published ports.

fail2ban says an IP is banned, and the service in the container keeps answering it. Docker DNATs a published port in `nat PREROUTING`, so the connection is forwarded to the container through `FORWARD` (`DOCKER-USER`, `DOCKER`), and never passes `INPUT`, the chain most fail2ban ban actions hook by default. `banprobe` reads the ruleset and tells you, for every banned IP and every published port, whether a new TCP connection would be **BLOCKED**, **REACHABLE** or **INCONCLUSIVE**, which rule decides it, and what to change.

It walks one new inbound TCP connection through the ruleset the way the kernel would: `raw`, `mangle` and `nat` `PREROUTING` (including Docker's `DNAT`), then `INPUT` or `FORWARD` depending on where the connection was sent, following jumps, gotos and `RETURN`s through user chains (`f2b-*`, `DOCKER-USER`, `DOCKER-FORWARD`, `DOCKER`, `DOCKER-ISOLATION-*`, ...) to a verdict or a chain policy. A rule it can't evaluate stops the walk with INCONCLUSIVE and the exact rule text; it never guesses.

Python 3.9+, no dependencies. It only reads: live, it runs `iptables-save`, `ipset save`, `fail2ban-client status`, `docker ps` and `ip route get`, and changes nothing.

## Install

```console
pip install git+https://github.com/jatingargiitk/banprobe
```

## Use

On the server (reading the ruleset needs root):

```console
sudo banprobe
```

Or save the state on the server and check it anywhere:

```console
sudo iptables-save > iptables-save.txt
for j in $(sudo fail2ban-client status | sed -n 's/.*Jail list:\s*//p' | tr -d ','); do sudo fail2ban-client status "$j"; done > fail2ban.txt
docker ps --format '{{.Names}}\t{{.Ports}}' > docker-ps.txt
sudo ipset save > ipset.txt      # only if your banaction uses ipset

banprobe --iptables-save iptables-save.txt --fail2ban fail2ban.txt --docker-ps docker-ps.txt [--ipset-save ipset.txt]
```

If `iptables-save` warns `iptables-legacy tables present`, save `sudo iptables-legacy-save` too and pass both files (`--iptables-save nft.txt --iptables-save legacy.txt`); a connection has to get past both. Live, banprobe does this itself.

## Example

`examples/server` is a saved state from a host running a WordPress compose project: `blog-wordpress-1` published as `:8080`, `blog-adminer-1` as `:8081`, and two fail2ban jails with the default `iptables-multiport` ban action. The `wordpress` jail has `port = 8080`, the port people open in the browser. The parts of `iptables-save.txt` that matter:

```
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
...
-A INPUT -p tcp -m multiport --dports 8080 -j f2b-wordpress
-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-FORWARD
-A DOCKER -d 172.18.0.2/32 ! -i br-6b1e0c2f4a77 -o br-6b1e0c2f4a77 -p tcp -m tcp --dport 80 -j ACCEPT
...
-A f2b-wordpress -s 192.0.2.44/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-wordpress -s 203.0.113.7/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-wordpress -j RETURN
COMMIT
*nat
...
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
...
-A DOCKER ! -i br-6b1e0c2f4a77 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.18.0.2:80
-A DOCKER ! -i br-6b1e0c2f4a77 -p tcp -m tcp --dport 8081 -j DNAT --to-destination 172.18.0.3:8080
```

```console
$ cd examples/server
$ banprobe --iptables-save iptables-save.txt --fail2ban fail2ban.txt --docker-ps docker-ps.txt
new TCP connections from 3 banned IP(s) to 2 published port(s), arriving on an unknown interface, sent to any host address

REACHABLE    192.0.2.44      wordpress  :8080 -> blog-wordpress-1 172.18.0.2:80
  path: nat PREROUTING -> DOCKER: DNAT to 172.18.0.2:80 (iptables-save.txt:62)
        filter FORWARD -> DOCKER-USER -> DOCKER-FORWARD -> DOCKER-CT -> DOCKER-ISOLATION-STAGE-1 -> DOCKER-BRIDGE -> DOCKER: ACCEPT (iptables-save.txt:27)
  why:  f2b-wordpress is hooked from INPUT (iptables-save.txt:23), but :8080 is DNATed to 172.18.0.2:80, so the connection goes through FORWARD and never passes INPUT
  fix:  set `chain = DOCKER-USER` for [wordpress] in jail.local; in DOCKER-USER the port is already the container port, so use `port = 80` (or match the host port with `-m conntrack --ctorigdstport 8080`)
REACHABLE    203.0.113.7     wordpress  :8080 -> blog-wordpress-1 172.18.0.2:80
  path: nat PREROUTING -> DOCKER: DNAT to 172.18.0.2:80 (iptables-save.txt:62)
        filter FORWARD -> DOCKER-USER -> DOCKER-FORWARD -> DOCKER-CT -> DOCKER-ISOLATION-STAGE-1 -> DOCKER-BRIDGE -> DOCKER: ACCEPT (iptables-save.txt:27)
  why:  f2b-wordpress is hooked from INPUT (iptables-save.txt:23), but :8080 is DNATed to 172.18.0.2:80, so the connection goes through FORWARD and never passes INPUT
  fix:  set `chain = DOCKER-USER` for [wordpress] in jail.local; in DOCKER-USER the port is already the container port, so use `port = 80` (or match the host port with `-m conntrack --ctorigdstport 8080`)
skipped      198.51.100.23   sshd       :8080: jail sshd only covers port(s) 22
skipped      198.51.100.23   sshd       :8081: jail sshd only covers port(s) 22
skipped      192.0.2.44      wordpress  :8081: jail wordpress only covers port(s) 8080
skipped      203.0.113.7     wordpress  :8081: jail wordpress only covers port(s) 8080

2 checked: 2 reachable, 0 blocked, 0 inconclusive; 4 skipped (port outside the jail's ports)
$ echo $?
1
```

Both banned IPs still get WordPress. A jail only counts for the ports it covers, so the `sshd` ban isn't checked against the web ports, and the `wordpress` jail isn't checked against Adminer's `:8081`.

`examples/docker-user` is the same host after moving the jail to `DOCKER-USER` and keeping `port = 8080`:

```console
$ cd ../docker-user
$ banprobe --iptables-save iptables-save.txt --fail2ban fail2ban.txt --docker-ps docker-ps.txt
new TCP connections from 3 banned IP(s) to 2 published port(s), arriving on an unknown interface, sent to any host address

REACHABLE    192.0.2.44      wordpress  :8080 -> blog-wordpress-1 172.18.0.2:80
  path: nat PREROUTING -> DOCKER: DNAT to 172.18.0.2:80 (iptables-save.txt:62)
        filter FORWARD -> DOCKER-USER -> DOCKER-FORWARD -> DOCKER-CT -> DOCKER-ISOLATION-STAGE-1 -> DOCKER-BRIDGE -> DOCKER: ACCEPT (iptables-save.txt:26)
  why:  the f2b-wordpress hook at iptables-save.txt:43 matches port(s) 8080, but in DOCKER-USER this connection already has the container port 80 (host port 8080, DNATed to 172.18.0.2:80)
  fix:  use `port = 80` for [wordpress], or match the host port with `-m conntrack --ctorigdstport 8080`
BLOCKED      192.0.2.44      wordpress  :8081 -> blog-adminer-1 172.18.0.3:8080
  path: nat PREROUTING -> DOCKER: DNAT to 172.18.0.3:8080 (iptables-save.txt:63)
        filter FORWARD -> DOCKER-USER -> f2b-wordpress: REJECT (iptables-save.txt:46)
REACHABLE    203.0.113.7     wordpress  :8080 -> blog-wordpress-1 172.18.0.2:80
  path: nat PREROUTING -> DOCKER: DNAT to 172.18.0.2:80 (iptables-save.txt:62)
        filter FORWARD -> DOCKER-USER -> DOCKER-FORWARD -> DOCKER-CT -> DOCKER-ISOLATION-STAGE-1 -> DOCKER-BRIDGE -> DOCKER: ACCEPT (iptables-save.txt:26)
  why:  the f2b-wordpress hook at iptables-save.txt:43 matches port(s) 8080, but in DOCKER-USER this connection already has the container port 80 (host port 8080, DNATed to 172.18.0.2:80)
  fix:  use `port = 80` for [wordpress], or match the host port with `-m conntrack --ctorigdstport 8080`
BLOCKED      203.0.113.7     wordpress  :8081 -> blog-adminer-1 172.18.0.3:8080
  path: nat PREROUTING -> DOCKER: DNAT to 172.18.0.3:8080 (iptables-save.txt:63)
        filter FORWARD -> DOCKER-USER -> f2b-wordpress: REJECT (iptables-save.txt:47)
skipped      198.51.100.23   sshd       :8080: jail sshd only covers port(s) 22
skipped      198.51.100.23   sshd       :8081: jail sshd only covers port(s) 22

4 checked: 2 reachable, 2 blocked, 0 inconclusive; 2 skipped (port outside the jail's ports)
$ echo $?
1
```

In `DOCKER-USER` the connection has already been DNATed, so its destination port is the container's (`80`). The jail's `--dports 8080` misses WordPress and catches Adminer, whose container happens to listen on `8080`.

`examples/fixed` has `chain = DOCKER-USER` and `port = 80`:

```console
$ cd ../fixed
$ banprobe --iptables-save iptables-save.txt --fail2ban fail2ban.txt --docker-ps docker-ps.txt
new TCP connections from 3 banned IP(s) to 2 published port(s), arriving on an unknown interface, sent to any host address

BLOCKED      192.0.2.44      wordpress  :8080 -> blog-wordpress-1 172.18.0.2:80
  path: nat PREROUTING -> DOCKER: DNAT to 172.18.0.2:80 (iptables-save.txt:62)
        filter FORWARD -> DOCKER-USER -> f2b-wordpress: REJECT (iptables-save.txt:46)
BLOCKED      203.0.113.7     wordpress  :8080 -> blog-wordpress-1 172.18.0.2:80
  path: nat PREROUTING -> DOCKER: DNAT to 172.18.0.2:80 (iptables-save.txt:62)
        filter FORWARD -> DOCKER-USER -> f2b-wordpress: REJECT (iptables-save.txt:47)
skipped      198.51.100.23   sshd       :8080: jail sshd only covers port(s) 22
skipped      198.51.100.23   sshd       :8081: jail sshd only covers port(s) 22
skipped      192.0.2.44      wordpress  :8081: jail wordpress only covers port(s) 80
skipped      203.0.113.7     wordpress  :8081: jail wordpress only covers port(s) 80

2 checked: 0 reachable, 2 blocked, 0 inconclusive; 4 skipped (port outside the jail's ports)
$ echo $?
0
```

The jail config for that:

```ini
[wordpress]
enabled   = true
port      = 80
chain     = DOCKER-USER
banaction = iptables-multiport
```

To ban on the host port instead, a ban action can match `-m conntrack --ctorigdstport 8080` in `DOCKER-USER`; banprobe evaluates that match too.

## Options

| Option | |
|:--|:--|
| `--iptables-save FILE` | saved `iptables-save` output; repeat for nft + legacy. Without it, banprobe reads the live host |
| `--ipset-save FILE` | `ipset save` output, for ban actions that use `-m set --match-set` |
| `--fail2ban FILE` | `fail2ban-client status <jail>` output for one or more jails |
| `--docker-ps FILE` | `docker ps --format '{{.Names}}\t{{.Ports}}'` output |
| `--banned IPS` | check these IPs (comma or space separated) instead of, or on top of, fail2ban's list |
| `--ip IP` | check only this source IP |
| `--port PORT` | check this host TCP port (repeatable) instead of the published ports |
| `--host-ip IP` | the host address clients connect to, for rules with `-d` |
| `--in-iface NAME` | the interface the traffic arrives on, for rules with `-i` |
| `--json` | print JSON: per IP and port the verdict, DNAT target, route, every chain walked, the deciding rule (file, line, text), why and fix |

With saved files and no `--docker-ps` or `--port`, the ports come from Docker's `DNAT` rules in the `nat` table. Ports published on `127.0.0.1` only are skipped, since other hosts can't reach them. Without `--in-iface`, an unknown interface is assumed not to be `lo`, `docker0`, `br-*` or `veth*`; any other `-i` match makes the verdict INCONCLUSIVE. Live, banprobe takes the interface and host address from `ip route get <banned IP>`.

## Exit codes

| Code | Meaning |
|:--|:--|
| 0 | every checked connection is blocked (or nothing is banned) |
| 1 | at least one banned IP can open a connection to a published port |
| 2 | nothing reachable, but at least one verdict is INCONCLUSIVE |
| 3 | usage or input error |

That makes it usable from cron or a CI job that checks a server's saved state, e.g. `sudo banprobe > /tmp/banprobe.txt || mail -s "banprobe exit $?" root < /tmp/banprobe.txt`.

## What it evaluates

- tables `raw`, `mangle`, `nat` (`PREROUTING`: `DNAT`, `REDIRECT`) and `filter` (`INPUT`, `FORWARD`), chain policies, jumps, `-g` gotos, `RETURN`
- `-s`, `-d` (CIDR, `!`), `-p`, `-i`, `-o` (with `+` wildcards), `--dport`, `--sport`, `--syn`, `--tcp-flags`, `-m multiport`, `-m conntrack` (`--ctstate`, `--ctorigdstport`, `--ctorigdst`, `--ctorigsrc`, `--ctdir`), `-m state`, `-m addrtype`, `-m set` with members from `ipset save` (`hash:ip`, `hash:net`), `-m iprange`, `-m comment`
- targets `ACCEPT`, `DROP`, `REJECT`, `RETURN`, user chains; logging and marking targets (`LOG`, `NFLOG`, `MARK`, `CONNMARK`, ...) are passed over
- the output interface after a DNAT, from Docker's `-s <subnet> ! -o <bridge> -j MASQUERADE` rules
- the client's source port as Linux's default ephemeral range, 32768-60999: `--sport 1024:65535` matches, `--sport 40000:50000` is INCONCLUSIVE

Anything else (`-m limit`, `-m recent`, `-m mark`, unknown targets, rules it can't parse) is INCONCLUSIVE if its verdict could matter.

## Limits

It is a simulation of the ruleset you give it, not a security proof.

- IPv4 and TCP only. IPv6 bans and UDP ports are listed as notes and not checked.
- Rulesets as `iptables-save` prints them (iptables-legacy and iptables-nft). Native nftables rulesets (`nft list ruleset`, fail2ban's `nftables` ban actions, Docker's nftables firewall backend) are not read.
- It checks the IP fail2ban banned as the packet's source. Behind a reverse proxy, load balancer or CDN, the connection comes from the proxy and the ban has to be enforced there.
- Docker Swarm ingress, rootless Docker, and ufw / ufw-docker setups beyond what the evaluated matches cover are not modelled; their rules show up as INCONCLUSIVE rather than being guessed.
- Connection tracking state is assumed `NEW`; it doesn't model existing connections, which a new ban doesn't cut either.

## Tested against real packets

Besides the unit tests on saved rulesets (including ones captured from real hosts), CI runs `tests/e2e/real_packets.sh` on an Ubuntu 24.04 runner: it starts nginx published as `:8080`, puts a client with address `10.200.0.2` in a network namespace, bans it with fail2ban, and for each of the three jail setups above checks banprobe's live verdict against what a real `curl` from that address does (REACHABLE and the page loads; BLOCKED and the connection is refused). The script changes the firewall and fail2ban config; it is meant for throwaway machines.

## License

MIT. Not affiliated with fail2ban or Docker.
