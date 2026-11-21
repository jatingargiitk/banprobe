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
