Run host discovery and port scanning against $ARGUMENTS

## Steps
1. Ping sweep / host discovery: nmap -sn $ARGUMENTS -oG reports/raw/hosts-alive.gnmap
2. Fast port scan (top 1000): nmap -sS -T4 --top-ports 1000 $ARGUMENTS -oA reports/raw/nmap-top1000
3. Full port scan if time permits: nmap -sS -p- -T4 $ARGUMENTS -oA reports/raw/nmap-allports
4. Service detection on open ports: nmap -sV -sC -p OPEN_PORTS $ARGUMENTS -oA reports/raw/nmap-services
5. OS fingerprinting: nmap -O $ARGUMENTS -oA reports/raw/nmap-os
6. UDP scan on common ports: nmap -sU --top-ports 50 -T4 $ARGUMENTS -oA reports/raw/nmap-udp
7. Parse results: compile host/port/service matrix into reports/discovery-summary.md

Report live hosts, total open ports, identified services, and recommended next steps (enumerate, vuln-scan, or cred-spray).
