Run vulnerability scanning pipeline against $ARGUMENTS

## Steps
1. Parse discovery/enumeration results to build target list with ports
2. Nuclei network scan: nuclei -u $ARGUMENTS -t network/ -severity critical,high,medium -o reports/raw/nuclei-network.txt
3. Nuclei CVE scan: nuclei -u $ARGUMENTS -t cves/ -severity critical,high -o reports/raw/nuclei-cves.txt
4. Nmap vuln scripts: nmap --script vuln -p OPEN_PORTS $ARGUMENTS -oA reports/raw/nmap-vuln
5. Nmap exploit scripts: nmap --script exploit -p OPEN_PORTS $ARGUMENTS -oA reports/raw/nmap-exploit
6. For each identified service version, search for known exploits:
   - searchsploit SERVICE VERSION
   - Log results to reports/raw/searchsploit-results.txt
7. TLS/SSL analysis on all HTTPS/TLS ports:
   - openssl s_client -connect $ARGUMENTS:PORT
   - nmap --script ssl-enum-ciphers,ssl-cert -p PORT $ARGUMENTS
8. Cross-reference findings with CVE databases
9. Compile validated vulnerabilities into reports/vuln-scan-summary.md

Report confirmed vulnerabilities by severity, CVE references, and recommended exploitation targets.
