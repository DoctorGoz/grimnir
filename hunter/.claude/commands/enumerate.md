Run deep service enumeration against $ARGUMENTS

## Steps
1. Parse discovery results to identify services and ports on target
2. For each service type, run targeted enumeration:

### HTTP/HTTPS (80, 443, 8080, 8443, etc.)
- whatweb $ARGUMENTS:PORT
- nikto -h $ARGUMENTS:PORT -o reports/raw/nikto-PORT.txt
- nmap --script http-enum,http-headers,http-methods -p PORT $ARGUMENTS

### SMB (139, 445)
- bash hunter/scripts/smb-enum.sh $ARGUMENTS
- enum4linux -a $ARGUMENTS > reports/raw/enum4linux.txt
- netexec smb $ARGUMENTS --shares

### SSH (22)
- nmap --script ssh2-enum-algos,ssh-auth-methods -p 22 $ARGUMENTS

### DNS (53)
- dnsrecon -d $ARGUMENTS -t axfr
- dnsx -d $ARGUMENTS -w wordlists -o reports/raw/dns-brute.txt

### SNMP (161)
- nmap --script snmp-brute,snmp-info -p 161 $ARGUMENTS
- Test community strings from hunter/wordlists/snmp-communities.txt

### Databases (3306, 5432, 1433, 27017, 6379)
- nmap --script *-info -p PORT $ARGUMENTS
- Check for unauthenticated access

3. Compile all enumeration results into reports/enumeration-summary.md

Report services found, versions, interesting findings, and recommended attack vectors.
