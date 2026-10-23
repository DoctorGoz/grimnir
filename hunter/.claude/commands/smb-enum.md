Run SMB/Windows enumeration suite against $ARGUMENTS

## Steps
1. SMB signing check: netexec smb $ARGUMENTS --gen-relay-list reports/raw/relay-targets.txt
2. Share enumeration:
   - netexec smb $ARGUMENTS --shares
   - smbclient -L //$ARGUMENTS -N (null session)
   - Test read/write access on each share
3. User enumeration:
   - netexec smb $ARGUMENTS --users
   - netexec smb $ARGUMENTS --rid-brute
   - enum4linux -U $ARGUMENTS
4. Group enumeration:
   - netexec smb $ARGUMENTS --groups
   - enum4linux -G $ARGUMENTS
5. Password policy:
   - netexec smb $ARGUMENTS --pass-pol
   - enum4linux -P $ARGUMENTS
6. Full enum4linux sweep: enum4linux -a $ARGUMENTS > reports/raw/enum4linux-full.txt
7. Check for known SMB vulnerabilities:
   - nmap --script smb-vuln* -p 445 $ARGUMENTS
   - EternalBlue (MS17-010), SMBGhost (CVE-2020-0796), PrintNightmare
8. Compile results into reports/smb-enum-summary.md

Report shares accessible, users/groups found, password policy, SMB signing status, and any SMB vulnerabilities.
