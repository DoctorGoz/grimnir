Run a quick vulnerability scan against $ARGUMENTS using nuclei

## Steps
1. Run nuclei with API-focused templates:
   nuclei -u $ARGUMENTS -tags api,cve -s critical,high -o reports/raw/nuclei-results.json -json
2. If auth token available, include it:
   nuclei -u $ARGUMENTS -tags api -H "Authorization: Bearer TOKEN" -s critical,high -json
3. Auto-template selection based on fingerprinting:
   nuclei -u $ARGUMENTS -as -o reports/raw/nuclei-auto-results.json -json
4. Summarize findings by severity and type
5. For critical/high findings, provide initial validation steps

Rate limit to avoid disruption: nuclei -u $ARGUMENTS -rl 10 -c 5
