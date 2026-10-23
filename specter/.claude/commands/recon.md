Run a full API reconnaissance pipeline against $ARGUMENTS

## Steps
1. Check WAF: wafw00f -a $ARGUMENTS -o reports/raw/waf-results.json -f json
2. Crawl with JS parsing: katana -u $ARGUMENTS -d 5 -jc -f qurl -silent -o reports/raw/endpoints.txt
3. Extract JS files: katana -u $ARGUMENTS -d 3 -jc -silent | grep -iE '\.js' | sort -u > reports/raw/js_files.txt
4. Analyze JS for endpoints with linkfinder, save to reports/raw/js_endpoints.txt
5. Analyze JS for secrets with SecretFinder, save to reports/raw/secrets.txt
6. API route brute-force: kr scan $ARGUMENTS -A=apiroutes-210328:20000 -x 5 -j 100 --fail-status-codes 400,401,404,403,501,502,426,411
7. Endpoint fuzzing: ffuf -w wordlists/api-endpoints.txt -u $ARGUMENTS/FUZZ -mc all -fc 404 -o reports/raw/ffuf-results.json -of json
8. Merge all discovered endpoints into reports/raw/all-endpoints.txt
9. Parameter discovery: arjun -i reports/raw/all-endpoints.txt -m JSON -oJ reports/raw/params.json -t 5
10. Check for exposed API docs (/swagger.json, /openapi.json, /api-docs, /graphql)
11. Compile attack surface map to reports/attack-surface-map.md

Report WAF results, total endpoints found, JS secrets, and recommended next steps.
