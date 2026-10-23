# Tool Quick Reference

## Reconnaissance
| Tool | Purpose | Key Command |
|------|---------|-------------|
| katana | Web crawl + JS | katana -u URL -d 5 -jc -f qurl |
| kiterunner | API route brute | kr scan URL -A=apiroutes-210328:20000 |
| ffuf | Fuzzing | ffuf -w list -u URL/FUZZ -mc all -fc 404 |
| arjun | Param discovery | arjun -u URL -m JSON |
| linkfinder | JS endpoints | python3 linkfinder.py -i JS_URL -o cli |
| secretfinder | JS secrets | python3 SecretFinder.py -i URL -e -o cli |
| getJS | JS file extract | getJS -url URL --complete --resolve |
| wafw00f | WAF detection | wafw00f -a URL |

## Scanning & Exploitation
| Tool | Purpose | Key Command |
|------|---------|-------------|
| nuclei | Template scan | nuclei -u URL -tags api -s critical,high |
| sqlmap | SQL injection | sqlmap -u URL --batch --level=5 --risk=3 |
| graphqlmap | GraphQL attacks | graphqlmap -u URL/graphql |
| grpcurl | gRPC testing | grpcurl -plaintext HOST:PORT list |
| jwt_tool | JWT attacks | python3 jwt_tool.py TOKEN -X a |

## Proxy & Interception
| Tool | Purpose | Key Command |
|------|---------|-------------|
| caido-cli | Web proxy | caido-cli --listen 0.0.0.0:8080 |
| mitmproxy | Scriptable proxy | mitmproxy -p 8080 |

## WAF Bypass
| Tool | Purpose | Key Command |
|------|---------|-------------|
| wafninja | Payload test | wafninja fuzz -u URL -t xss |
| sqlmap tamper | SQLi bypass | --tamper=space2comment,randomcase |

## Output Formats
| Tool | JSON | Pipe stdin |
|------|------|-----------|
| nuclei | -json | Yes (stdin targets) |
| ffuf | -of json | Yes (stdout URLs) |
| katana | -j | Yes (stdout) |
| kiterunner | No | Yes (stdout) |
| sqlmap | Partial | -r file input |
| wafw00f | -f json | Yes |

## Common Pipelines
katana -u URL -jc -silent | sort -u | nuclei -tags api -s critical,high
katana -u URL -jc -silent | grep '.js' | while read u; do python3 linkfinder.py -i "$u" -o cli; done
subfinder -d DOMAIN | httpx -silent | nuclei -as
ffuf -w list -u URL/FUZZ -mc 200 -o endpoints.json -of json
