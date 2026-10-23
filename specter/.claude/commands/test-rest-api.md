# REST API Security Test

Test REST API endpoints with schema-driven and manual methodology.

## Usage
/test-rest-api $ARGUMENTS

## Behavior

Parse $ARGUMENTS for:
- Target URL (required)
- `--spec <url>` - URL to OpenAPI/Swagger spec (optional, will auto-discover if not provided)
- `--token <token>` - Authorization bearer token
- `--token-b <token>` - Second user token for BOLA testing
- `--phase <phase>` - Specific phase: discover|schema|methods|content-type|versioning|mass-assignment|full
- `--proxy <url>` - Route traffic through proxy (e.g., http://127.0.0.1:8080)
- `--rate <n>` - Max requests per second (default: 10)

## Execution Flow

### Phase: discover (default first step)
1. Attempt to locate OpenAPI/Swagger spec at common paths using openapi-paths.txt wordlist
2. Crawl target with katana for JS-based endpoint discovery
3. Run kiterunner for API-aware route brute-forcing
4. Run arjun for hidden parameter discovery on found endpoints
5. Output discovered endpoints to reports/rest-api/endpoints.txt

### Phase: schema (if spec found or provided)
1. Download and parse OpenAPI/Swagger specification
2. Extract full endpoint inventory with methods and parameters
3. Identify BOLA candidates (endpoints with path parameters containing {id}/{uuid})
4. Identify admin/internal endpoints by path keywords
5. Find endpoints without security requirements in the spec
6. Identify deprecated endpoints still accessible
7. Extract readOnly properties as mass assignment targets
8. Generate BOLA, BFLA, and input validation test matrices
9. Save analysis to reports/rest-api/spec-analysis.json

### Phase: methods
1. For each discovered endpoint, enumerate all HTTP methods (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS/TRACE)
2. Test method override headers: X-HTTP-Method-Override, X-Method-Override, X-HTTP-Method
3. Flag unexpected responses (DELETE returning 200, PUT without auth required)
4. Save results to reports/rest-api/method-enum.md

### Phase: content-type
1. Test each endpoint with Content-Types from content-types.txt wordlist
2. Flag endpoints accepting XML (XXE potential) or text/plain (CORS bypass)
3. Test WAF bypass via content-type switching
4. If XML accepted, attempt basic XXE payloads
5. Save results to reports/rest-api/content-type-results.md

### Phase: versioning
1. Test path-based version variations using api-versions.txt wordlist
2. Test header-based versioning (Api-Version, Accept with vendor media type)
3. Test query-parameter versioning (?version=, ?v=, ?api-version=)
4. Diff responses across versions to find security control gaps
5. Save results to reports/rest-api/version-diff.md

### Phase: mass-assignment
1. For each writable endpoint (POST/PUT/PATCH):
   a. GET the resource to enumerate all response fields
   b. Send PUT with privilege fields from mass-assignment-fields.txt
   c. Send PATCH with same privilege fields
   d. Test JSON Patch (RFC 6902) format with op:replace on role/admin fields
   e. Test JSON Merge Patch (RFC 7396) null deletion to disable security controls
   f. Compare before/after responses for any field changes
2. Save results to reports/rest-api/mass-assignment.md

### Phase: full (runs all phases sequentially)
1. Execute: discover -> schema -> methods -> content-type -> versioning -> mass-assignment
2. If --token-b provided, run BOLA testing across all discovered endpoints
3. Run response differential analysis (admin vs user vs unauth)
4. Compile all findings into reports/rest-api/findings.md

## Output
All output saved to reports/rest-api/ with timestamped filenames.
Final summary printed to stdout with finding counts by severity.
