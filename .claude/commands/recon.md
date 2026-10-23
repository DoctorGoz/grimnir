Run coordinated reconnaissance against $ARGUMENTS

Delegates ALL reconnaissance to HUGINN, the dedicated recon and intel agent.

## Routing

HUGINN handles all recon regardless of target type. It produces a unified asset map and pre-populates the intel feed for specialist agents.

1. **Delegate to HUGINN**:
   - Run: `bash huginn/scripts/recon-pipeline.sh TARGET --project-dir "$PROJECT_DIR" [--type TYPE]`
   - Then: `bash huginn/scripts/asset-map.sh --project-dir "$PROJECT_DIR" --target TARGET`
   - Types: `web`, `api`, `network`, `ai`, `mixed` (default)

2. **HUGINN performs layered recon**:
   - Passive: subdomain enum, DNS, certificate transparency, URL archives
   - Active: port scanning, service detection, HTTP probing
   - Fingerprinting: technologies, WAF, response headers, TLS certs
   - Discovery: crawling, JS analysis, endpoint mining, parameter discovery
   - Classification: build asset map, identify AI indicators, generate routing

3. **Output**:
   - Raw recon data → `$PROJECT_DIR/recon/`
   - Asset map → `$PROJECT_DIR/asset-map.json`
   - Intel feed → `$PROJECT_DIR/intel.jsonl` (pre-populated with classified discoveries)

4. **Post-recon**: Review the asset map and intel feed, then launch specialists:
   - `/api-audit TARGET` for Specter (pass relevant asset map sections)
   - `/genai-audit TARGET` for ARTEMIS (pass AI indicators)
   - `/net-audit TARGET` for Hunter (pass host/port data)
   - `/full-audit TARGET` for all applicable agents

## State Integration

```bash
bash scripts/state.sh update --project-dir "$PROJECT_DIR" --agent huginn \
  --phase recon --status in_progress --progress 0.1
```

**IMPORTANT**: Always pass `"project_dir"` to HUGINN. All output uses absolute paths.
