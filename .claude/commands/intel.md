Query and manage the intel feed for the current engagement

## Steps

1. Identify the project directory `$PROJECT_DIR` for the current or specified engagement
2. Check if `$PROJECT_DIR/intel.jsonl` exists — if not, report "No intel feed found"

3. **Default (no arguments)** — show intel summary:
   ```bash
   bash scripts/intel.sh summary --project-dir "$PROJECT_DIR"
   ```

4. **With `route` argument** — show items needing routing:
   ```bash
   bash scripts/intel.sh route --project-dir "$PROJECT_DIR"
   ```

5. **With `route <agent>` argument** — show items for specific agent:
   ```bash
   bash scripts/intel.sh route --project-dir "$PROJECT_DIR" --for-agent specter
   ```

6. **With `query` arguments** — filter the feed:
   ```bash
   bash scripts/intel.sh query --project-dir "$PROJECT_DIR" --type endpoint --unprocessed
   bash scripts/intel.sh query --project-dir "$PROJECT_DIR" --agent hunter --format json
   bash scripts/intel.sh query --project-dir "$PROJECT_DIR" --tag high-value
   ```

## Usage Examples
- `/intel` — summary of all intel for current engagement
- `/intel route` — show unprocessed items needing agent routing
- `/intel route specter` — show items tagged needs-specter
- `/intel query --type endpoint --unprocessed` — find unprocessed endpoints
