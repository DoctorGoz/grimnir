---
name: database-exposure
description: Database exposure testing — exposed databases, default credentials, unauthenticated access. Maps to Hunter NET06.
allowed-tools: Read, Grep, Glob, Bash
---

# Database Exposure Skill

## When to Use
- When database ports are discovered (3306, 5432, 1433, 27017, 6379, 9200, etc.)
- When testing for unauthenticated or default-credential access to databases

## Tool Chain

### MySQL (Port 3306)
    nmap --script mysql-info,mysql-enum -p 3306 TARGET
    # Default creds: root:(empty), root:root, root:mysql
    hydra -l root -P hunter/wordlists/common-passwords.txt TARGET mysql -t 4

### PostgreSQL (Port 5432)
    nmap --script pgsql-brute -p 5432 TARGET
    # Default creds: postgres:postgres, postgres:(empty)
    netexec ssh TARGET -u postgres -p postgres

### MSSQL (Port 1433)
    nmap --script ms-sql-info,ms-sql-ntlm-info -p 1433 TARGET
    netexec mssql TARGET -u sa -p ''
    netexec mssql TARGET -u sa -p 'sa'
    # If access gained:
    netexec mssql TARGET -u USER -p PASS --query "SELECT name FROM master.dbo.sysdatabases"

### MongoDB (Port 27017)
    nmap --script mongodb-info,mongodb-databases -p 27017 TARGET
    # Unauthenticated access test:
    ncat TARGET 27017 <<< '{"listDatabases": 1}'

### Redis (Port 6379)
    nmap --script redis-info -p 6379 TARGET
    # Unauthenticated access:
    ncat TARGET 6379 <<< "INFO"
    ncat TARGET 6379 <<< "CONFIG GET *"

### Elasticsearch (Port 9200)
    curl -s http://TARGET:9200/
    curl -s http://TARGET:9200/_cat/indices
    curl -s http://TARGET:9200/_cluster/health

## Key Findings
- Unauthenticated database access (Critical)
- Default credentials accepted (Critical/High)
- Database exposed to external network (High)
- Sensitive data accessible (severity depends on data)
- Outdated database version with known CVEs

## Output
Document: database type, version, access level, data accessible, and credential used.

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** Show the DB is reachable AND returns real data unauthenticated; an open port/banner alone is validated, not confirmed.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent hunter \
  --id HUN-NNN --state confirmed --method manual-repro \
  --negative-control "<what you proved, and the control result>" --by hunter
```
