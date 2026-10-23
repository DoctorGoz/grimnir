---
name: rag-poisoning
description: RAG system poisoning and retrieval manipulation testing. Covers document injection, embedding manipulation, chunk boundary attacks, and knowledge base corruption.
allowed-tools: Read, Grep, Glob, Bash
---

# RAG Poisoning Testing Skill

## When to Use
- Testing RAG (Retrieval-Augmented Generation) applications
- OWASP LLM01 (indirect injection via documents), LLM04 (data poisoning), LLM08 (vector/embedding)
- When the target system ingests external documents or data

## Attack Vectors

### Document Injection
1. Upload documents containing hidden prompt injection payloads
2. Embed instructions in document metadata (PDF title, author, keywords)
3. Use invisible text (white on white, font-size: 0, CSS display:none)
4. Place payloads in headers, footers, or annotations

### Embedding Space Attacks (LLM08)
1. Craft documents that are semantically similar to target queries
2. Test if poisoned documents are retrieved for unrelated queries
3. Check embedding distance thresholds (can distant documents be retrieved?)
4. Test for embedding collision — documents that map to same vector space

### Chunk Boundary Exploitation
1. Place injection payloads at chunk boundaries where they span two chunks
2. Test if chunking preserves or breaks injection payloads
3. Exploit overlap regions in sliding-window chunking
4. Place different instructions in adjacent chunks

### Cross-Tenant Poisoning
1. In multi-tenant RAG: upload documents that affect other tenants
2. Test namespace isolation in vector databases
3. Check if document access controls are enforced at retrieval time

### Retrieval Manipulation
1. SEO-style optimization for vector search — craft documents that rank highly
2. Flood the knowledge base to dilute legitimate documents
3. Test if the system validates document source/authenticity

## Output
Attack vector, poisoned document details, retrieval impact, cross-contamination evidence, severity.

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** Show the poisoned doc altered a later answer/citation; control = unpoisoned corpus returns the correct answer.
- **Automated confirm — `llm-confirm.py --mode injection`:** after poisoning the corpus, confirm the injected instruction actually RAN downstream — a unique marker in the RAG answer that the unpoisoned-control corpus does not produce.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent artemis \
  --id ART-NNN --state confirmed --method manual-repro \
  --negative-control "<what you proved, and the control result>" --by artemis
```
