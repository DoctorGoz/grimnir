# Project Manager Agent — ARTEMIS Integration Guide

## Overview

This document describes how a "Project Manager" orchestrator agent can delegate GenAI security testing tasks to the ARTEMIS agent (GenAI Red Teaming & Penetration Testing Agent).

---

## Handoff Protocol

### Initiating an Engagement

Send the following JSON payload to ARTEMIS to start an engagement:

```json
{
  "action": "initiate_engagement",
  "engagement_id": "ENG-2025-XXX",
  "target": {
    "type": "rag_application | chatbot | agent | multi_agent | foundation_model | fine_tuned_model",
    "name": "Target System Name",
    "endpoint": "https://target-system.example.com/api/chat",
    "description": "Customer-facing RAG chatbot for insurance claims assistance",
    "technology": {
      "model_provider": "OpenAI",
      "model_version": "gpt-4o",
      "framework": "LangChain",
      "vector_db": "Pinecone",
      "deployment": "AWS ECS"
    }
  },
  "scope": {
    "in_scope": [
      "Chat API endpoint",
      "RAG knowledge base",
      "System prompt security",
      "Output handling"
    ],
    "out_of_scope": [
      "Underlying cloud infrastructure",
      "Third-party model API security"
    ],
    "priority_categories": ["LLM01", "LLM02", "LLM07", "LLM08"],
    "max_test_categories": 10
  },
  "constraints": {
    "authorization": "confirmed",
    "environment": "staging",
    "rate_limit": "10 requests per minute",
    "testing_window": "09:00-17:00 EST weekdays",
    "data_handling": "No real PII — redact all findings"
  },
  "reporting": {
    "report_to": "pm-agent",
    "format": "markdown",
    "interim_updates": true,
    "update_frequency": "after each category completion",
    "deadline": "2025-03-15"
  }
}
```

### Receiving Status Updates

ARTEMIS will send periodic status updates in this format:

```json
{
  "agent": "artemis",
  "engagement_id": "ENG-2025-XXX",
  "timestamp": "2025-03-10T14:30:00Z",
  "phase": "assessment",
  "progress": 0.45,
  "categories_completed": ["LLM01", "LLM07"],
  "categories_in_progress": ["LLM02"],
  "categories_remaining": ["LLM08"],
  "findings": {
    "total": 7,
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 1,
    "informational": 0
  },
  "critical_alert": {
    "finding_id": "FINDING-003",
    "title": "Indirect Prompt Injection via RAG Documents Enables Data Exfiltration",
    "category": "LLM01",
    "description": "Crafted documents in the RAG knowledge base can override system instructions and exfiltrate user conversation data via the chat interface."
  },
  "status": "in_progress",
  "next_action": "Completing LLM02 sensitive information disclosure assessment",
  "estimated_completion": "2025-03-12T17:00:00Z",
  "blockers": []
}
```

### Requesting Specific Actions

```json
// Request assessment of specific category
{
  "action": "assess_category",
  "engagement_id": "ENG-2025-XXX",
  "category": "LLM01",
  "depth": "comprehensive",
  "max_payloads": 50
}

// Request findings summary
{
  "action": "get_findings_summary",
  "engagement_id": "ENG-2025-XXX",
  "min_severity": "Medium"
}

// Request final report generation
{
  "action": "generate_report",
  "engagement_id": "ENG-2025-XXX",
  "format": "markdown",
  "include_executive_summary": true,
  "include_remediation_roadmap": true
}

// Pause or stop testing
{
  "action": "pause_engagement",
  "engagement_id": "ENG-2025-XXX",
  "reason": "Target system maintenance window"
}
```

---

## Workflow Integration Patterns

### Pattern 1: Full Engagement Delegation
The PM agent delegates the entire engagement. ARTEMIS handles scoping, recon, assessment, and reporting autonomously, sending status updates at defined intervals.

```
PM Agent                          ARTEMIS
   │                                 │
   │──── initiate_engagement ───────▶│
   │                                 │──── scope ────▶
   │◀──── status: scoping ──────────│
   │                                 │──── recon ────▶
   │◀──── status: recon_complete ───│
   │                                 │──── assess ──▶
   │◀──── status: finding_alert ────│  (critical finding)
   │◀──── status: progress_update ──│
   │                                 │──── exploit ──▶
   │◀──── status: assessment_done ──│
   │                                 │──── report ──▶
   │◀──── final_report ────────────│
   │                                 │
```

### Pattern 2: Category-by-Category
The PM agent controls which categories to test and in what order, useful when integrating with a broader pentest workflow.

```
PM Agent                          ARTEMIS
   │                                 │
   │──── assess LLM01 ─────────────▶│
   │◀──── LLM01 findings ──────────│
   │                                 │
   │──── assess LLM07 ─────────────▶│  (PM decides next category)
   │◀──── LLM07 findings ──────────│
   │                                 │
   │──── generate_report ──────────▶│
   │◀──── report ──────────────────│
```

### Pattern 3: Triage and Escalate
ARTEMIS runs a quick scan across all categories, reports initial findings, and the PM agent decides which areas warrant deeper investigation.

```
PM Agent                          ARTEMIS
   │                                 │
   │──── quick_scan all ───────────▶│
   │◀──── initial_findings ────────│
   │                                 │
   │  (PM triages findings)         │
   │                                 │
   │──── deep_dive LLM01 ─────────▶│  (PM escalates critical areas)
   │◀──── detailed_findings ───────│
   │                                 │
   │──── generate_report ──────────▶│
   │◀──── report ──────────────────│
```

---

## Error Handling

ARTEMIS will report errors in this format:

```json
{
  "agent": "artemis",
  "engagement_id": "ENG-2025-XXX",
  "status": "error",
  "error": {
    "type": "access_denied | rate_limited | target_unavailable | scope_violation",
    "message": "Target API returned 403 — test credentials may have expired",
    "category": "LLM02",
    "test_id": "T-LLM02-03",
    "recoverable": true,
    "suggested_action": "Refresh API credentials and retry"
  }
}
```

The PM agent should handle errors by:
1. **access_denied**: Verify credentials and re-authorize
2. **rate_limited**: Adjust testing pace or wait
3. **target_unavailable**: Pause and retry later
4. **scope_violation**: Review and clarify scope boundaries
