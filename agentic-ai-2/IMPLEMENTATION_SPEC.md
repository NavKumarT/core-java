# Implementation Spec — Dependency Vulnerability Reachability Agent

**Companion document to the Technical Design Proposal.** That document explains *why*; this document specifies *exactly how*, at a level a coding agent (Claude Code, Cursor, etc.) can execute task-by-task without needing to infer missing decisions. Where a decision isn't specified here, the agent should stop and ask rather than guess.

---

## 0. Repository Structure

```
reachability-agent/
├── pyproject.toml
├── .env.example
├── docker-compose.yml
├── Dockerfile.api
├── Dockerfile.worker
├── Dockerfile.sandbox            # network-isolated container for repo cloning/parsing
├── alembic/                      # DB migrations
│   └── versions/
├── app/
│   ├── main.py                   # FastAPI app entrypoint
│   ├── config.py                 # Pydantic Settings (Section 6)
│   ├── api/
│   │   ├── routes_scan.py        # POST /v1/scan, GET /v1/scan/{id}, SSE stream
│   │   └── deps.py                # FastAPI Depends() providers
│   ├── models/
│   │   ├── db.py                 # SQLAlchemy ORM models
│   │   └── schemas.py            # Pydantic request/response/report models (Section 3)
│   ├── ingestion/
│   │   ├── clone.py              # sandboxed shallow clone
│   │   ├── detect_ecosystem.py
│   │   ├── parse_python.py       # requirements.txt / pyproject.toml resolution
│   │   └── parse_js.py           # package.json + lockfile resolution
│   ├── vulndata/
│   │   ├── osv_client.py         # OSV.dev batch query + cache
│   │   └── registry_client.py    # npm / PyPI metadata client
│   ├── callgraph/
│   │   ├── build_python.py       # tree-sitter based Python call graph
│   │   ├── build_js.py           # tree-sitter based JS/TS call graph
│   │   └── graph_search.py       # path-finding from entry points to a symbol
│   ├── agents/
│   │   ├── state.py              # LangGraph state schema (Section 4)
│   │   ├── graph.py              # the compiled LangGraph StateGraph
│   │   ├── lead.py                # Lead/orchestrator node
│   │   ├── subagent_vuln_research.py
│   │   ├── subagent_callpath.py
│   │   ├── subagent_codeverify.py
│   │   └── prompts.py            # all system prompts, versioned (Section 5)
│   ├── worker/
│   │   └── run_scan.py           # background job entrypoint, called by the queue
│   └── observability/
│       └── otel_setup.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── eval/
│       ├── ground_truth.json     # the 15–20 CVE ground-truth set (Section 7)
│       └── run_eval.py
└── README.md
```

**Task 0.1** — Create this structure with empty `__init__.py` files and stub modules. Do not implement logic yet. Confirm the tree matches before proceeding.

---

## 1. Environment & Dependencies

**`pyproject.toml` — exact package list:**

```toml
[project]
name = "reachability-agent"
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.115",
    "uvicorn[standard]>=0.32",
    "pydantic>=2.9",
    "pydantic-settings>=2.6",
    "langgraph>=0.2",
    "langchain-core>=0.3",
    "langchain-anthropic>=0.3",
    "sqlalchemy[asyncio]>=2.0",
    "asyncpg>=0.30",
    "alembic>=1.14",
    "redis>=5.2",
    "httpx>=0.28",
    "tree-sitter>=0.23",
    "tree-sitter-python>=0.23",
    "tree-sitter-javascript>=0.23",
    "tree-sitter-typescript>=0.23",
    "docker>=7.1",                     # for sandboxed clone/parse container control
    "opentelemetry-api>=1.28",
    "opentelemetry-sdk>=1.28",
    "opentelemetry-instrumentation-fastapi>=0.49b0",
    "structlog>=24.4",
]

[project.optional-dependencies]
dev = ["pytest>=8.3", "pytest-asyncio>=0.24", "pytest-mock>=3.14", "ruff>=0.7"]
```

**`.env.example`:**

```
ANTHROPIC_API_KEY=
DATABASE_URL=postgresql+asyncpg://reachability:reachability@localhost:5432/reachability
REDIS_URL=redis://localhost:6379/0
GITHUB_TOKEN=                          # read-only PAT, repo scope only
OSV_API_BASE=https://api.osv.dev/v1
LEAD_MODEL=claude-opus-4-6             # strong model, reasoning-quality layer
SUBAGENT_MODEL=claude-sonnet-4-6       # cheaper model for narrower subagent tasks
MAX_SCAN_COST_USD=0.50
SCAN_TIMEOUT_SECONDS=300
LOG_LEVEL=INFO
```

**Task 1.1** — Implement `app/config.py` as a `pydantic_settings.BaseSettings` subclass loading every variable above, with no default for secrets (fail-fast on missing `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, `DATABASE_URL`).

**Task 1.2** — Write `docker-compose.yml` with three services: `api` (FastAPI, port 8000), `worker` (background scan processor), `postgres` (15+), `redis` (7+). The sandbox container (`Dockerfile.sandbox`) is spawned dynamically per-scan by the worker, not a long-running compose service — it must have `network_mode: none` or an equivalent egress-blocking network.

---

## 2. Database Schema

**Exact DDL** (implement via Alembic migration, not raw SQL in app code):

```sql
CREATE TABLE scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_url        TEXT NOT NULL,
    commit_sha      TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    error_message   TEXT,
    total_cost_usd  NUMERIC(10,4),
    UNIQUE (repo_url, commit_sha)                  -- idempotency: re-scan of same commit is a no-op read
);

CREATE TABLE findings (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id             UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    package_name        TEXT NOT NULL,
    package_version     TEXT NOT NULL,
    ecosystem           TEXT NOT NULL CHECK (ecosystem IN ('PyPI','npm')),
    osv_id              TEXT NOT NULL,
    severity            TEXT,
    vulnerable_symbol    TEXT,
    reachability_verdict TEXT NOT NULL CHECK (reachability_verdict IN ('reachable','not_reachable','indeterminate')),
    confidence          NUMERIC(3,2) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    justification        TEXT NOT NULL,
    evidence_call_path   JSONB,                     -- ordered list of {file, line, function}
    fixed_version        TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_scans_status ON scans(status);
```

**Task 2.1** — Generate the Alembic migration for the above. **Task 2.2** — Implement matching SQLAlchemy 2.0 async ORM models in `app/models/db.py` using `Mapped[...]` typed columns.

---

## 3. Data Models (Pydantic) — Exact Schemas

**`app/models/schemas.py`:**

```python
from pydantic import BaseModel, Field, HttpUrl
from typing import Literal
from datetime import datetime

class ScanRequest(BaseModel):
    repo_url: HttpUrl
    ref: str = Field(default="HEAD", description="branch, tag, or commit SHA to scan")

class ScanAccepted(BaseModel):
    scan_id: str
    status: Literal["queued"]
    status_url: str

class CallPathHop(BaseModel):
    file: str
    line: int
    function: str

class Finding(BaseModel):
    package_name: str
    package_version: str
    ecosystem: Literal["PyPI", "npm"]
    osv_id: str
    severity: str | None
    vulnerable_symbol: str | None
    reachability_verdict: Literal["reachable", "not_reachable", "indeterminate"]
    confidence: float = Field(ge=0.0, le=1.0)
    justification: str = Field(min_length=1, description="cited, evidence-grounded explanation")
    evidence_call_path: list[CallPathHop] = Field(default_factory=list)
    fixed_version: str | None

class ScanReport(BaseModel):
    scan_id: str
    repo_url: str
    commit_sha: str
    status: Literal["queued", "running", "completed", "failed"]
    created_at: datetime
    completed_at: datetime | None
    findings: list[Finding] = Field(default_factory=list)
    raw_finding_count: int = Field(description="total OSV findings before reachability filtering")
    reachable_finding_count: int
    total_cost_usd: float | None
```

**Task 3.1** — Implement exactly the above. **Task 3.2** — Write a unit test asserting `ScanReport.model_json_schema()` produces valid JSON Schema (this schema becomes the OpenAPI contract automatically via FastAPI — do not hand-write API docs separately).

---

## 4. LangGraph State & Graph Definition

**`app/agents/state.py`:**

```python
from typing import TypedDict, Annotated
import operator
from app.models.schemas import Finding

class ReachabilityState(TypedDict):
    scan_id: str
    repo_path: str                          # local sandboxed clone path
    ecosystem: str
    raw_osv_findings: list[dict]            # unfiltered OSV matches
    entry_points: list[str]                 # detected route handlers / CLI entrypoints / exports
    call_graph_ref: str                     # identifier for the built graph, not the graph itself (too large for state)
    current_finding_index: int
    verdicts: Annotated[list[Finding], operator.add]   # accumulates across the finding loop
    total_cost_usd: float
```

**`app/agents/graph.py` — exact node/edge wiring:**

```python
from langgraph.graph import StateGraph, END
from app.agents.state import ReachabilityState
from app.agents.lead import plan_and_dispatch, should_continue
from app.agents.subagent_vuln_research import vuln_research_node
from app.agents.subagent_callpath import callpath_node
from app.agents.subagent_codeverify import codeverify_node
from app.agents.lead import synthesize_verdict

def build_graph():
    g = StateGraph(ReachabilityState)
    g.add_node("plan", plan_and_dispatch)
    g.add_node("vuln_research", vuln_research_node)
    g.add_node("callpath", callpath_node)
    g.add_node("codeverify", codeverify_node)
    g.add_node("synthesize", synthesize_verdict)

    g.set_entry_point("plan")
    g.add_edge("plan", "vuln_research")
    g.add_edge("vuln_research", "callpath")
    g.add_edge("callpath", "codeverify")
    g.add_edge("codeverify", "synthesize")
    g.add_conditional_edges(
        "synthesize",
        should_continue,                     # returns True while findings remain unprocessed
        {True: "plan", False: END}
    )
    return g.compile()   # add a checkpointer here in Task 4.2 — do not ship without one
```

**Task 4.1** — Implement the above exactly; each subagent node function signature is `async def node(state: ReachabilityState) -> dict` returning only the keys it updates (never the full state), per the reducer pattern.

**Task 4.2** — Add a Postgres-backed checkpointer (`langgraph.checkpoint.postgres.AsyncPostgresSaver`) so a scan interrupted mid-run resumes from its last completed finding rather than restarting — this is a **hard requirement**, not optional, per the Technical Design Proposal's idempotency requirement (NFR: idempotency).

**Task 4.3** — `should_continue` must cap total findings processed at a configurable max (default 200) to prevent runaway loops on a pathological dependency tree — implement this as an explicit guard, not an assumption.

---

## 5. Subagent Prompts — Exact System Prompts

Store every prompt as a versioned constant in `app/agents/prompts.py`, never inline in node functions (this is what makes prompt changes auditable and testable independently of code changes).

```python
LEAD_SYSTEM_PROMPT = """You are the lead security analyst coordinating a vulnerability \
reachability assessment. For the current finding, decide how much analysis effort it needs:
- LOW effort (skip detailed subagent analysis): severity is LOW and the package is a leaf \
  dependency with no clear entry-point path.
- FULL effort (dispatch all three subagents): severity is HIGH/CRITICAL, OR the finding is \
  ambiguous, OR a previous pass returned 'indeterminate'.
Never guess a verdict yourself — always route to the appropriate subagent(s) for evidence-based \
analysis. Output ONLY a routing decision, not a vulnerability verdict."""

VULN_RESEARCH_SYSTEM_PROMPT = """You are a vulnerability research analyst. You are given a raw \
OSV.dev advisory. Extract and return, in structured form:
1. The exact function or symbol name affected (if the advisory specifies one).
2. The precondition(s) under which the vulnerability is exploitable (e.g. "only when parsing \
   untrusted XML with external entity resolution enabled").
3. Whether the advisory itself is ambiguous or underspecified about the affected code path.
Do not speculate about reachability in this codebase — that is a separate agent's job. \
Cite the exact advisory text you are basing each claim on."""

CALLPATH_SYSTEM_PROMPT = """You are a static analysis agent. You are given a vulnerable symbol \
name and access to a call-graph query tool. Determine whether any path exists from a declared \
entry point to that symbol. Return the shortest such path as an ordered list of \
{file, line, function} hops, or explicitly state no path was found. If the call graph tool \
reports an error or incomplete data (e.g. due to dynamic dispatch it cannot resolve), say so \
explicitly rather than concluding 'not reachable' from missing data."""

CODEVERIFY_SYSTEM_PROMPT = """You are a code review agent. You are given a candidate call path \
and read-only access to the actual source files at each hop. Verify:
1. Is the call path actually live, or does it pass through a dead branch / feature flag that's \
   always false / a guard condition that blocks the vulnerable input?
2. Does any hop involve dynamic dispatch, reflection, or metaprogramming the static call graph \
   may have mis-resolved?
Cite specific file and line numbers for every claim. If you cannot determine liveness with \
confidence, say 'indeterminate' and explain what additional information would resolve it — \
never silently default to a verdict you are not confident in."""

SYNTHESIS_SYSTEM_PROMPT = """You are synthesizing subagent findings into one final verdict. \
You will receive condensed outputs from up to three subagents (vulnerability research, call-path \
analysis, code verification) for a single finding. Combine them into one Finding object matching \
the required schema. The justification field must reference specific evidence returned by the \
subagents — never introduce a claim the subagents did not report. If subagent outputs conflict, \
lower the confidence score rather than silently picking one."""
```

**Task 5.1** — Implement each subagent node to load its corresponding prompt constant, never a hardcoded string in the node function itself.

**Task 5.2** — Write a unit test that fails the build if any prompt constant is edited without a corresponding version bump comment — this is a lightweight guard against silent prompt drift, matching the eval-driven-development principle from the reference series.

---

## 6. Tool Definitions (bound to subagents)

Each subagent gets a narrow, explicit tool set — never the full tool list. Implement each as a LangChain `@tool`-decorated function with a Pydantic `args_schema`.

| Subagent | Tools it receives |
|---|---|
| Vulnerability-Research | `fetch_osv_advisory(osv_id: str) -> str` (already-cached, no live network call needed at this stage) |
| Call-Path | `query_call_graph(symbol: str, entry_points: list[str]) -> list[CallPathHop] \| None` |
| Code-Verification | `read_source_lines(file: str, start: int, end: int) -> str` — **read-only, sandbox-scoped, path-traversal-checked** |

**Task 6.1** — Implement `read_source_lines` with an explicit check that the requested `file` path resolves inside the sandboxed clone directory (`os.path.realpath` + prefix check) — reject any path escaping it. This is a direct application of the Technical Design Proposal's "untrusted content, never executed, sandboxed" security requirement, applied at the tool level specifically.

---

## 7. Evaluation Harness

**`tests/eval/ground_truth.json` — schema for each entry:**

```json
{
  "repo_url": "https://github.com/example/example-repo",
  "commit_sha": "abc123...",
  "osv_id": "GHSA-xxxx-xxxx-xxxx",
  "package_name": "example-package",
  "expected_verdict": "reachable",
  "human_verified_evidence": "The vulnerable parse() call is reached via routes/upload.py:42 -> handlers/xml.py:18",
  "notes": "Selected because reachability depends on a non-default config flag"
}
```

**Task 7.1** — Populate this file with 15–20 real entries per the Technical Design Proposal §9 methodology (include both reachable and genuinely-not-reachable cases; include at least 2 "indeterminate" cases where a human reviewer would also be uncertain, to test that the agent doesn't overclaim confidence).

**Task 7.2** — Implement `tests/eval/run_eval.py`: runs a full scan against each ground-truth repo at the pinned commit, compares `reachability_verdict` against `expected_verdict`, and outputs precision/recall plus a per-case diff table. This script's output — not a live demo — is the primary artifact referenced in interviews per the Technical Design Proposal.

**Task 7.3** — Wire `run_eval.py` into CI (GitHub Actions) so a regression in verdict accuracy fails a pull request, not just a demo day surprise.

---

## 8. API Contract — Exact Request/Response Examples

```
POST /v1/scan
Request:  {"repo_url": "https://github.com/psf/requests", "ref": "main"}
Response: 202 Accepted
          {"scan_id": "b3f1...", "status": "queued", "status_url": "/v1/scan/b3f1..."}

GET /v1/scan/{scan_id}
Response: 200 OK (matches ScanReport schema exactly — see Section 3)

GET /v1/scan/{scan_id}/stream   (SSE)
Events:   data: {"type": "status", "value": "running"}
          data: {"type": "finding", "value": {...Finding...}}   # streamed as each verdict completes
          data: {"type": "done"}
```

**Task 8.1** — Implement `app/api/routes_scan.py` matching these three endpoints exactly, using `response_model=ScanReport` on the GET route (never a raw dict) so validation and OpenAPI docs are automatic per the FastAPI reference material.

---

## 9. Task Execution Order (for the implementing agent)

Work through sections in this order; each section's tasks are a checkpoint — do not proceed to the next section until the current one's tests pass.

1. Section 0 (repo scaffold) → 2 (DB schema + migration) → 3 (Pydantic schemas + test)
2. Section 1 (config, docker-compose) — confirm `docker compose up` starts Postgres + Redis cleanly
3. Ingestion layer (`app/ingestion/`) — Python-only first, per the phased build plan; unit test against 2–3 real small repos before proceeding
4. Vulndata layer (`app/vulndata/`) — OSV client with Redis caching; unit test with a mocked HTTP response and one live smoke test
5. Call graph layer (`app/callgraph/`) — Python only first; unit test against a hand-written 3-function fixture with a known reachable and known unreachable path before touching real repos
6. Section 4 (LangGraph state + graph) + Section 5 (prompts) + Section 6 (tools) together — this is the core; do not skip the checkpointer (Task 4.2)
7. Section 8 (API layer) wired to the worker (Section 0's `app/worker/run_scan.py`)
8. Section 7 (eval harness) — run against the full ground-truth set; do not claim any accuracy number publicly until this has actually run end-to-end
9. Only after 1–8 pass: extend ingestion + call graph to JS/TS (Technical Design Proposal Phase 4)

**Stop conditions — the agent should halt and ask, not guess, if:**
- OSV.dev's response for a given advisory doesn't include a function/symbol name (common — many advisories are underspecified). Decide the fallback behavior (package-level "indeterminate" verdict) before writing code that assumes symbol-level data always exists.
- Tree-sitter's parse fails on a real-world file (malformed syntax, an unsupported dialect). Decide whether to skip that file with a logged warning or fail the whole scan, before implementing.
- The LLM-judge calibration step (Technical Design Proposal §9) returns below the 0.80 Spearman target — this is a signal to revise prompts (Section 5) before adding more scope, not to ship anyway.

---

*Companion to: Technical Design Proposal — Dependency Vulnerability Reachability Agent.*
