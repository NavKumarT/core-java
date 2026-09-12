# Deployment & Scalability Spec — Dependency Vulnerability Reachability Agent

**Third companion document.** The Technical Design Proposal explains *why*; the Implementation Spec explains *how to build it*; this document explains *how to run it as a real product* — scaling, resilience, and operations, staged from a single-VM MVP to a horizontally-scaled, multi-tenant service.

---

## 0. Deployment Philosophy

Do not build for Stage 3 scale on day one. This spec is intentionally staged — each stage is a complete, shippable product on its own, and you upgrade only when a real, measured constraint (not a guess) forces the next stage. This mirrors the same "prove you need the complexity first" discipline used throughout the design and implementation specs.

| Stage | Scale target | Infra shape |
|---|---|---|
| **1 — MVP** | Portfolio demo, a few scans/day, single operator | One VM, docker-compose, no autoscaling |
| **2 — Small product** | Dozens of users, tens of scans/hour | Managed Postgres/Redis, containerized API + worker on a PaaS (Fly.io / Render / Railway), horizontal API replicas |
| **3 — Real product** | Hundreds of users, sustained concurrent scan load | Kubernetes, autoscaled worker pool, managed queue, multi-AZ Postgres, CDN/WAF in front |

This document specifies all three stages explicitly so you can build Stage 1 now while knowing exactly what Stage 2 and 3 require — and can speak to that roadmap in an interview without having built it yet.

---

## 1. Deployment Architecture — Component Map

```
                         ┌─────────────┐
 Client ──HTTPS──▶ LB/CDN │  (Stage 2+) │
                         └──────┬──────┘
                                │
                    ┌───────────┴───────────┐
                    │   FastAPI API replicas │  (stateless, horizontally scaled)
                    └───────────┬───────────┘
                                │
                 ┌──────────────┼──────────────┐
                 ▼              ▼              ▼
           ┌──────────┐  ┌──────────┐   ┌─────────────┐
           │ Postgres │  │  Redis   │   │  Job Queue   │
           │ (state,  │  │ (cache,  │   │ (Celery/RQ,  │
           │ findings)│  │ ratelim) │   │  Redis-backed)│
           └──────────┘  └──────────┘   └──────┬───────┘
                                                 ▼
                                     ┌────────────────────┐
                                     │  Worker pool         │  (autoscaled on queue depth)
                                     │  (LangGraph scan run) │
                                     └──────────┬─────────┘
                                                 ▼
                                     ┌────────────────────┐
                                     │ Ephemeral sandbox    │  (per-scan, network-isolated,
                                     │ container            │   destroyed after scan)
                                     └────────────────────┘
                                                 │
                              external calls (rate-limited, circuit-breakered):
                              OSV.dev · npm/PyPI registries · GitHub API · Anthropic API
```

**The core architectural decision:** the API layer, worker layer, and sandbox layer scale **independently** on different axes — API scales with request volume, workers scale with scan queue depth, sandboxes scale 1:1 with concurrently *running* scans and are always ephemeral. Conflating these into one deployable is the most common early mistake; keep them separate from Stage 1 onward even if they run on the same VM initially.

---

## 2. Stage 1 — Single-VM MVP

**`docker-compose.yml` (production-oriented, not the dev version):**

```yaml
services:
  api:
    build: { dockerfile: Dockerfile.api }
    restart: unless-stopped
    ports: ["8000:8000"]
    env_file: .env
    depends_on: [postgres, redis]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/healthz"]
      interval: 10s
      timeout: 3s
      retries: 3

  worker:
    build: { dockerfile: Dockerfile.worker }
    restart: unless-stopped
    env_file: .env
    depends_on: [postgres, redis]
    deploy:
      replicas: 2                      # even at Stage 1, run 2+ workers — never 1

  postgres:
    image: postgres:16
    restart: unless-stopped
    volumes: ["pgdata:/var/lib/postgresql/data"]
    env_file: .env

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: ["redis-server", "--maxmemory", "512mb", "--maxmemory-policy", "allkeys-lru"]

volumes:
  pgdata:
```

**Task 2.1** — `restart: unless-stopped` on every service is non-negotiable even at Stage 1 — a VM reboot or an OOM-killed container must self-heal without manual intervention.

**Task 2.2** — Run 2 worker replicas minimum from day one — this costs almost nothing and immediately validates that your job-queue design is actually safe under concurrent workers (no double-processing the same scan), which you need to be true at every later stage anyway.

**Task 2.3** — Nginx (or Caddy, for automatic TLS) in front of the API container, terminating TLS and proxying to `api:8000`. Do not expose Uvicorn directly to the internet.

---

## 3. Stage 2 — Small Product: Managed Infra, Horizontal API

**What changes from Stage 1:**

| Component | Stage 1 | Stage 2 |
|---|---|---|
| Postgres | Self-hosted container | Managed (RDS, Neon, Supabase) — automated backups, PITR |
| Redis | Self-hosted container | Managed (Upstash, ElastiCache) — persistence + failover |
| API | 1 container | 2–4 stateless replicas behind a load balancer |
| Worker | 2 fixed replicas | Autoscaled 2–10 based on queue depth |
| Job queue | In-process or simple Redis list | Celery or RQ with a proper broker, retry/dead-letter support |
| Deploy target | One VM | Fly.io / Render / Railway (managed container platform) — defer Kubernetes until Stage 3 |

**Gunicorn/Uvicorn worker count** (per Stage 2 API replica):

```
CMD ["gunicorn", "main:app", "-k", "uvicorn.workers.UvicornWorker",
     "--workers", "4", "--bind", "0.0.0.0:8000",
     "--timeout", "120", "--graceful-timeout", "30",
     "--max-requests", "1000", "--max-requests-jitter", "100"]
```

- `--workers 4`: a reasonable starting point for an I/O-bound async app on a 2-vCPU instance; tune against real load-test data, not this number alone.
- `--max-requests` + jitter: recycles workers periodically to bound the impact of any slow memory leak — cheap insurance, not optional at Stage 2+.
- `--graceful-timeout 30`: gives in-flight requests 30s to finish on a rolling deploy before being force-killed (Section 14).

**Task 3.1** — Move Postgres and Redis to managed services before scaling API replicas past 2 — a self-hosted single-instance Postgres becomes the actual bottleneck and single point of failure once multiple API/worker instances depend on it concurrently.

---

## 4. The Worker/Queue Layer — Scaling Scan Jobs

This is the layer most likely to be the actual bottleneck, since a single scan can run for minutes and involves multiple LLM calls per finding.

**Queue design:**

```python
# app/worker/run_scan.py — Celery task definition
from celery import Celery

celery_app = Celery("reachability", broker=settings.redis_url, backend=settings.redis_url)

@celery_app.task(
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    acks_late=True,                 # task is only ack'd after completion — survives worker crash mid-scan
    reject_on_worker_lost=True,     # requeues automatically if the worker process dies
)
def run_scan_task(self, scan_id: str):
    ...
```

- **`acks_late=True` + `reject_on_worker_lost=True`** is the single most important line in this section: without it, a worker crash mid-scan silently loses the job with no record it ever failed. With it, the job is automatically requeued — and because the LangGraph checkpointer (Implementation Spec §4.2) persists progress per finding, the requeued scan resumes from its last completed finding rather than restarting from zero.
- **`max_retries=2`** with backoff, distinguishing retryable failures (a transient OSV.dev timeout) from fatal ones (a malformed repo URL) — same retryable/fatal exception hierarchy used throughout the reference series.

**Autoscaling the worker pool** — scale on **queue depth**, not CPU:

```yaml
# Stage 3 (Kubernetes) HPA example — Stage 2 platforms (Fly.io/Render) expose an equivalent
# "scale on custom metric" or "scale on queue length" option under different config syntax
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata: { name: worker-hpa }
spec:
  scaleTargetRef: { apiVersion: apps/v1, kind: Deployment, name: worker }
  minReplicas: 2
  maxReplicas: 20
  metrics:
    - type: External
      external:
        metric: { name: celery_queue_depth }
        target: { type: AverageValue, averageValue: "5" }   # ~5 pending scans per worker before scaling up
```

CPU-based autoscaling is the wrong signal here — a worker waiting on an LLM API response shows near-zero CPU usage while genuinely busy; queue depth (or in-flight task count) is the correct scaling metric for this specific I/O-bound workload, directly echoing the reference series' point that CPU profiling is usually the wrong lens for agentic systems.

---

## 5. The Sandbox Layer — Isolating Untrusted Repo Analysis

This layer has the sharpest resilience *and* security requirements simultaneously, since it processes attacker-influenced content (a malicious or malformed public repo) by design.

```yaml
# Dockerfile.sandbox run invocation (from the worker, per scan)
docker run \
  --rm \
  --network none \                          # zero network egress — the repo cannot phone home
  --memory 512m --memory-swap 512m \        # hard memory ceiling, no swap thrashing
  --cpus 1.0 \
  --pids-limit 128 \                        # fork-bomb protection
  --read-only \                             # root filesystem read-only
  --tmpfs /workspace:size=256m \            # the only writable location, size-capped
  --security-opt no-new-privileges \
  --cap-drop ALL \
  --timeout 120 \
  reachability-sandbox:latest \
  --repo-url "$REPO_URL" --ref "$REF"
```

**Task 5.1** — Every flag above is load-bearing, not defensive theater: `--network none` is what actually enforces the "no external communication" leg of the lethal-trifecta removal specified in the Technical Design Proposal — it is not achieved by application-code discipline alone, it is enforced at the container runtime level, which is the correct place to enforce it since application code can have bugs.

**Task 5.2** — If the sandbox process exceeds its timeout or memory limit, the orchestrating worker must catch that specific failure and mark the finding-set as `indeterminate` with a clear reason (`"repository analysis exceeded resource limits"`) rather than silently truncating results — an honest partial failure, not a silent one.

**Scaling this layer:** one ephemeral sandbox container per *concurrently running* scan, destroyed immediately on completion or failure — never reused across scans (a reused sandbox risks cross-scan data leakage between different users' private repos). At Stage 3, run these as Kubernetes Jobs with a pod-level resource quota rather than raw `docker run` from a worker process.

---

## 6. Database Scaling & Resilience

| Concern | Approach |
|---|---|
| Connection pooling | PgBouncer in front of Postgres once API + worker replicas exceed ~4 total — direct per-replica connection pools will exhaust Postgres's own `max_connections` before the app layer becomes the bottleneck |
| Read scaling | A read replica for the (eventual) dashboard/history-browsing UI, keeping write traffic (scan results) on the primary only |
| Backup | Automated daily snapshots + point-in-time recovery (PITR) via WAL archiving — a managed provider (Stage 2+) gives you this by default; verify it, don't assume it |
| Migration safety | Every Alembic migration must be backward-compatible with the *previous* app version for one deploy cycle (additive-only: add nullable columns, backfill, then tighten constraints in a follow-up migration) — this is what makes zero-downtime rolling deploys (Section 14) actually safe |
| Idempotency at the DB layer | The `UNIQUE (repo_url, commit_sha)` constraint from the Implementation Spec's schema is the actual enforcement mechanism for "re-scanning an unchanged commit returns the cached result" — a real, DB-enforced idempotency guarantee, not just a convention |

---

## 7. Caching Layer (Redis) at Scale

- **Eviction policy**: `allkeys-lru` — OSV/registry cache entries are the right thing to evict under memory pressure; never let cache growth threaten the rate-limiter or job-queue data structures also living in Redis. At Stage 3, split these into separate Redis instances/databases (cache vs. queue vs. rate-limit counters) so a cache eviction storm can't disrupt job queuing.
- **TTL discipline**: 24h TTL on OSV advisory data (Implementation Spec §6.2's specified value) — advisories update infrequently, but a TTL that's too long risks serving stale "fixed in version X" data after a package patches again.
- **Failure mode**: if Redis is unreachable, the API and worker must degrade to "no cache, direct API calls" rather than hard-failing the whole request — implement this as an explicit try/except around every Redis call, not an assumption that Redis is always up.

---

## 8. Reliability Engineering — External Dependency Resilience

This system calls four external services per scan (OSV.dev, npm/PyPI registries, GitHub API, Anthropic API) — each needs its own circuit breaker and fallback behavior, not a shared generic "retry everything" policy.

| External dependency | Circuit breaker trigger | Fallback behavior |
|---|---|---|
| OSV.dev | 5 consecutive failures in 60s | Serve last-cached advisory data (even if past TTL) with a `"data may be stale"` flag on the report, rather than failing the scan |
| npm / PyPI registry | 5 consecutive failures in 60s | Skip fix-version lookup for affected findings; mark `fixed_version: null` rather than blocking the whole scan |
| GitHub API | Any 5xx on repo clone | Fail the specific scan with a clear `"repository unavailable"` error — this one has no safe fallback, since it's the actual input |
| Anthropic API (LLM calls) | 3 consecutive failures | Retry with the fallback-provider pattern from the reference series (`with_fallbacks`) if a second provider is configured; otherwise mark affected findings `indeterminate` rather than blocking the entire scan on one stuck finding |

**Task 8.1** — Implement each circuit breaker as an independent instance (per-dependency, not global) — a global circuit breaker means one flaky dependency takes down calls to every other dependency, which is strictly worse than the problem it's meant to solve.

**Task 8.2** — Every external call gets its own explicit timeout, sized to that specific dependency's real expected latency (an LLM call needs a much longer budget than an OSV lookup) — a shared generic timeout is a documented anti-pattern from the reference series' production material and applies directly here.

---

## 9. Zero-Downtime Deployment

**Rolling deploy sequence (Stage 2+):**

1. New API replica starts, begins passing `/readyz` (Section 10) only once its DB connection and Redis connection are confirmed live.
2. Load balancer routes traffic to the new replica only after `/readyz` succeeds.
3. Old replica stops receiving new traffic, but is given `--graceful-timeout 30` (Section 3) to finish in-flight requests before termination.
4. Repeat per replica until all are on the new version.

**Worker deploys are different and require more care:** a worker mid-scan holds real progress in the LangGraph checkpointer, so killing it mid-task is safe (the checkpointer resumes it, per Section 4) — but prefer a graceful drain (stop pulling new tasks, finish current task, then exit) over a hard kill wherever the deployment platform supports it, to avoid unnecessary requeue churn.

**Database migrations** run as a separate, preceding deploy step — never bundled into the same deploy as new application code that depends on the new schema (Section 6's backward-compatibility rule is what makes this safe to sequence this way).

---

## 10. Health Checks & Load Balancer Integration

```python
@app.get("/healthz")           # liveness — is the process alive at all
async def healthz():
    return {"status": "ok"}

@app.get("/readyz")            # readiness — can it actually serve traffic right now
async def readyz():
    try:
        await db.execute(select(1))
        await redis_client.ping()
        return {"status": "ready"}
    except Exception:
        raise HTTPException(503, "dependencies unavailable")
```

Configure the load balancer / orchestrator to route traffic based on `/readyz`, and configure process-restart policy based on `/healthz` — conflating the two (as many default configs do) means a replica with a temporarily-down DB connection gets killed and restarted repeatedly instead of just being paused from receiving traffic until the DB recovers, which is a meaningfully worse failure mode under a transient outage.

---

## 11. Multi-Tenant Rate Limiting at the Deployment Layer

Beyond the application-level rate limiter (Implementation Spec), enforce a second layer at the edge:

| Layer | Enforces | Why both are needed |
|---|---|---|
| Edge (Nginx/CDN/API Gateway) | Coarse IP-based request rate limit | Cheap, first line of defense against abuse before it even reaches the app; protects against a broad flood, not per-tenant fairness |
| Application (Redis token bucket, per API key) | Fine-grained per-tenant request AND token-based limits | Real fairness between tenants, and cost control specifically — a single tenant's expensive scans shouldn't starve others' quota |

**Task 11.1** — Set the application-layer limit meaningfully *below* the edge-layer limit, so the edge layer is genuinely a backstop, not the binding constraint in normal operation.

---

## 12. Observability & SLOs in Production

**Minimum dashboard, from day one of Stage 2:**

| Metric | Alert threshold (starting point — tune with real data) |
|---|---|
| API P99 latency (non-scan endpoints) | > 1s sustained for 5 min |
| Scan completion P95 latency | > 8 min sustained for 15 min |
| Queue depth (pending scans) | > 50 for 10 min, or growing for 30 min |
| Worker error rate | > 5% of tasks failing over 15 min |
| External dependency circuit-breaker trips | Any trip — page immediately, these are rare and always worth a look |
| Cost per scan (rolling average) | > $0.75 (50% over the $0.50 target) sustained over 1 hour |
| Postgres connection pool utilization | > 80% sustained |

**Task 12.1** — Every scan gets one OTel trace spanning the full multi-agent run (API request → job enqueue → worker pickup → each subagent call → synthesis → response), with cost and token counts attached as span attributes per finding — this is the direct production analog of the reference series' "two-span trace" failure mode: without per-subagent spans, a slow or expensive scan is invisible until someone notices the invoice.

---

## 13. Security Hardening for Production

- **Secrets**: never in environment files committed to the image; use the platform's secret manager (Fly.io secrets, AWS Secrets Manager, Kubernetes Secrets + external-secrets-operator at Stage 3). Rotate the GitHub PAT and Anthropic API key on a defined schedule, not only on suspected compromise.
- **Least-privilege IAM**: the worker's cloud credentials (if any, e.g. for object storage) should be scoped to exactly the buckets/resources it needs — never a broad account-level credential.
- **Sandbox escape defense-in-depth**: Section 5's container flags are the primary control; at Stage 3, additionally run sandbox Jobs in a dedicated, network-policy-isolated Kubernetes namespace so even a full container escape can't reach the API/DB/Redis network segment.
- **Dependency hygiene for the service itself**: this product's own dependency tree should be scanned by *itself* (or an equivalent tool) in CI — a genuinely good story for an interview, and a real practice, not just a demo gimmick.

---

## 14. Cost Management at Scale

- Track **cost per scan** as a first-class metric (Section 12), not an after-the-fact invoice surprise — this is enforced at the code level by summing per-subagent token costs into `scans.total_cost_usd` (Implementation Spec §2 schema) on every run.
- **Model routing is the primary lever**: the Lead agent's routing decision (Implementation Spec §5, `plan_and_dispatch`) — full three-subagent treatment only for high-severity or ambiguous findings — is what keeps average cost near the $0.50/scan target; monitor the *ratio* of full-effort to lightweight findings as a leading indicator before cost itself drifts.
- **Budget circuit breaker**: if a single scan's running cost exceeds a hard ceiling (e.g., 3x the target), abort that scan with a partial report rather than let one pathological repository (thousands of dependencies) consume unbounded spend.

---

## 15. Capacity Planning — Worked Example

**Scenario:** size Stage 2 infrastructure for 200 scans/day, assuming scans arrive unevenly (peak hours see 3x average load).

```
Average: 200 scans/day ÷ 24h ≈ 8.3 scans/hour
Peak (3x): ≈ 25 scans/hour ≈ 1 scan every ~2.4 minutes

Assume: average scan takes 4 minutes end-to-end (per NFR target), with a worker
occupied for the full duration of a scan it's processing.

Concurrent scans in flight at peak ≈ (scans/hour at peak) × (avg duration in hours)
                                    ≈ 25 × (4/60) ≈ 1.7 concurrent scans at peak

Worker replicas needed ≈ ceil(1.7 / target_utilization) 
                        → with 70% target utilization (headroom for spikes): ceil(1.7 / 0.7) ≈ 3 workers minimum at peak

Sandbox containers needed = 1:1 with concurrently running scans → 3 sandbox slots at peak,
                             sized per Section 5's per-container limits (512MB, 1 CPU each)
                             → ~1.5GB RAM, 3 CPU cores of sandbox capacity at peak alone

API replicas: request volume here is low-frequency (scan submission + polling), not the
              bottleneck — 2 replicas for redundancy is sufficient well past this scale.
```

**The actual lesson this worked example is built to teach:** at this scale, the **worker/sandbox layer**, not the API layer, is the real capacity constraint — directly consistent with Section 1's point that these layers scale on different axes, and a reminder to size infrastructure against the *scan* workload specifically, not generic "web traffic" assumptions.

---

## 16. Environments & CI/CD

| Environment | Purpose | Notes |
|---|---|---|
| **Local dev** | `docker-compose.yml` (dev variant), hot-reload enabled | Never points at real OSV/GitHub rate-limited quotas without a mock/cache layer for iteration speed |
| **Staging** | Mirrors Stage 2 production topology at minimal scale | Runs the eval harness (Implementation Spec §7) on every merge to `main` — a verdict-accuracy regression blocks promotion to production |
| **Production** | Stage 2 or 3 per current real scale | Deploys only from a tagged release, never directly from `main` |

**CI pipeline (GitHub Actions), minimum stages:** lint/type-check → unit tests → integration tests (mocked external APIs) → eval harness against the ground-truth set → build + push container images → deploy to staging → (manual or automated gate) → deploy to production.

---

## 17. Interview Talking Points

**"How would you scale this if usage grew 10x overnight?"**
Workers and sandboxes autoscale on queue depth (Section 4) — that's the layer that actually needs to grow. The API layer barely needs to change (Section 15's worked example shows it's never the constraint). The real risk at 10x is external API rate limits (OSV.dev, GitHub, Anthropic) becoming the ceiling before infrastructure does — I'd check those quotas first, and lean harder on the cache layer (Section 7) to reduce redundant external calls before scaling compute.

**"What's your single point of failure right now, and how would you remove it?"**
At Stage 1, it's the single VM. At Stage 2, it's the primary Postgres instance for writes — mitigated by managed automated failover, not eliminated; a genuinely HA Postgres setup (multi-AZ with synchronous replication) is a Stage 3 investment I'd make once write throughput or availability SLAs actually demanded it, not before.

**"How do you know a deploy didn't break anything, before a user tells you?"**
The eval harness (Section 16) runs in CI against the ground-truth set on every merge — a verdict-accuracy regression is caught before staging, let alone production. Combined with the OTel dashboards (Section 12) and their alert thresholds, a production regression in either accuracy or latency/cost surfaces automatically rather than via a support ticket.

---

*Third companion document to: Technical Design Proposal and Implementation Spec — Dependency Vulnerability Reachability Agent.*
