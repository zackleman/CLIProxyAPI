# Plan: Fable quota-aware routing + decoupled Codex upstream WebSockets

Date: 2026-09-13
Status: approved design (grilling converged), ready to implement
Base branch: `codex/fable51-upstream-7-2-155` (deployed on nucbox, commit `62711e08`)
Delivery: two separate feature branches off the base branch, one per feature.

## Context and existing infrastructure

Facts established by exploring the fork:

- Selection lives in `sdk/cliproxy/auth/selector.go` (`Selector.Pick`) and the fast-path
  `sdk/cliproxy/auth/scheduler.go`. Today: priority buckets (`Attributes["priority"]`),
  then round-robin or fill-first. Per-model cooldown gating via `auth.ModelStates[model]`.
- No proactive quota tracking exists. Only reactive cooldown state from 429s
  (`Quota.NextRecoverAt`, in-memory by default, `.cds` files when
  `save-cooldown-status: true`). Codex parses `resets_at` from usage-limit errors;
  Claude has nothing.
- Passive header observation **already exists on the base branch**:
  `sdk/cliproxy/auth/quota_signals.go` captures `anthropic-ratelimit-unified-*`,
  `x-codex-*` etc. into `QuotaState.Signals` per auth and per model, exposed via
  `GET /v0/management/auth-files` (`entry["quota"]`, `entry["model_quotas"]`).
- The management dashboard quota page is client-side JS (downloaded
  `management.html`) that calls upstream APIs itself through the opaque
  `POST /v0/management/api-call` proxy. Nothing is stored server-side.
  - Claude quota source: `GET https://api.anthropic.com/api/oauth/usage` with
    `Authorization: Bearer <oauth token>`, `anthropic-beta: oauth-2025-04-20`.
    Returns per-window objects (`five_hour`, `seven_day`, `seven_day_opus`,
    `seven_day_sonnet`, ...) with `{utilization, resets_at}`, plus `limits[]`
    where Fable weekly is `kind == "weekly_scoped"`, `scope.model.display_name`
    in {"fable", "fable 5"}, carrying `percent`, `resets_at`, `is_active`.
  - Codex quota source: `GET https://chatgpt.com/backend-api/wham/usage`.
- Codex upstream WebSocket **already exists**:
  `internal/runtime/executor/codex_websockets_executor.go`
  (`CodexWebsocketsExecutor`, `wss://.../responses`, per-session persistent
  connections, reconnect logic), plus a downstream WS handler
  (`GET /v1/responses` upgrade). But `CodexAutoExecutor` only engages upstream WS
  when the *client* connected over WS. Codex CLI is HTTP, so the perf benefit is
  unreachable in real usage.
- OAuth token refresh machinery for background use exists (`auto_refresh_loop.go`).

## Feature 1: quota-aware account prioritization

Status: **implemented** on branch `codex/fable-quota-aware-routing`
(worktree `~/Projects/oss/CLIProxyAPI-quota-routing`):
`quota_probe.go` / `quota_probe_parse.go` / `quota_probe_store.go` /
`quota_poller.go` / `quota_routing.go` + selector/scheduler wiring, config flag
`quota-aware-routing` (default off), poller started from the service lifecycle
and force-refreshed from `MarkResult` on any quota-class 429 (claude/codex).
Deviations for simplicity: weighted round-robin rotates weightedly within the
sorted head group instead of a full weighted sort; the per-auth sidecar
extension is `.quota` (not `.quota.json`, which the auth-file watcher and token
store would misread).

### Extension (2026-09-13): Codex weekly-first ordering

Second user requirement: Codex/ChatGPT subscriptions with the most weekly
allowance left must serve first; a credits-backed account whose weekly
subscription is spent is last resort only (live-confirmed skew: 487 vs 9
requests landing on the credits account in one hour under plain round-robin).

Rule (family `"codex"`, gated by the same `quota-aware-routing` flag, applied
to providers `"codex"` and `"mixed"` for gpt-*/codex-* models): order ready
candidates by fresh weekly (`secondary_window`) used_percent ascending —
hourly(5h)-exhausted credentials demoted below all others, unknown allowances
below known ones, then priority desc, ID asc — and rotate within the head
group. Nothing is excluded and there is no local 429: a weekly-exhausted
(credits-reliant) account stays eligible and only serves once every fresher
subscription leaves availability, matching "credits only after every
subscription allowance is used up". Ordering uses percent, not reset
projection, so no recurrence constant is needed for Codex.

### Live verification (2026-09-13, nucbox accounts, read-only curls)

- Claude `GET api.anthropic.com/api/oauth/usage` with plain
  `Authorization: Bearer` + `anthropic-beta: oauth-2025-04-20` → HTTP 200 on
  all 3 OAuth accounts; `limits[]` carries
  `{"kind":"weekly_scoped","scope":{"model":{"display_name":"Fable"}},percent,resets_at,is_active}`.
  Actual state: z2@jarmin.ai **31%** (resets 09-16), zack@jarmin.ai **100%**
  (resets 09-17 12:00Z), z@jarmin.ai **100%** (resets 09-17 20:00Z) — exactly
  the account skew this routing exists for. Regression test added from a
  reduced copy of this payload.
- Codex `GET chatgpt.com/backend-api/wham/usage` → HTTP 200; shape is
  `rate_limit.primary_window` / `secondary_window` (not `primary`/`secondary`)
  with `used_percent`, `reset_after_seconds`, `reset_at` (unix); additional
  limits nest the same struct under `additional_rate_limits[].rate_limit`.
  Parser updated accordingly; live-shape fixture added. A stale (2026-07)
  Codex access token → 401, handled by the poller's refresh-then-poll.

### Deployment verification (2026-09-13, nucbox)

Deployed `08d3fdad` on nucbox with `quota-aware-routing: true`. Poller fetched
all 6 healthy credentials within one jittered round, `.quota` sidecars match
hand-verified upstream values, and probes restore across restarts
("restored 6 persisted quota probe(s)"). Live e2e routing: a `claude-fable-5-1`
request bound to claude-z2@jarmin.ai (31% used, soonest reset), a
`claude-opus-5` request bound to claude-z@jarmin.ai (Fable exhausted). The
post-deploy smoke run also caught and fixed a real gap: the legacy
mixed-provider selection path (session-affinity round-robin + Bedrock failback
credentials) invokes selectors with provider "mixed", which the claude-only
gate rejected (`08d3fdad`).

### Rules (approved)

1. **Fable reset-soonest.** For requests routed to any `claude-fable-*` model:
   among candidate accounts with Fable quota remaining, sort by next weekly Fable
   reset time ascending (soonest first). This is a **strict primary sort key**,
   above the auth `priority` attribute; existing logic (priority buckets, then
   round-robin/fill-first) breaks ties.
2. **Opus spills onto Fable-exhausted accounts** (one-way). For requests routed
   to any `claude-opus-*` model: prefer accounts whose Fable 5.1 weekly quota is
   exhausted, then existing logic. No symmetric rule for Fable requests.
3. **All-exhausted Fable request** → fall through to existing all-cooling-down
   behavior (429 + `Retry-After`, earliest reset). No silent model swaps.

### Exhaustion and reset semantics (approved)

- An account counts as Fable-exhausted when polled `percent >= 100` or a
  weekly-limit 429 was observed on it, sticky until `resets_at` passes or a fresh
  poll shows `percent < 100`.
- Fable requests filter candidates to `percent < 100` (or unknown) **before**
  the soonest-reset sort.
- Recurrence trick: once a weekly reset time T is learned, project T + 7d
  forward so stale snapshots rarely degrade to "unknown". Accounts with
  genuinely unknown reset time sort as **resetting latest** (pessimistic).

### Data plane: server-side quota poller (approved)

- Port the dashboard's quota fetch into Go: a background poller that calls
  `GET https://api.anthropic.com/api/oauth/usage` (and `wham/usage` for Codex)
  per OAuth account, using `auto_refresh_loop`-adjacent token refresh so expired
  tokens are refreshed before polling.
- Poll interval: **10 min per account, staggered**. Force-refresh an account on
  any weekly-limit 429.
- Staleness cap **2h**: older snapshots are treated as unknown by the selector.
- Persist snapshots to a per-auth `.quota.json` cache file (pattern after
  `cooldown_state.go`) so restarts keep learned reset windows.
- Passive header signals (`quota_signals.go`) stay as a real-time overlay on top
  of the polled snapshot.

### Selector integration

- New pre-filter/ordering step in the selection path (both `Selector.Pick`
  legacy and `scheduler.go` fast path must behave identically; add tests for
  both).
- Model-family matching is prefix-based: `claude-fable-*` and `claude-opus-*`,
  applied after alias/force-mapping resolution (`selectionModelForAuth`).

### Config (hardcoded rules, no rule engine — approved)

```yaml
quota-aware-routing: true            # one toggle, off by default
```

Poll interval and staleness get sensible constants first; promote to config
only if needed (YAGNI).

## Feature 2: decoupled Codex upstream WebSockets

Status: **implemented** on branch `codex/fable-quota-aware-routing` (commit
`b7ba9eef`): `codex.upstream-websockets` config (default off), auto-executor
gate requiring per-credential `websockets: true`, session ids derived from the
canonical session identity (`decws:<canonical>`), HTTP fallback + 5 min
per-credential WS cooldown on connect/send failures (never mid-stream), 30-min
idle eviction added to the session store (no lifecycle closes decoupled
sessions), `UsesConfig` rebinding so reloads apply the flag.
`scripts/bench-codex-transport.sh` replays a 12-turn full-transcript session
with tool calls and reports wall + cached_tokens.

### Bench results (2026-09-13, nucbox, spark/gpt-5.5)

- gpt-5.5, 12 turns × 5 reps: HTTP 20.8s vs WS 18.9s mean wall (~9%).
- gpt-5.3-codex-spark, 12 turns: HTTP 19.4s vs WS ~22.8s (noise-level, both
  runs suffered one dropped turn each — upstream flakiness among mostly
  exhausted accounts, not transport-specific).
- cached_tokens: 0 in both transports (transcripts stay below the upstream
  caching threshold), so parity holds trivially; connection reuse verified via
  socket logs (one connect per session).
- Verdict: no ≥30% win in this workload — turns are generation-bound.
  **Config default stays off; nucbox flag left off.** The mode is one config
  line away for real Codex CLI traffic (longer turns, session_id headers),
  where the steady-state reuse story may differ; revisit if desired with
  real-world traces.

### Verify first, then decouple (approved)

1. Bench and validate the **existing** WS executor path (downstream WS →
   upstream WS) to confirm upstream ChatGPT accepts it and measure baseline.
2. Then decouple: allow upstream WS for HTTP-downstream requests.

### Config (approved)

- Existing per-auth `websockets: true` capability flag stays.
- New global toggle `codex.upstream-websockets: true` (default off) enables
  upstream WS regardless of downstream transport, still requiring the per-auth
  capability.

### Failure semantics (approved)

- WS connect/handshake failure → one transparent retry over HTTP for that
  request, mark the account WS-cooldown ~5 min to avoid thrash, log loudly.
- Mid-stream WS failure (after tokens streamed) → fail the request. No replay
  of partial streams.
- Connection keying: keep `codexWebsocketSessionStore` per-session persistence
  (protects prompt-cache locality). HTTP clients without session IDs fall back
  to the existing hash-of-system+first-messages session key the selector already
  computes.

### Benchmark acceptance (approved)

- Replayed multi-turn Codex session (10–20 turns with real tool calls),
  alternating HTTP vs WS against the same account, 5+ reps.
- Success = **≥30% lower total wall time** for the session, and `cached_tokens`
  share **no worse than the HTTP run**, with no cache-key drift in what we send
  upstream.
- Bench script: `scripts/bench-codex-transport.sh` in the proxy repo, prints
  wall / TTFB / cached_tokens side-by-side.
- Rollout: keep repo default off; flip nucbox config to `true` after numbers
  validate; bake.

## Decisions log (from grilling, all approved by Zack)

| # | Decision |
|---|---|
| 1 | Base both features on `codex/fable51-upstream-7-2-155`; two feature branches |
| 2 | Quota source = proactive server-side poll of the same upstream APIs the dashboard uses + passive header overlay + reactive 429 learning; no new ToS-gray probing |
| 3 | Fable sort is strict primary key, above `priority` attribute; unknown reset = latest |
| 4 | Opus rule one-way; exhaustion known from poll (`percent >= 100`) or observed weekly 429; all-exhausted Fable request → 429 + Retry-After |
| 5 | Rules cover whole `claude-fable-*` and `claude-opus-*` families; designated Opus model is `claude-opus-5` |
| 6 | WS: verify existing path, then decouple upstream transport from downstream transport |
| 7 | Benchmark: replayed real multi-turn session, ≥30% wall-time win, cached_tokens parity required |

## Risks / open items to watch

- Whether non-Max/other plans actually get the Fable `limits[]` entry from
  `api/oauth/usage` needs live verification during implementation; the
  passively-captured headers are the fallback signal.
- Upstream may rate-limit or dislike frequent `wham/usage` / `oauth/usage`
  polling; staggered 10-min cadence is conservative.
- Selector change touches both legacy and scheduler fast paths; identical
  behavior must be proven by tests, not assumed.
