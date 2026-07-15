# whisper-catalog

**The portable query catalog for [whisper.security](https://whisper.security).**
One machine-readable file, [`catalog.json`](./catalog.json), describes every graph query and read flow the Whisper security graph exposes, so any surface (an MCP server, an SDK, a CLI, an LLM tool-belt) can offer them without re-discovering the wire format.

Every entry is **provenance-backed**: its shape (columns, arguments) was taken from a live probe of the endpoint, not guessed.

---

## Two tiers: taste it keyless, build on a key

Both tiers are honest.

**Keyless taste (no key).** The single-request **direct read verbs** (`identify`, `assess`, `explain`, `variants`, `walk`, `origins`, `history`, and the rest of the 13 marked `access: "keyless"` / `playgroundTryable: true`) run with **no key at all** and return real answers. One line, zero setup:

```bash
# keyless: no auth header, real answer, rate-limited
curl -s https://graph.whisper.security/api/query \
  -H 'content-type: application/json' \
  --data '{"query":"CALL whisper.assess([$v]) YIELD host, label, band","parameters":{"v":"8.8.8.8"}}'
# -> {"columns":["host","label","band"],"rows":[{"host":"8.8.8.8","label":"benign-allowlisted","band":"INFO"}], ...}
```

It is a **rate-limited taste**: **100 requests / window** (`x-ratelimit-limit: 100`; every request, even a refusal, spends one). It works, then it `429`s, then it resets. Perfect for a first look or a light check; **not something to build a production system on.**

**Keyed (your API key).** Send `X-API-Key` and the rate limit lifts (unlimited), and you unlock the rest of the graph: **raw Cypher**, the **multi-step investigation flows**, and the `whisper.submit` write channel.

```bash
# keyed: unlimited, plus raw Cypher + the flows + submit
curl -s https://graph.whisper.security/api/query \
  -H 'content-type: application/json' \
  -H 'X-API-Key: whisper_live_…' \
  --data '{"query":"CALL whisper.identify([$v]) YIELD host, vendor_id, canonical_name","parameters":{"v":"api.openai.com"}}'
```

The **response envelope** is always `{columns, rows, statistics}`, and **rows are objects keyed by column name**:

```json
{
  "columns": ["host","vendor_id","canonical_name","category","roles","host_class","band"],
  "rows": [
    {"host":"api.openai.com","vendor_id":"cloudflare","canonical_name":"Cloudflare",
     "category":"cdn","roles":["ORIGIN_AS","CDN"],"host_class":"unknown","band":"DERIVED"}
  ],
  "statistics": {"rowCount": 1, "executionTimeMs": 12}
}
```

| | Keyless taste (no key) | Keyed (your API key) |
|---|---|---|
| **What** | The direct read verbs: identify, assess, explain, variants, walk, origins, history, … | Everything: every read verb, every multi-step investigation flow, and the `whisper.submit` write channel |
| **Limit** | **100 requests / window** (every request, even a refusal, spends one) | **Unlimited** |
| **For** | A first look; a light check; kicking the tyres | Production. Everything real. |

Why keyless is only the direct reads: a multi-step **flow** is dozens of `CALL`s (one deep flow would exhaust the 100/window cap mid-run), and **writes** must be attributable, so `whisper.submit` is keyed always. A keyless write is refused with a clear message (`a write channel requires an attributable API key … preserves K-anonymity`); it fails helpfully, never silently.

> Whisper has a second keyless surface outside this catalog: the non-Cypher **identity** tools `verify` (prove an agent/domain identity) and `rdap` (IP-anchored registration lookup), which carry no key and no rate cap at all. This catalog is the **graph** (Cypher) surface.

## What's in the catalog

`catalog.json` holds **29 entries**, two-tier: **13 keyless** single-request direct reads (`access: "keyless"`, tastable with no key) and **16 keyed** (the multi-step flows and the one write channel, `whisper.submit`). Two execution modes:

- **`direct`**: a single Cypher `CALL` you can run against the endpoint as-is. The entry carries the exact `cypher`, its `params`, and the `columns` it returns.
- **`flow`**: a multi-step read investigation (e.g. `attack-surface`, `indicator`, `typosquat`) orchestrated by a `run_workflow` runner over the same endpoint. The entry carries the anchor step's live columns and the analyst prompt. Flows are runnable via the top-level `graph.flowRun` contract: `POST` the entry's `id` as `slug` (plus `inputs`/`params`) to the run endpoint with `X-API-Key`; the result streams back over SSE.

Every entry also carries a **`docPath`**: a root-relative documentation path. Build the absolute docs link as `graph.docsBase + docPath` (e.g. `https://www.whisper.security/docs/whisper-graph/procedures/explain`).

Each entry:

```jsonc
{
  "id": "identify",
  "title": "Vendor / Operator Identity (whisper.identify)",
  "purpose": "Name the vendor and operator role behind a host or IP in one call.",
  "category": "Infrastructure, supply-chain & compliance / Research & OSINT",
  "docPath": "/docs/whisper-graph/procedures/identify",
  "inputs": [{ "id": "value", "kind": "any", "paramName": "v", "default": "api.openai.com" }],
  "exec": {
    "mode": "direct",
    "cypher": "CALL whisper.identify([$v]) YIELD host, vendor_id, canonical_name, category, roles, host_class, band",
    "params": { "v": "api.openai.com" }
  },
  "access": "keyless",
  "playgroundTryable": true,
  "columns": ["host","vendor_id","canonical_name","category","roles","host_class","band"],
  "prompt": "Identify the vendor and operator roles behind api.openai.com…",
  "provenance": true,
  "version": "1.0.0"
}
```

See [`docs/CATALOG.md`](./docs/CATALOG.md) for the full table, and [`catalog.schema.json`](./catalog.schema.json) for the entry contract.

## How surfaces consume it

`catalog.json` is the single source of truth; the derived surfaces are generated from it:

```bash
node scripts/validate.mjs   # access-correctness + hygiene gate (non-zero on failure)
node scripts/generate.mjs   # emits docs/CATALOG.md, mcp-tools.json, sdk-methods.json
```

- **[`mcp-tools.json`](./mcp-tools.json)**: every graph query as an MCP tool descriptor (JSON-Schema `inputSchema` per tool), each marked `_requiresKey` (`false` for the 13 keyless direct-read verbs, `true` for the flows + `submit`) so a surface can offer a real "try without a key" path, plus `_docPath`/`_docsUrl` docs links and, on flow tools, the ready-to-POST `_flowRun` contract.
- **[`sdk-methods.json`](./sdk-methods.json)**: one method stub per entry (name, params, cypher/runVia/flowRun, returns, `requiresKey`, `playgroundTryable`, `docPath`/`docsUrl`) for SDK codegen.
- **[`docs/CATALOG.md`](./docs/CATALOG.md)**: the human-readable table.

All scripts are **Node stdlib only**: no dependencies, no build step.

## License

[MIT](./LICENSE) © 2026 viaGraph B.V. (Whisper Security).
