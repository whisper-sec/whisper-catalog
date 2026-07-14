# whisper-catalog

**The portable query catalog for [whisper.security](https://whisper.security).**
One machine-readable file, [`catalog.json`](./catalog.json), describes every graph query and read flow the Whisper security graph exposes, so any surface (an MCP server, an SDK, a CLI, an LLM tool-belt) can offer them without re-discovering the wire format.

Every entry is **provenance-backed**: its shape (columns, arguments) was taken from a live probe of the endpoint, not guessed.

---

## Keyed by design

The whisper.security graph is a **keyed** surface: supply your API key (unlimited). It's Cypher; Cypher needs a key. Every entry in this catalog runs Cypher, so every entry is keyed. That's the whole rule.

```bash
curl -s https://graph.whisper.security/api/query \
  -H 'content-type: application/json' \
  -H 'X-API-Key: whisper-…' \
  --data '{"query":"CALL whisper.identify([$v]) YIELD host, vendor_id, canonical_name, category, roles, host_class, band","parameters":{"v":"api.openai.com"}}'
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

With your key, queries are **unlimited**.

## Playground: a taste, not a tier

You *can* run the read verbs without a key, but only as a **rate-limited playground**: **100 requests / window** (`x-ratelimit-limit: 100`; every request, even a refusal, spends one). It works, then it `429`s, then it resets. It exists to give new users and agents a taste of the graph in one line, **never to build a product on.** If it is Cypher, it needs a key.

Only the single-request **direct read verbs** are practical to sample this way (marked `playgroundTryable: true`). The multi-step flows are dozens of `CALL`s each (a single deep flow would exhaust the playground cap mid-run), and writes are keyed always. So `playgroundTryable` is `false` for every flow and for `whisper.submit`.

## The genuine keyless half of Whisper

Whisper *is* two-tier, but the keyless half is **not** in this catalog. It's the non-Cypher **identity** tools: `verify` (prove an agent/domain identity) and `rdap` (IP-anchored registration lookup). Those make no graph query, so they carry no key and no rate cap. This catalog is the **graph** surface (Cypher), and the graph is keyed.

| | Playground (no key) | Keyed (your API key) |
|---|---|---|
| **What** | A *taste* of the direct read verbs: identify, assess, explain, origins, history, … | The whole graph: every read verb, every multi-step investigation flow, and the `whisper.submit` write channel |
| **Limit** | **100 requests / window** (every request, even a refusal, spends one) | **Unlimited** |
| **For** | Kicking the tyres; a new agent's first look | Production. Everything real. |

A keyless **write** attempt is refused with a clear message (`a write channel requires an attributable API key … preserves K-anonymity`); it fails helpfully, never silently.

## What's in the catalog

`catalog.json` holds **29 entries**, **all keyed** (it is Cypher). **13** are `playgroundTryable` single-request direct reads; the other **16** are the multi-step flows and the one write channel (`whisper.submit`). Two execution modes:

- **`direct`**: a single Cypher `CALL` you can run against the endpoint as-is. The entry carries the exact `cypher`, its `params`, and the `columns` it returns.
- **`flow`**: a multi-step read investigation (e.g. `attack-surface`, `indicator`, `typosquat`) orchestrated by a `run_workflow` runner over the same endpoint. The entry carries the anchor step's live columns and the analyst prompt.

Each entry:

```jsonc
{
  "id": "identify",
  "title": "Vendor / Operator Identity (whisper.identify)",
  "purpose": "Name the vendor and operator role behind a host or IP in one call.",
  "category": "Infrastructure, supply-chain & compliance / Research & OSINT",
  "inputs": [{ "id": "value", "kind": "any", "paramName": "v", "default": "api.openai.com" }],
  "exec": {
    "mode": "direct",
    "cypher": "CALL whisper.identify([$v]) YIELD host, vendor_id, canonical_name, category, roles, host_class, band",
    "params": { "v": "api.openai.com" }
  },
  "access": "keyed",
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

- **[`mcp-tools.json`](./mcp-tools.json)**: every graph query as an MCP tool descriptor (JSON-Schema `inputSchema` per tool), each marked `_requiresKey: true` and carrying `_playgroundTryable` so a surface can offer a "try without a key" hint on the direct-read verbs.
- **[`sdk-methods.json`](./sdk-methods.json)**: one method stub per entry (name, params, cypher/runVia, returns, `requiresKey`, `playgroundTryable`) for SDK codegen.
- **[`docs/CATALOG.md`](./docs/CATALOG.md)**: the human-readable table.

All scripts are **Node stdlib only**: no dependencies, no build step.

## License

[MIT](./LICENSE) © 2026 viaGraph B.V. (Whisper Security).
