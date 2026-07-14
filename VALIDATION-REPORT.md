# Validation Report: whisper.security query catalog

Endpoint under test: `POST https://graph.whisper.security/api/query` · body `{"query":"<cypher>","parameters":{…}}` · response `{columns, rows, statistics}` with **rows as objects keyed by column name**.

All findings below are grounded in live probes: a keyless boundary-map sweep (≤6 requests against the quota'd keyless surface) and a keyed shape-probe pass (one live `CALL` per anchor/verb, HTTP + columns + a sample row captured). No credential is printed; keys are redacted as `whisper-…`.

---

## Verify-item resolutions

### 1. Playground quota vs flow depth: does a deep flow exhaust the 100/window cap mid-run?
**Resolved: yes, which is exactly why flows are not playground-tryable; the catalog marks every entry keyed.**
Every keyless request (success **or** a 400 refusal) decrements `x-ratelimit-limit: 100` (observed 96→93 across the boundary sweep, refusals included). A flow's **anchor** step is a single request and *can* be sampled keyless, but a full flow is dozens of `CALL`s (`indicator` ≈ 80 query-steps / doLength 98, `blast-radius` ≈ 55 / 67, `attack-surface` 30 / 33), and a single deep flow can exhaust the 100/window playground cap mid-run. **Conclusion under Kaveh's rule:** it is Cypher, so it needs a key: every entry (flow and direct) is `access:"keyed"`, unlimited with a key. The keyless surface is only a rate-limited *playground* (a taste, never production). We therefore set `playgroundTryable:true` only for the single-request direct read verbs and `false` for every multi-step flow (and the write), and the README states the 100/window playground cap plainly.

### 2. Cognition-verb playground exposure: do the read verbs run with no key?
**Resolved: empirically yes, but only as the rate-limited playground; the catalog marks them keyed.** `identify` and `db.schema()` were directly confirmed runnable keyless in the boundary map; the remaining direct verbs (`assess`, `variants`, `walk`, `explain`/`whisper.explain`, `psl.tldPlusOne`, `psl.affiliation`, `origins`, `history`, `history.whois`, `asSet`, `lookupTorRelay`) are all `isRead:true` and returned HTTP 200 valid shapes in the shape-probe pass. The boundary sweep established the empirical fact: **arbitrary reads (including deep multi-hop `MATCH` traversals and the catalog verbs) run keyless, bounded only by 100/window; no read was depth- or complexity-refused.** **But that keyless window is the *playground*, not a product tier.** Under Kaveh's rule (if it is Cypher, it needs a key), every one of these verbs is `access:"keyed"`; because each is a single-request direct read, each is also `playgroundTryable:true` (you can taste it keyless in the 100/window playground). The genuine keyless half of Whisper is the non-Cypher identity ops (`verify`/`rdap`), which are not in this catalog. (`asSet` returns a valid shape but 0 rows because membership data is unpopulated, not a permission block.)

### 3. Two `explain()` forms: same procedure?
**Resolved: same engine, two projections; both live.** Bare `CALL explain($v)` returns the **full** column set: `indicator, type, available, cached, found, score, level, explanation, factors, sources, advisory`. `CALL whisper.explain($v) YIELD indicator, score, level, explanation, sources` returns the **restricted** projection of the same underlying threat scorer (identical verdict/score/level/explanation, fewer columns). Both confirmed for `v='paypal.com'` (score 0.0, level NONE, identical `sources[]`). The 9 flow anchors that use the bare `explain()` form and the direct `explain` catalog entry both point at this engine; the catalog's `explain` entry carries the `whisper.explain` YIELD as canonical and notes the bare full-column form in `exec.altForm`.

### 4. Two `history()` forms: columns and difference?
**Resolved: both live; one is a superset projection of the other.** Bare `CALL whisper.history($v)` **auto-yields 11 columns**: `indicator, type, queryTime, createDate, updateDate, expiryDate, registrar, registrant, country, nameServers, cached` (48 rows for paypal.com). `CALL whisper.history.whois($v) YIELD queryTime, createDate, updateDate, expiryDate, registrar, registrant, country, nameServers` is the **WHOIS-only projection**: the same per-snapshot timeline, dropping `indicator/type/cached`. Both are catalog entries (`history`, `history-whois`); `history` notes the `.whois` projection in `exec.altForm`.

### 5. Sample-entity residency in the current graph.
**Resolved: the at-risk / sparse defaults return live rows (with two honest caveats).**
- `theblackservicenetwork.com` → `whisper.assess` returned `label:malicious, band:CRITICAL, sub_labels:[malware,phishing], coverage:malicious-evidenced` (feed-source-count 4). **Resident.**
- `ickaoex.com` → `explain` returned `level:LOW`, listed in `hagezi-tif-full`. **Resident.**
- `DNS_ROOT_INSTANCE` / country `BR` → the anycast anchor returned `distinctLetters:8, totalInstances:47, globalCount:17, localCount:30, hostingAsns:4`. **Resident.** Per the flow's own guidance a 0-instance country is a CRITICAL sovereignty finding, not "no data".
- `AS13335` MOAS/`CONFLICTS_WITH` → the bgp-hijack anchor returned 50 prefix rows but `is_moas:false / conflicting_asn:null` on the sample; **MOAS/route-conflict data is sparse until the next route-collector refresh** (flagged in the flow prompt).
- `1.1.1.0/24` → route-health anchor returned `multi_origin:false, anycast:true, withdrawn:true`; the label queried is `PREFIX` (`db.schema()` lists `PREFIX` count 2.49M), matched fine. **Resident.**
- CNAME dangling-target layer (`subdomain-takeover`): the anchor returns subdomains, but the **CNAME layer is "prod-ahead"** (schema-ahead of populated data); catalog entry carries that caveat in `why`.

### 6. Response envelope for procedure CALLs: objects, not arrays?
**Resolved: identical to `MATCH`.** Every `CALL … YIELD` and bare `RETURN *` probe returned `{columns:[…], rows:[{col:val,…}], statistics:{rowCount, executionTimeMs}}` with **rows as objects keyed by their YIELD column names** (e.g. `{"host":"api.openai.com","vendor_id":"cloudflare",…}`), not positional arrays. The envelope is uniform across MATCH and procedure output.

### 7. `minSchema` engine-capability gate: where does it bite?
**Resolved: gate is console/engine-side, not at `graph.whisper.security`; the graph endpoint accepted every probe.** The flows declaring `minSchema:5` (`attack-path`, `attack-surface`) and `minSchema:4` (`blast-radius`, `indicator`, `infrastructure-mapping`, `typosquat`) all had their **anchor steps execute HTTP 200** against the live endpoint; the query endpoint applies no schema floor. `minSchema` is a **runner/engine capability floor** (a wrong-graph-that-looks-right guard) enforced by the `run_workflow` orchestrator, not by the raw graph API. The catalog preserves `minSchema` on each flow's `exec` so a runner can honor it; the raw `direct` entries carry no floor because the endpoint imposes none.

### 8. Control-plane boundary + LIMIT policy.
**Resolved (a): keyless control-plane call is cleanly refused, not 500, and no catalog flow reaches it.** `CALL whisper.agents({op:'list', args:{kind:'agents'}})` keyless → **HTTP 400** `anonymous callers cannot use the agent control plane; an attributable API key is required` (keyed → 200, real inventory). No catalog entry references `whisper.agents`; `validate.mjs` hard-fails if one ever does.
**Resolved (b): the endpoint accepts procedure `LIMIT`s well above 50.** The typosquat anchor materialized **160 rows** and the `variants`/`bgp-hijack`/`subdomain-takeover` probes returned 50 each, with no cap or rejection at the graph endpoint. The `LIMIT ≤ 50` convention is a client-side courtesy, not an endpoint constraint; procedure reads return their full result set.

---

## Per-entry access map

**Rule applied (Kaveh's definitive rule):** it is Cypher, so it needs an API key: **every entry is `access:"keyed"`** (unlimited with a key). Keyless is only a rate-limited *playground* (100/window; a taste, never production). `playgroundTryable` is the practical marker: **`true`** for single-request direct read verbs (samplable keyless in the playground), **`false`** for the write (`whisper.submit`) and for every multi-step flow (a deep flow would burn the keyless cap). Empirical note: the read verbs *do* run keyless, but only as that playground; our surfaces are keyed. Single-step reads → `exec.mode:direct` with the live Cypher + columns; multi-step read flows → `exec.mode:flow` (run via `run_workflow`). The `whisper.agents` control plane is **never** a catalog entry. The genuine keyless half of Whisper is the non-Cypher identity ops (`verify`/`rdap`), which are not in this catalog.

**Totals: 29 entries, all keyed. 13 `playgroundTryable:true` (single-request direct reads), 16 `false` (15 multi-step flows + 1 write).**

### Keyed: multi-step read flows (`mode:flow`), 15 · `playgroundTryable:false`
| id | anchor step | anchor columns (live) | minSchema |
|----|-------------|-----------------------|-----------|
| `anycast-dns-root-sovereignty` | overview | distinctLetters, totalInstances, globalCount, localCount, hostingAsns | none |
| `attack-path` | verdict | indicator, type, available, cached, found, score, level, explanation, factors, sources, advisory | 5 |
| `attack-surface` | verdict | (explain shape, as above) | 5 |
| `bgp-hijack-exposure` | prefixes | prefix, is_moas, conflicting_asn | none |
| `blast-radius` | classify | labels, name | 4 |
| `build-takedown-evidence-package` | verdict | (explain shape) | none |
| `discover-ai-agent-infrastructure` | ai_subdomains | hostname, ips | none |
| `indicator` | assess | host, label, band, sub_labels, coverage, evidence | 4 |
| `indicator-enrichment` | identity | attribute, value | none |
| `infrastructure-mapping` | operator | canonical_name, vendor_id, category, roles, host_class | 4 |
| `map-supply-chain-concentration` | concentration | provider, asn, region, country | none |
| `nameserver-hijack-dns-consistency` | nameservers | nameserver, ips, status | none |
| `route-health` | prefix-status | prefix, multi_origin, anycast, withdrawn | none |
| `subdomain-takeover` | subdomains | subdomain, ips | none |
| `typosquat` | registered | variant, method, confidence | 4 |

### Keyed: single-step read verbs (`mode:direct`), 13 · `playgroundTryable:true`
| id | cypher | columns (live) |
|----|--------|----------------|
| `identify` | `CALL whisper.identify([$v]) YIELD …` | host, vendor_id, canonical_name, category, roles, host_class, band |
| `assess` | `CALL whisper.assess([$v]) YIELD …` | host, label, band, sub_labels, coverage, evidence |
| `variants` | `CALL whisper.variants($v) YIELD …` | variant, method, exists, confidence |
| `walk` | `CALL whisper.walk($v) YIELD …` | coverage, host, nearest_known_vendors, no_atlas_match, siblings |
| `explain` | `CALL whisper.explain($v) YIELD …` (bare `explain()` = full cols, altForm) | indicator, score, level, explanation, sources |
| `psl-tldplusone` | `CALL whisper.psl.tldPlusOne($v) YIELD apex` | apex |
| `psl-affiliation` | `CALL whisper.psl.affiliation($v) YIELD …` | found, suffix, submitterOrg, submitterLogin, evidenceKind, confidence |
| `origins` | `CALL whisper.origins($v) YIELD …` | ip, confidence, methods, asn, asnName, kind |
| `history` | `CALL whisper.history($v)` (auto-yield) | indicator, type, queryTime, createDate, updateDate, expiryDate, registrar, registrant, country, nameServers, cached |
| `history-whois` | `CALL whisper.history.whois($v) YIELD …` | queryTime, createDate, updateDate, expiryDate, registrar, registrant, country, nameServers |
| `asset` | `CALL whisper.asSet($v) YIELD …` (string as-set name) | asSetName, memberAsn, sourceRir |
| `lookup-tor-relay` | `CALL whisper.lookupTorRelay($v) YIELD …` | indicator, found, fingerprint, exitAddressCount, source, ingestedAt |
| `db-schema` | `CALL db.schema()` | type, name, count, description, example, sourceLabels, targetLabels, fastPatterns, slowPatterns, bestPractices |

### Keyed: write channel, 1 · `playgroundTryable:false`
| id | cypher | why not playground-tryable |
|----|--------|-----------|
| `submit` | `CALL whisper.submit({kind:$kind, …})` | WRITE. Keyed like everything else, but never playground-tryable: anonymous callers are refused with a clear 400 (`a write channel requires an attributable API key … preserves K-anonymity`); with a key it passes auth and validates on `kind`. |

### Excluded (never a catalog entry)
`CALL whisper.agents({op:…})` is the agent **control plane**. Keyed-only, and not a graph query surface; it belongs to the separate whisper.online control API. `validate.mjs` fails the build if any entry references it.
