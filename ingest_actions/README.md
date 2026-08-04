# Ingest actions

YAML rules applied to every event as it is written — to uploads, the HTTP ingest API,
the Splunk HEC shim, syslog, NetFlow and every collector alike, because all of them
funnel through `pipeline.write_stream`.

Four verbs:

| action   | what it does                                                              |
|----------|---------------------------------------------------------------------------|
| `drop`   | the event is never stored (counted on `/health` and on the batch row)      |
| `mask`   | redacts or pseudonymises a field, **and sweeps the value out of `raw`**    |
| `route`  | rewrites attribution — `vendor` / `product` / `log_type` / `raw["_index"]` |
| `sample` | keeps a deterministic 1-in-N subset, whole entities at a time             |

The `logsource:` / `detection:` block is **byte-for-byte a detection rule's** — the same
Sigma subset, evaluated by the same `app/detection/engine.py` matcher. There is no second
matching language.

## Three things worth knowing before you write one

1. **A rule with neither `logsource:` nor `detection:` is rejected at load.** A
   match-everything `drop` is total data loss, so it is refused rather than obeyed.
2. **Masking rewrites the stored identity.** `dedup_hash` is derived from the *masked*
   event, deliberately: hashing the pre-mask event would make an indexed column a
   side channel for the value the mask exists to remove. The cost is that changing a
   mask rule changes the identity of everything ingested afterwards, so that source
   re-inserts instead of dedupping.
3. **Masking is typed.** `src_ip`/`dst_ip` are `inet` columns and the ports and byte
   counts are integers, so a mask cannot write `"***"` into them — `redact` nulls them
   and `hash` maps an address deterministically into `100.64.0.0/10` (RFC 6598) so the
   column stays a valid `inet` and "same host" stays joinable. For the same reason a
   `mask.patterns` entry may only target a **text** column: a regex substitution
   produces a string, and one bound to `%(src_ip)s::inet` would abort the whole batch.
   Anonymising an address is `mask.fields`, not a `\d+$` pattern.
4. **`scrub` matches short values on token boundaries.** A masked value is swept out of
   `raw` and the sibling text columns. A value of 8+ characters is replaced as a plain
   substring; a shorter one — `jdoe`, `admin`, `root`, which is most of them — only
   where it stands as a whole token, so `jdoe` in a URL is redacted while `jdoexyz`
   (a different account) and `8080` (containing `80`) are left alone.

## Watch it

`/health` reports `ingest_actions`: rules loaded, how many events each rule has dropped
or changed, and `load_errors`. Check it after every edit — **a dropped event leaves no
row behind**, so those counters are the only trace it ever existed, and a rule that is
not loaded is silently filtering nothing at all.

`load_errors` covers all three ways a rule fails to take effect, because each of them
looks identical from the outside — zero rules running:

* the rule is malformed or names an unknown verb;
* a document has no `action:` key at all (`actions:` is the usual typo);
* **the rules directory does not exist.** `INGEST_ACTIONS_DIR` defaults to the
  *relative* `ingest_actions`, resolved against the process working directory — so a
  rule verified from the repo root loads nothing under a systemd unit with a different
  `WorkingDirectory`, or in a container with a different workdir. Set it to an absolute
  path in production.

Files are `*.yml` / `*.yaml` in this directory; multiple documents per file are fine.
Set `INGEST_ACTIONS_DIR` to point somewhere else.
