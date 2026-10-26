# Plan: replace `parsedmarc` with an in-repo DMARC parser

Status: DRAFT — to be executed later on a single feature branch.
Owner: silpol
Branch: `feature/drop-parsedmarc` (git-flow feature, branched from `develop`)

---

## 1. Why

`mailgun-mail-store` uses `parsedmarc` for exactly one call —
`parsedmarc.parse_report_file(path, offline=True)` — and reads only a handful of
fields from the result. In exchange it pulls ~80 transitive packages
(elasticsearch, opensearch, kafka, boto3, azure-*, google-api-*, msgraph, …),
none of which the app uses. Those are `parsedmarc`'s output-backend
dependencies.

Concrete costs this imposes today:

- `parsedmarc` hard-requires `elasticsearch < 7.14` and `elasticsearch-dsl == 7.4.0`,
  which cap `urllib3 < 2`, which strands the app on urllib3 1.26.x — the source
  of the 5 standing security alerts that cannot be cleared by bumping.
- A large, mostly US-cloud-SDK supply-chain surface for an app that only parses
  XML and POSTs to one HTTP endpoint.
- Recurring Dependabot/pip-compile conflicts whenever any of those transitive
  pins moves.

Removing `parsedmarc` collapses the direct dependency set to roughly
**flask, gunicorn, requests, sentry-sdk** (+ stdlib for parsing), lifts the
urllib3 cap (nothing else pins `< 2`), clears the 5 alerts, and removes the
`elasticsearch`/`elasticsearch-dsl`/`urllib3` Dependabot ignores as no longer
needed.

## 2. The contract to preserve (do NOT change app.py's notification logic)

The replacement module must expose a function with the same call shape and
return a dict (or list of dicts) carrying these exact keys, so that
`check_pass_fail_unknown`, `_check_aggregate_report`, and
`_notify_forensic_report` in `app.py` keep working **unchanged**.

Top level (per report):
- `report_type`: `"aggregate"` or `"forensic"`
- `report`: dict (see below)

Aggregate `report`:
- `policy_published`: `{ "domain": str }`
- `report_metadata`: either `{ "begin_date": ..., "end_date": ... }`
  or `{ "date_range": { "begin": ..., "end": ... } }`
  (app.py already handles both via `_safe_get` fallbacks)
- `records`: list of:
  - `policy_evaluated`: `{ "dkim": "pass"|"fail"|..., "spf": "pass"|"fail"|... }`
  - source IP available as `source.ip_address` OR `row.source_ip`
    (app.py tries `source.ip_address` first, falls back to `row.source_ip`)

Forensic `report`:
- `reported_domain`: str
- `arrival_date_utc` (preferred) or `arrival_date`: str
- `auth_failure`: list[str]
- `source`: `{ "ip_address": str }`
- `delivery_result`: str

Call shape to preserve:
- `parse_report_file(path, offline=True)` — `offline` kept for signature
  compatibility but is a no-op (we never enrich).
- May return a single dict or a list/tuple of dicts (app iterates either).

## 3. Phases

### Phase 0 — confirm whether forensic (RUF) reports actually arrive  [GATE]
This decides how much of the forensic path we must build for real vs. stub.

1. Scan history for any non-aggregate payloads:
   - `python3 dmarc_fail_scan.py archive/` and `… failed/` already parse only
     aggregate XML; anything that is NOT aggregate XML will show as a parse
     error / be skipped. Inventory those.
   - Additionally grep the archive for forensic markers:
     `for f in archive/* failed/*; do …` — look for `message/feedback-report`,
     `Feedback-Type: auth-failure`, or `.eml`/`message/rfc822` payloads vs the
     usual `<feedback>` aggregate XML.
2. Check the DMARC DNS record for a `ruf=` tag:
   `dig +short TXT _dmarc.talentmilesapp.pro` — no `ruf=` means no forensic is
   even requested, and most receivers don't send it regardless.

Decision:
- If **aggregate-only** (expected, based on the Sept-2025 investigation where
  every archived report was aggregate from Google/Outlook/Yahoo):
  build the aggregate parser fully; make the forensic branch a safe fallback
  (parse best-effort; if it can't, route the file to `failed/` exactly as the
  current `except` does, so nothing is silently lost).
- If **forensic does arrive**: build the forensic parser for real (RFC 5965
  AFRF / message-feedback-report), with fixtures from the real samples found in
  step 1.

### Phase 1 — aggregate parser (the easy, mostly-done half)
1. New module `dmarc_parser.py` at repo root. Reuse the proven logic already in
   `dmarc_fail_scan.py` (`iter_xml_blobs`, the XML walk) — it already handles
   `.zip` (possibly multi-member), `.xml.gz`, and `.xml`.
2. Implement `parse_report_file(path, offline=True)` that, for each XML blob:
   - detects aggregate by root `<feedback>` containing `<report_metadata>` /
     `<record>`
   - emits a dict matching the aggregate contract in §2, including BOTH the
     `source.ip_address` shape (preferred) so app.py's primary path is used
   - returns a list when a container holds multiple reports
3. Preserve current failure semantics: malformed/empty XML should raise (so the
   app's `except` quarantines to `failed/`), matching today's behavior — do not
   silently swallow, or the heartbeat's quarantine signal breaks.

### Phase 2 — forensic parser (scope set by Phase 0)
1. If building for real: parse the forensic report (RFC 5965). Forensic reports
   are a MIME `multipart/report; report-type=feedback-report` message with a
   `message/feedback-report` part (the AFRF fields: `Arrival-Date`,
   `Source-IP`, `Auth-Failure`, `Reported-Domain`, `Delivery-Result`) plus the
   original `message/rfc822`. Use stdlib `email` to parse; map fields to the
   forensic contract in §2.
2. If stubbing: detect "not aggregate XML", attempt a minimal forensic field
   extraction, and on any uncertainty raise → file goes to `failed/`. Add a
   heartbeat note so quarantined forensic reports are visible rather than lost.

### Phase 3 — swap into app.py
1. Replace `import parsedmarc` with `import dmarc_parser`.
2. Replace the one call site `parsedmarc.parse_report_file(file_path, offline=True)`
   with `dmarc_parser.parse_report_file(file_path, offline=True)`.
3. Leave `check_pass_fail_unknown`, `_check_aggregate_report`,
   `_notify_forensic_report`, `_safe_get`, `_format_report_date`,
   `_send_notification_email` UNCHANGED — they already match the §2 contract.
4. Keep `offline=True` in the call for signature parity / clarity.

### Phase 4 — tests
1. Existing suite mocks `app.parsedmarc.parse_report_file`
   (e.g. test_integration.py, test_unit.py). Re-point those patches to
   `app.dmarc_parser.parse_report_file`. The asserted dict shapes stay the same
   because the contract is preserved.
2. Add `tests/test_dmarc_parser.py`: unit tests over real fixture files —
   aggregate pass/fail/mixed, multi-member zip, gz, plain xml, malformed/empty
   (must raise), and (if Phase 0 = forensic) at least one real forensic sample.
   Reuse the builder style already in `tests/test_dmarc_fail_scan.py`.
3. Target: full suite stays green (currently 189), and the new parser has
   direct coverage independent of `app`.

### Phase 5 — dependencies
1. Edit `requirements.in`: remove `parsedmarc`. Expected direct set becomes
   `flask`, `gunicorn`, `requests`, `sentry-sdk`.
2. Regenerate the lock: `pip-compile --no-strip-extras requirements.in -o requirements.txt`.
   Expect the lock to shrink from ~80 packages to a handful, and `urllib3` to
   float to 2.x (no more `< 2` cap).
3. `.github/dependabot.yml`: remove the `urllib3`, `elasticsearch`, and
   `elasticsearch-dsl` ignore entries — they exist only because of parsedmarc.
   Keep the `groups` config.
4. Confirm nothing else imports a now-removed package (grep app.py + scripts;
   they only import flask, requests, sentry_sdk, stdlib).

### Phase 6 — CI / validation / deploy
1. `submit-pypi` (pip-compile validation) should pass trivially on the tiny lock.
2. CodeQL: re-scan; the 5 urllib3 alerts should disappear once urllib3 moves to
   a 2.x release without the standing advisories.
3. Run the full pytest suite; run the app once against a real archived report to
   confirm a notification is produced byte-compatibly with the old path
   (diff the email subject/body against a parsedmarc-era sample).
4. On deploy, no infra change needed; it's a code+deps change. Note: this also
   removes ~75 packages from the runtime image — smaller attack surface, faster
   cold installs.

## 4. Risk register & rollback
- **Highest risk: forensic format fidelity.** Mitigated by Phase 0 (likely
  aggregate-only) and by the "raise → failed/" fallback that preserves the
  current no-silent-loss behavior. If forensic turns out to be common and
  messy, keep parsedmarc on a fallback branch and ship aggregate-only first.
- **Contract drift:** any field the app reads that the new parser omits = a
  broken notification. Mitigated by §2 being explicit and by Phase 6 step 3
  (byte-diff against a known-good parsedmarc-era notification).
- **Compression/edge cases:** multi-member zips, empty gz (the Aug-29 stubs),
  odd encodings. Covered by Phase 4 fixtures, reusing dmarc_fail_scan's tested
  reader.
- **Rollback:** the change is isolated to `dmarc_parser.py` + one import line +
  requirements. Reverting the feature branch restores parsedmarc fully.

## 5. Acceptance criteria
- [ ] `parsedmarc` absent from `requirements.in` and the regenerated lock.
- [ ] `urllib3` resolves to a 2.x release; the 5 standing alerts cleared.
- [ ] `elasticsearch`/`elasticsearch-dsl`/`urllib3` ignores removed from dependabot.yml.
- [ ] Full pytest suite green; new `tests/test_dmarc_parser.py` covers the parser.
- [ ] A real archived aggregate report produces a notification identical in
      subject/body to the parsedmarc-era output.
- [ ] Forensic reports either parsed correctly (if they arrive) or safely
      quarantined to `failed/` with a heartbeat-visible signal (if they don't).
- [ ] `submit-pypi` and CodeQL green on the feature PR.

## 6. Effort estimate (rough)
- Aggregate parser + swap + test re-pointing: ~half a day (logic largely exists).
- Forensic real parser + fixtures (only if Phase 0 says so): +0.5–1 day.
- Deps regen + CI shakeout: ~1–2 hours.
Single feature branch is appropriate; no need to split.