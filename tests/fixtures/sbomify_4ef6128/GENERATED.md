# sbomify CRA Article 14 reporting API — real responses on synthetic data

Generated 2026-11-13, 05:01–05:10 UTC (`date -u` at start: `Fri Nov 13 05:01:37 AM UTC 2026`; last API call 05:09:29 UTC;
teardown done 05:10:17 UTC). Machine: x86_64 Chromebook Linux, podman 4.3.1, no podman-compose (plain `podman pod`).

These are HTTP responses of a local sbomify instance, saved byte for byte with
`curl -s -D <headers> -o <body>` (never parsed and re-written). All data is synthetic. No sbomify source file
is copied here: the scripts in `scripts/` are ours and only call sbomify's HTTP API or its Django shell.

## Image and commit

| Item | Value |
|---|---|
| Image | `ghcr.io/sbomify/sbomify@sha256:bd286464fddc0cb3d3c9c5b1ed5762df13cb0f2bd8b52f03ce7120bbcc2de8a2` (OCI index; tag `latest` when read on 2026-11-13 ~05:02 UTC) |
| linux/amd64 manifest | `sha256:a82ca8673c1ee42b9660888a674ed08b4ba0e594fde57711fc2a13ad79119065`, local image id `01d028a0a6e6…` |
| Label `org.opencontainers.image.revision` | `4ef61281e69d693e3560185bf81ec5474179ea98` |
| Label `org.opencontainers.image.version` / `ref.name` / `created` | `master-4ef6128` / `master` / `2026-11-12T12:48:28Z` |
| Matches commit 4ef6128 | **yes** (read from the image config labels, not assumed) |
| postgres | `docker.io/library/postgres:17-alpine`, digest `sha256:d3244e8ce3f165ee3c93d9c4a4b1d0fe48b3a89e2287b717fdcbbde92d405065` |
| valkey | `docker.io/valkey/valkey:9-alpine`, digest `sha256:bf09d58e96d6b4524a15396b65b242bbe18beebbcc15a04d8ee75ddac62fae0b` |

There is no sha tag on ghcr.io (1233 tags listed: `latest`, `vX` releases, `pr-NNN`, `sha256-…` signatures);
the match was found by reading the labels of `latest` (v26.11.0 is revision `57384506…`, 2026-11-03).

Run mode: production settings (`DEBUG` unset), single gunicorn/uvicorn worker, backend published only on
`127.0.0.1:18000`; no caddy, worker, scheduler, S3 or Keycloak. Requests carry `X-Forwarded-Proto: https`
(what caddy sends; without it production settings redirect to HTTPS). `BILLING=False`.

## Paths (correction to the brief)

The router is mounted under `/compliance`, so the real paths are `/api/v1/compliance/cra-reports…`
(measured from `/api/v1/openapi.json`), not `/api/v1/cra-reports`. v1 answers with
`deprecation: @1787702400` (= 2026-08-26T00:00Z) and `link: </api/v2/docs>; rel="successor-version"`;
the same GETs were therefore also captured under `/api/v2/compliance/cra-reports…` in `v2/`.
v1 and v2 bodies were compared with `cmp` on report, filing and srp files: byte-identical.

## What was captured

Reports (ids are sbomify's):

| Report | Kind | Product | Filings captured |
|---|---|---|---|
| `s1AfwOnAgUPN` | vulnerability (advisory `wYJ6OfmjjUKk`, CVE-2099-0001) | Acme Smart Thermostat T100 (synthetic) | early_warning, notification, intermediate ×2, final_report, users_informed (6) |
| `BA1rXunidkQE` | incident | Acme Gateway Hub G2 (synthetic) | early_warning, notification (2) |
| `JBuMp9bYI2aN` | vulnerability, minimal (same advisory) | Acme Door Sensor D1 (synthetic) | early_warning (1) |
| `qIRd1SyRrUvq` | incident, order probe, created **after** all v1 captures | Acme Gateway Hub G2 (synthetic) | final_report only (see probe 19) |

Top-level files (v1, final state, captured 05:08:54 UTC):
- `list.json` — GET list (3 reports; the order probe did not exist yet).
- `report_<id>.json` — GET each report.
- `filing_<report>_<stage>_<n>.json` — GET every filing with its `snapshot` (9 filings, all 5 stages).
- `srp_<id>.json` — GET `/srp` without `stage` (server picks next due stage, or `final_report` once closed);
  `srp_<id>_stage_<stage>.json` — the same with `?stage=early_warning|notification|final_report`.
- `headers/<name>.headers` — response headers for every saved body (response headers only: curl `-D` does not
  write the request, so no Authorization header is in them; nothing needed redacting).
- `requests/` — the JSON bodies we sent (`*.request.json`) and the responses to the create/PATCH/POST-filing
  calls (`*.json`), i.e. the values entered.
- `errors/` — refused requests and two probes (below); their request bodies are in `requests/`.
- `v2/` — the same GETs under `/api/v2` at 05:09:28–29 UTC (list holds 4 reports, including the order probe).
- `scripts/` — everything used; `scripts/calls_*.log` lists every call with its HTTP status; `scripts/state.json`
  holds the ids.
- `podman_state.txt` — `podman ps -a`, `podman volume ls`, `podman images` at start, before and after teardown.

Field coverage: the 39 SRP field ids appear in the srp layouts; every one of the 39 has a non-empty `value`
in at least one saved srp file (vulnerability fields from `s1AfwOnAgUPN`, incident fields from `BA1rXunidkQE`;
counted by script over all `srp_*.json`, never-valued list empty). In report `values`: vulnerability final state
27 JSON fields (17 common + 10 vulnerability) plus the 3 date columns; incident 24 JSON fields (17 common + 7
incident) plus 2 date columns (`measure_available_at` is not an incident field). Snapshots: the 9 filing
snapshots are pairwise different except `final_report` = `users_informed` on `s1AfwOnAgUPN`
(expected: after the final report the report refuses edits, error 12).
`srp_reference` is empty on `filing_s1AfwOnAgUPN_intermediate_2.json` and set on all other kept filings.

## Commands, in order

1. `podman pull` of the three images above by tag/digest (`nice -n 19`).
2. `scripts/start_stack.sh` — pod + volume `sbomify-cra-pg` + postgres + valkey + `python /code/bin/release.py`.
   **Failed** (see Problems 1); then `scripts/migrate_workaround.sh` (dropdb/createdb, `manage.py migrate plugins 0004`,
   `release.py`, start backend). Backend health `GET /UuPha8mu/` 200.
3. **Non-API (Django shell)** `podman exec -i sbomify-cra-backend python manage.py shell < scripts/bootstrap_shell.py`:
   user `psirt-demo` / `psirt@example.com` (unusable password), workspace "Example Widgets GmbH (synthetic)",
   owner membership, workspace-scoped personal access token. Reason: a fresh install has no login without
   Keycloak, and tokens are minted from a session.
4. `python3 -I scripts/drive_api.py setup . <token file>` — API: 3 products (`POST /api/v1/products`), advisory
   (`POST /api/v1/advisories/`, identifier `CVE-2099-0001`, CVSS 8.1, products T100 and D1), and error 01.
5. **Non-API (Django shell)** `scripts/mark_exploited_shell.py`: set the advisory vulnerability's
   `exploitation_status` to `known_exploited`. Reason: a vulnerability report requires it (error 01 shows the
   refusal), and a grep of the 4ef6128 source found no API, form or service that writes this field (only readers).
6. `python3 -I scripts/drive_api.py reports . <token file>` — everything else through the API: create, PATCH
   values/dates (always with a fresh `revision`), POST filings with explicit `filed_at`, errors, captures.
7. `python3 -I scripts/drive_api.py afterwards . <token file>` — order probe (19).
8. `scripts/capture_v2.sh . <token file>` — v2 captures.
9. Teardown: `podman pod rm -f sbomify-cra`, `podman volume rm sbomify-cra-pg`, `podman rmi` of the sbomify,
   postgres, valkey images and of `localhost/podman-pause:4.3.1-0` (built by `podman pod create`).
   The 20 volumes, 1 container and 13 images present at start are untouched (`podman_state.txt`).

The token lived only in a 0600 file in the session scratchpad, passed to curl as `-H @file`; deleted after use.
`grep -rlF -f <token file>` over this folder returned nothing (rc=1) before the file was deleted.

## Values entered (summary; exact bodies in `requests/*.request.json`)

CVE id: `CVE-2099-0001` (year 2099, clearly not a real CVE); EUVD id `EUVD-2099-0001`; SRP references
`SRP-<stage>-2099-000NNN`; all names "(synthetic)", e-mail `psirt@example.com`.

- Vulnerability `s1AfwOnAgUPN`: aware_at 2026-11-09T07:30Z, occurred_at 2026-11-08T22:15Z (at creation);
  measure_available_at 2026-11-11T16:00Z (set by PATCH before intermediate 2).
  Before early warning: title, summary, member_states, product_name, product_version, product_type,
  product_class, cve_id, attack_vector, measure_expected=Yes, sensitivity. Before notification:
  general_information, component_name, product_category, end_of_support, user_action, euvd_id, product_version
  changed. Before intermediate 1: malicious_actor, vulnerability_severity, attack_vector changed. Before
  intermediate 2: measure_expected=No, measures_taken, measure_details + date. Before final report:
  measures_for_users, vulnerability_impact, pec, pec_delay_reason, further_information, ar_note.
  Filed_at: EW 2026-11-09T18:00Z, N 2026-11-11T09:00Z, IR1 2026-11-12T10:00Z, IR2 2026-11-12T15:00Z (no reference),
  FR 2026-11-13T04:30Z, UI 2026-11-13T04:45Z. sbomify prefilled title, summary, product_name, cve_id from the
  advisory at creation; our PATCHes overwrote them.
- Incident `BA1rXunidkQE`: aware_at 2026-11-12T06:00Z, occurred_at 2026-11-12T02:40Z. Before early warning 8 fields
  (incl. suspected_unlawful, product_type=Default); before notification all remaining 16 incident+common fields.
  Filed_at EW 2026-11-12T12:00Z, N 2026-11-13T03:00Z.
- Minimal `JBuMp9bYI2aN`: aware_at 2026-11-13T01:00Z only; values exactly the early-warning required set
  (title, summary, member_states, product_name, product_version; the prefilled `cve_id` was cleared by sending it
  empty). One early_warning filing 2026-11-13T04:50Z.

## Error responses and probes (`errors/`)

| File | Request | Status |
|---|---|---|
| error_01 | create vulnerability report before the CVE is known_exploited | 400 |
| error_02 | PATCH values with unknown key `unknown_field` | 400 |
| error_03 | PATCH `product_type: "Medium"` (bad choice) | 400 |
| error_04 | PATCH `cve_id` on an incident (other kind's field) | 400 |
| error_05 | PATCH date column `vulnerability_aware_at` inside `values` | 400 |
| error_06 | PATCH title of 256 chars (max 255) | 400 |
| error_07 | PATCH with a stale `revision` | 409 |
| error_08 | PATCH without `revision` | 422 (ninja validation shape, `error_code: VALIDATION_ERROR`) |
| error_09 | second early_warning filing | 409 |
| error_10 | filing with stage `draft` | 400 |
| error_11 | intermediate filing after the final report | 409 |
| error_12 | PATCH after the final report | 409 |
| error_13 | `GET /srp?stage=intermediate` | 400 |
| error_14 | create with a naive `aware_at` (no timezone) | 422 |
| error_15 | create with kind `advisory` | 400 |
| error_16 / 17 | GET unknown report / unknown filing | 404 / 404 |
| probe_18 | PATCH with an undeclared top-level key `valuez` (plus a valid revision) | **200** — the key is ignored silently, nothing changes |
| probe_19a/b/c | new incident report; `final_report` filed with no earlier stage → **201**; then `early_warning` → 409 | stage order is not enforced: a final report can be the first filing, and it closes the report |

## Problems

1. **Fresh-install migration failure at 4ef6128.** On an empty database `bin/release.py` applied
   `vulnerability_scanning.0004_add_release_mapping_remove_old_models` (deletes `VulnerabilityScanResult`) before
   `plugins.0004_migrate_osv_results_to_assessment_runs` (a RunPython that loads that model; it depends only on
   `vulnerability_scanning.0001_initial`), which raised
   `LookupError: App 'vulnerability_scanning' doesn't have a 'VulnerabilityScanResult' model.`
   Measured once in this run (plan order in the log: vulnerability_scanning.0004 at plan line 591, plugins.0004 at 697).
   Workaround: recreate the DB, `migrate plugins 0004` first, then the full release script. Not reported anywhere.
2. Two steps have no API (Django shell used): user/workspace/token bootstrap, and setting `exploitation_status`.
3. The order probe report `qIRd1SyRrUvq` stays in v2/list.json; reports with filings cannot be deleted (by design).
4. `next_due.overdue` and list order depend on the clock at capture time (05:08:54 UTC for v1).
