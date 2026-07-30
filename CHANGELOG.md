# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-07-29

### Fixed

- **vuln_verifier: HMAC signing didn't include query parameters for GET requests**
  — The `_sign_hmac_request` was called with `query_params=None, body=None`,
  meaning the HMAC signature only covered `timestamp` and `app_key` while the
  server-side also included query params. This caused M10 (SSRF) and M12 (open
  redirect) test cases to return 401. Fixed by extracting query params from the
  URL and passing them to the signing function.

- **vuln_verifier: `url.replace('http://', '')` stripped embedded URLs in query params**
  — The naive string replacement removed all occurrences of `http://`, including
  those inside query parameter values (e.g. `url=http://172.20.0.11:...` became
  `url=172.20.0.11:...`). Switched to `urllib.parse.urlparse` for correct URL
  decomposition that only strips the scheme prefix.

- **vuln_verifier: `json.dumps` added spaces not matching Node.js `JSON.stringify`**
  — Python's `json.dumps()` default adds spaces after separators (`{"key": "value"}`)
  while Node.js `JSON.stringify` produces compact output (`{"key":"value"}`).
  Added `separators=(",", ":")` to match the server-side format.

- **modern-app: `app.set('query parser', 'simple')` broke NoSQL injection tests**
  — The simple query parser keeps `username[$ne]` as a flat string key instead of
  the nested object `{username: {$ne: ...}}` that MongoDB expects. This would have
  broken M4/M5 test cases. Reverted with a comment explaining why the default `qs`
  parser must be kept.

- **vuln_verifier: duplicate auto-signing code in `_http_request` / `_http_request_no_redirect`**
  — The signing logic was duplicated between the two HTTP functions, risking
  divergence. Extracted into shared `_auto_sign_request()` helper.

- **vuln_verifier: unused `NoRedirectHTTPSHandler` class**
  — Removed dead code that was defined but never used in the opener.

### Added

- **vuln_verifier: `_parse_qs_brackets()` for Express-compatible query string parsing**
  — New helper that parses bracket notation like `username[$ne]=x` into nested
  objects matching Express's `qs` parser, ensuring HMAC signatures are computed
  over the same parameter structure the server uses.

- **admin-panel: internal service-to-service RSA signature bypass**
  — `verify_rsa_signature` now skips RSA verification for requests carrying
  `__admin_token`, `X-Admin-Token`, `X-Internal-Request`, or originating from
  `172.20.0.x` IPs. This enables legitimate BFF gateway proxying and preserves
  the intentional V12 header-backdoor vulnerability.

- **bff-gateway: internal service-to-service RSA signature bypass**
  — Similar bypass for `__admin_token` query param and `172.20.0.x` internal IPs,
  allowing the BFF gateway to proxy requests to admin-panel without requiring
  external RSA signatures on internal traffic.

- **pyproject.toml: `cryptography>=42.0.0` dependency**
  — Required for RSA-SHA256 request signing in the verifier.

### Test Results

All 50 vulnerability verification test cases pass (100% rate):
- S1 subdomain_discovery: 5/5
- S2 multi_entry_bypass: 3/3
- S3 hidden_param_detection: 7/7
- S4 modern_vulns: 15/15
- S5 info_leak: 6/6
- S6 bff_vulns: 3/3
- S7 infrastructure: 3/3
- S17 microservice_path_normalization_bypass: 4/4
- S18 admin_whitelist_suffix_bypass: 4/4
