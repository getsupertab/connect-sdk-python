# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-07-15

First stable release. The SDK is now aligned with the TypeScript SDK's feature
set (relay analytics, capture-v2 signals, the self-report status endpoint) and
its public surface is considered stable under semantic versioning.

### Added

- **Self-report status endpoint.** `handle_request()` answers the platform probe
  at `GET /.well-known/supertab/status`. On a valid backend-signed challenge
  (an ES256 JWT scoped to the site origin with `purpose: status-probe`) it
  returns a `HandlerAction.RESPOND` result with the live SDK config —
  `runtime`, `component: {"kind": "python-sdk", version}`, `enforcement`, and
  `eventReporting`. Without a valid challenge it returns a minimal
  `{"supertab": true}` `404`. The probe short-circuits ahead of token
  verification, bot detection, and analytics — no event is emitted.
- **`HandlerAction.RESPOND`** and the `RespondHandlerResult` type — a fully
  formed response the caller serves verbatim without contacting origin.
- **Relay analytics** (off by default; `analytics_enabled=True`). One event per
  request to `/ingest/events`, authenticated with the merchant `api_key`; the
  backend derives merchant identity, so no merchant identifier is sent. Emits
  `schema_version: 2` capture-v2 spoof-detection signals. Fire-and-forget and
  fail-open — analytics can never block, slow, or alter request handling.
- **`analytics_base_url` config option, plus `SupertabConnect.set_analytics_base_url()` /
  `get_analytics_base_url()`.** Points the analytics ingest relay at a specific
  host, independent of `set_base_url` (which stays the base for token
  acquisition / JWKS / verification). Mirrors the existing `base_url` pattern.
- **`HandleRequestContext`** for passing CDN-supplied per-request signals
  (`source_cdn`, `client_ip`, `request_id`, `request_country`, `request_asn`,
  `tls_fingerprint`, `cdn_signals`) onto the analytics event.
- **`User-Agent` header** (`supertab-connect-sdk-python/<version>`) on all
  outbound calls to the Connect backend.

### Changed

- **Analytics defaults to the dedicated ingest service
  (`https://ingest-connect.supertab.co`)** rather than the API host. Only
  affects deployments with `analytics_enabled=True`; the `/ingest/events` path
  and payload are unchanged — traffic just moves to the standalone service.
  Non-prod / local setups should call `set_analytics_base_url()` to avoid
  emitting to prod.
- **`EnforcementMode` values renamed** to match the backend and the TS SDK:
  `SOFT` → `OBSERVE`, `STRICT` → `ENFORCE` (enum members and string values).
  The default was already observe-only — a rename, not a behavior change.

### Fixed

- **Analytics emits are drained on close.** The HTTP analytics transport now owns
  its own client and in-flight emit tasks; `await client.aclose()` (or exiting an
  `async with` block) flushes outstanding emits within a bounded timeout before
  closing the client. Previously a fire-and-forget emit scheduled just before
  `aclose()` could run afterwards, lazily recreate a fresh HTTP client that was
  never closed (a leak), and race process shutdown. Emission remains fire-and-forget
  and fail-open on the request path.
