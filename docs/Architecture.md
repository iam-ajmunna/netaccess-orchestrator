# Architecture

## Core model

Only the process tree launched via `netaccess run` is affected. Everything else on the machine uses its normal path.

Isolation is implemented via:

1. Environment-variable proxying (`HTTP_PROXY` / `ALL_PROXY`) for cooperating apps
2. Per-session Network Extension capture scoped to the child PID/UID for non-cooperating binaries

No persistent modification of system DNS, default gateway, global routes, system proxy settings, or firewall rules.

## Diagnostic pipeline

```
Captive portal check
  → DNS (system + optional encrypted alt resolver)
  → Address selection (Happy Eyeballs RFC 8305)
  → TCP connectivity
  → Path / MTU
  → TLS (handshake, cert, SNI/ECH signals)
  → HTTP application test
  → Route / ASN analysis
  → Weighted-evidence classification
```

## Classification

Findings carry layer, weight, class hint, and optional supporting classes. Confidence is the normalized combination of primary weight, margin over the runner-up, and corroboration count. Guesses are never presented as facts.

## Transport selection (policy-as-code)

```
policy:
  - match: { destination_tag: sensitive }
    forbid_transport_tag: [untrusted]
  - prefer: lowest_latency
    within_ms: 200
  - prefer_tag: home
  - fallback: direct
```

Selection produces a full decision trail: which rules fired, which transports were dropped, and why the winner won.

## Health scoring

```
score(t) = EWMA(success_rate) * w1
         + normalize(1/latency) * w2
         + normalize(1/jitter) * w3
         - penalty(recent_failures)
```

Circuit breakers open after repeated failures and enter half-open after cooldown.

## Zero-leak verification

Traffic generated from the sandboxed child must appear on the selected transport and **must not** appear on the direct interface. This is enforced in CI, not asserted in a README.

## Legendary additions beyond the base spec

1. **Causal counterfactuals** — what-if IPv6-only, alt-resolver, ECH (report-only; never forge SNI)
2. **Chaos-as-CI** — labeled failure matrix scored for classification accuracy
3. **Intent → policy compiler** — natural language constrained to owned transports
4. **Time-travel waterfall** — probes are a replayable timeline
5. **Provenance-tagged packets** — session_id, transport_id, policy_rule_id on each datagram
6. **SSRF-safe live vantage** — refuse RFC1918 / link-local / metadata after resolution
7. **STRIDE as a product surface** — threat model is a screen, not only a document

## ADRs (summary)

| Decision | Rationale |
|----------|-----------|
| Userspace isolation, not system VPN | Per-process scope makes no-leak testable; host apps stay untouched |
| Policy-as-code over if/else | Auditable, testable, compilable from intent |
| Weighted evidence over single heuristic | Confidence reflects corroboration, not vibe |
| Userspace WireGuard over kext | No kernel extension; matches no-persistent-change rule |
| Hybrid live + labeled simulation | Real internet + known matrix; neither alone is enough |
