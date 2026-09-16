# Requirements Summary (v2)

## Primary goals

1. Diagnose destination connectivity failures with per-layer granularity
2. Classify failures with a confidence score
3. Support multiple transports behind one abstraction, selected by declarative policy
4. Run a single target application through the selected transport with a provable no-leak guarantee
5. Make zero persistent changes to host network configuration
6. Explain every selection decision in structured form
7. Guarantee cleanup on every exit path
8. Modular core for Linux/Windows backends
9. Fully open source, reproducibly buildable, independently auditable

## MVP (macOS)

- Per-layer, confidence-scored diagnosis
- HTTP/SOCKS5 transports with health scores
- Declarative policy selection
- Per-process isolation for the launched app
- Automated zero-leak verification
- Cleanup across normal exit, crash, and signal
- Keychain-protected credentials
- Structured, redacted, OpenTelemetry-compatible diagnostics

## Roadmap phases

1. Foundation — scaffolding, config, CLI, session manager, transport abstraction
2. Diagnostics — DNS (incl. alt-resolver), TCP, TLS, HTTP, scored classifier
3. Proxy support — HTTP/SOCKS5, health checks, policy-driven selection
4. Application isolation — launcher, env + Network Extension, lifecycle, zero-leak
5. macOS native — NE hardening, Keychain, pf-anchor scoping, signing/notarization
6. Advanced transports — WireGuard userspace, SSH dynamic forward, Tailscale
7. GUI — menu-bar app, diagnostic timeline, session history
8. Ecosystem — Plugin SDK, signed plugins, PAC/config import
9. Cross-platform — Linux, Windows
