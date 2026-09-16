# Threat Model (STRIDE)

| Category | Example threat | Mitigation |
|----------|----------------|------------|
| Spoofing | Malicious process impersonates local IPC client | UDS + peer-credential checks |
| Tampering | Malicious/compromised plugin | Signature verification, sandboxed execution |
| Repudiation | No record of why a transport was chosen | Full decision-trail logging |
| Info disclosure | Credential leakage in logs/crash reports | Redaction middleware, Keychain-only secrets |
| DoS | Flapping transport causes retry storm | Circuit breaker + cooldown |
| Elevation of privilege | Orphaned privileged helper | Watchdog sweep, minimal separate privileged binary |
| Leakage | Traffic escaping the selected transport | Automated zero-leak CI verification |
| SSRF | Diagnose used as open proxy into private nets | Block loopback, RFC1918, link-local, metadata |

Also covers: compromised VPN/proxy endpoint, DNS leakage, malicious configuration, supply-chain compromise.

## Credential security

- macOS Keychain Services for storage
- Config references secrets by `keychain://` name, never inline values
- Never logged, printed in diagnostics, committed to Git, or included in crash reports

## Transport security

- TLS certificate validation always on (no production skip-verify)
- Proxy auth credentials never sent over unencrypted proxy connections
- Tunnel integrity checks (WireGuard AEAD, SSH host-key pinning)
