# Security Policy

## Reporting

Please report security issues privately to the repository owner. Do not open public issues for vulnerabilities that could endanger users.

## Principles

- Credentials only via Keychain / secret references (`keychain://…`)
- No production skip-verify for TLS
- Peer-credential-checked local IPC only
- Plugins must be signed before load
- Live diagnose refuses private, link-local, and cloud-metadata destinations
- Zero-leak verification is a release gate

## Scope

NetAccess diagnoses **reachability** through infrastructure the operator is already authorized to use. It does not provide mechanisms for unauthorized access, authentication bypass, or circumvention of access controls.
