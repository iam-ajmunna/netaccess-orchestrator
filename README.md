# NetAccess Orchestrator

**Per-application network reliability and authorized multi-transport orchestration.**

NetAccess diagnoses *why* a destination is unreachable, then — only through infrastructure **you already own** (your proxy, WireGuard, SSH jump host, Tailscale) — runs a single target application through the path that actually works.

It is **not** a VPN client, **not** a censorship circumvention tool, and **not** a system-wide network mutator.

> Reachability is diagnosed. Authorization is out of scope.

## Why this project exists

Most “connectivity fixer” tools become sketchy proxy switchers. This one is built like production infrastructure software:

- Explainable, confidence-scored failure classification (DNS → TCP → TLS → HTTP → route)
- Policy-as-code transport selection (not hardcoded if/else)
- EWMA health scoring + circuit breakers
- Automated **zero-leak** verification as a first-class test
- Privilege-minimized session isolation (env proxy + per-process capture model)
- Explicit ethical boundaries and a STRIDE threat model in-product

## What it does

1. **Diagnose** a target with per-layer evidence and a confidence score  
2. **Select** an authorized transport via declarative policy  
3. **Run** only the intended process tree through that transport  
4. **Prove** nothing leaked onto the direct interface  
5. **Tear down** cleanly on exit, crash, or signal  

## Ethical non-goals (enforced)

The project will **not**:

- Guarantee access to every destination  
- Circumvent authentication or authorization  
- Break, downgrade, or strip encryption  
- Operate anonymous/public proxies without explicit user configuration  
- Modify system-wide routing, DNS, or firewall state without reversible, per-session scope  
- Act as general-purpose censorship or geo-restriction circumvention infrastructure  

Geographic or destination-side restrictions are **reported**, never “fixed.”

## Repository layout

```
netaccess/
├── README.md
├── LICENSE
├── docs/
│   ├── Architecture.md
│   ├── Threat-Model.md
│   └── Requirements.md
├── src/netaccess/          # Core engine
│   ├── types.ts
│   ├── engine.ts           # Classifier, policy, EWMA, selection
│   ├── leak.ts
│   └── cli.ts
├── scripts/
└── public/
```

## CLI surface (target)

```bash
netaccess check <target> [--deep]
netaccess run <application> [args...]
netaccess transports [--scores]
netaccess test <transport>
netaccess status
netaccess stop <session>
netaccess policy validate
netaccess doctor
netaccess leak verify
```

## License

MIT — see [LICENSE](LICENSE).

## Status

Educational / portfolio implementation of the v2 architecture.
