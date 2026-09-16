# Contributing

1. Keep ethical non-goals intact — no circumvention features.
2. Prefer policy and tests over hardcoded selection logic.
3. New transports implement the versioned `Transport` interface.
4. Classifier changes must keep the labeled chaos matrix green.
5. Secrets never appear in logs, configs, or crash reports.
