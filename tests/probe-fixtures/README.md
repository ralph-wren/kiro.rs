# Probe test fixtures

These files are imported from the supplied test materials and are intentionally
kept outside `src/`. They are reference fixtures for local probe experiments;
they are not compiled into the service and do not change request routing.

- `identity_guard.rs`: scripted identity/cutoff response logic.
- `handlers.rs`: external Anthropic handler implementation for compatibility comparison.
- `identity_prompt.txt`: supplied identity prompt used as a test input.

The external handler has dependencies that are not present in this repository,
so it must not replace `src/anthropic/handlers.rs` without a separate porting and
review effort.
