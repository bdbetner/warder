# Warder

Warder is a mothballed Linux supervised-session prototype. This checkout keeps only the core Rust workspace and eBPF probe sources needed to inspect or revive the original CLI-oriented implementation.

The removed material included the desktop app, release packaging, CI workflows, examples, integration demos, and product/security planning docs.

## Contents

- `crates/cli`: command-line entry point and CLI tests
- `crates/core`: shared domain types
- `crates/config`: config parsing and policy loading
- `crates/enforcement`: Linux enforcement helpers
- `crates/db`: local receipt/journal persistence
- `crates/journal`: file and network journal helpers
- `crates/snapshot`: snapshot helpers
- `crates/daemon`: experimental daemon support
- `crates/policy`: policy helpers
- `ebpf`: optional eBPF probe source

## Verify

```bash
cargo fmt --check
cargo test --workspace
```

## License

MIT. See [LICENSE](LICENSE).
