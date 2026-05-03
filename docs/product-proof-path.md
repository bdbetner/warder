# Product Proof Path

This plan turns the current public beta into an easier product to understand, demo, and trust.

The product lane is intentionally narrow:

> Warder is a local, cross-tool, host-side supervision and receipt layer for explicit AI-agent sessions.

It is not a general endpoint security product, a cloud AI governance tool, a model reviewer, or a host-wide sandbox.

## P0: Make The Linux Beta Undeniable

1. **Attack-pack demo**
   - Use `warder demo attack-pack` as the first installed-product proof.
   - Keep `scripts/attack-pack-demo.sh` as a source-checkout smoke wrapper while the native command is the user-facing path.
   - Show a protected write denied where Landlock is available.
   - Show read status honestly: allowed by default, denied only when experimental read denial is configured and supported.
   - Show a network attempt as observed, not blocked.
   - Show an allowed workspace edit.
   - End with the receipt, file journal, network coverage, and snapshot/recovery state.

2. **Host verification command**
   - Use `warder test-host` or its alias, `warder verify-host`.
   - Run real child-process probes for Landlock write denial, experimental read denial, and seccomp escape filtering.
   - Report pre-exec cgroup attribution, eBPF attach readiness, and Btrfs snapshot support from host capability checks until privileged matrix tests can prove them end to end.
   - Report each control as `proven working`, `configured/planned`, `degraded`, or `unsupported`.
   - Provide JSON output so the desktop app can reuse the same result.

3. **First-class setup wrappers**
   - `warder setup codex|claude|openclaw --workspace <path> --protect-secrets` now generates a first policy from the known agent preset.
   - `warder codex|claude|openclaw -- [agent args]` now provides a thin launch shortcut over `warder run --launch`.
   - Keep local scripts as the generic fallback.
   - Do not include Goose in the near-term setup surface until there is specific demand and a tested flow.

4. **Protection matrix**
   - Use [Protection Matrix](protection-matrix.md) as the public expectation table.
   - Include containerized and OpenClaw paths as explicitly degraded unless Warder can prove the required host controls.
   - Keep network blocking listed as `no` until there is a real enforcement backend.

5. **Release trust**
   - Keep GitHub artifact attestations, checksums, and manifest validation.
   - Add stronger artifact signing only after key custody, rotation, revocation, and user verification docs exist.

P0 status: implemented except for stronger artifact signing, which remains intentionally gated on key custody and user verification design.

## P1: Strengthen The Security Story

- Add privileged integration tests for Landlock write denial, experimental read denial, symlink cases, seccomp inheritance, pre-exec cgroup attribution, Btrfs restore, and degraded eBPF receipts.
- Document the exact seccomp escape-syscall filter and keep it framed as hardening, not a complete sandbox policy.
- Keep `network.allowed_destinations` labeled as non-enforcing metadata everywhere it appears.
- Prefer XDG-safe default paths for desktop config, database, receipt key, and snapshot roots. Allow arbitrary absolute paths only after explicit user selection.

## P2: Increase Reach Without Diluting The Claim

- Consider a macOS alpha only after the Linux proof path is simple and reproducible.
- Keep any macOS promise narrower than Linux parity.
- Add packaging channels such as Homebrew, Nix, or AUR after the beta release flow stabilizes.
- Publish short demos and comparison docs that position Warder as complementary to agent-native permissions.

## Refactor Track

`crates/cli/src/lib.rs` has grown too large for the next phase. Split it before adding much more command surface:

- `args`
- `render`
- `run`
- `doctor`
- `receipt`
- `snapshot`
- `profiles`
- `demo`
- `host_probe`

Preserve behavior first, with tests around the existing command surface. Consider moving to `clap` only after the module boundaries are clean.
