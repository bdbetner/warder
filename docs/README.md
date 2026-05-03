# Warder Documentation

Warder wraps explicit local agent sessions with protected paths, receipts, and recovery where Linux supports it. Start with the page that matches what you are trying to do.

## Try Warder

- [Install Notes](install.md): download, verify, install, or build Warder.
- [Linux Compatibility](linux-compatibility.md): supported release target, host requirements, and feature degradation.
- [Reviewer Feedback Guide](reviewer-feedback.md): release-artifact demo path and feedback checklist.
- [Prototype Demo](prototype-demo.md): run the source-checkout demo flow.
- [Product Proof Path](product-proof-path.md): next demo, host-probe, matrix, and setup-wrapper work.
- Run `warder demo attack-pack` for a local proof that shows blocked, observed, and degraded behavior on this host.
- Run `warder test-host` after install to prove which host controls work on the current machine.
- Run `warder setup codex|claude|openclaw --workspace . --protect-secrets` to generate a first policy from an agent preset.
- Run `warder codex|claude|openclaw -- [agent args]` after setup for the shortest supervised launch path.
- [Protection Matrix](protection-matrix.md): expected coverage on common Linux, container, and OpenClaw hosts.
- [Protected Zones](protected-zones.md): choose what Warder should protect.
- [OpenClaw Support](openclaw-support.md): recommended way to run OpenClaw through Warder.
- [Examples](examples/README.md): common protected-zone scenarios.
- [FAQ](FAQ.md): short answers to common questions.

## Understand The Safety Model

- [Security Model](security-model.md): what Warder enforces, observes, and reports.
- [Desktop Security](desktop-security.md): Tauri IPC and capability boundaries.
- [Threat Model](../THREAT_MODEL.md): risks Warder is designed around.
- [Permissions](permissions.md): how policy choices are framed.
- [Release Trust Model](release-trust.md): how to verify release artifacts.
- [Release Readiness](release-readiness.md): final release decisions and pull-release criteria.
- [Security Review Triage](security-review-triage.md): current hardening priorities from independent review.

## Understand The Project

- [Vision](vision.md): the long-term product direction.
- [Product Overview](../PRODUCT_SPEC.md): product goals and non-goals.
- [Roadmap](../ROADMAP.md): current and future work.
- [Product Completion Plan](product-completion-plan.md): proposed final release shape.
- [Scope](../MVP_SCOPE.md): what the current release includes and excludes.
- [How Warder Fits](comparison.md): where Warder sits next to wrappers, containers, VMs, and host policy.
- [Architecture](architecture.md): crate layout and session flow.
- [Journals](audit-log.md): what receipts and journals can show.
- [Journal Coverage](journal-coverage.md): exact file/network journal surfaces and blind spots.

## Integration Notes

- [Cgroup Setup](cgroup-setup.md): delegated cgroup setup for stronger process tagging.
- [Landlock Demo](landlock-demo.md): local write-denial demo.
- [eBPF File Journal](ebpf-file-journal.md): privileged file-journal setup.
- [OpenClaw Integration](../integrations/openclaw/README.md): maintainer notes for OpenClaw-specific profile and preflight behavior.

## Maintainer Notes

- [GUI design notes](design/2026-04-28-gui-v1-design.md) are maintainer/design records, not first-read user docs.
