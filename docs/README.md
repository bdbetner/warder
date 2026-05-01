# Warder Documentation

Warder is a Linux safety layer for local agent sessions. Start with the page that matches what you are trying to do.

## Try Warder

- [Install Notes](install.md): download, verify, install, or build Warder.
- [Prototype Demo](prototype-demo.md): run the source-checkout demo flow.
- [Protected Zones](protected-zones.md): choose what Warder should protect.
- [Examples](examples/README.md): common protected-zone scenarios.
- [FAQ](FAQ.md): short answers to common questions.

## Understand The Safety Model

- [Security Model](security-model.md): what Warder enforces, observes, and reports.
- [Threat Model](../THREAT_MODEL.md): risks Warder is designed around.
- [Permissions](permissions.md): how policy choices are framed.
- [Release Trust Model](release-trust.md): how to verify alpha artifacts.

## Understand The Project

- [Vision](vision.md): the long-term product direction.
- [Product Overview](../PRODUCT_SPEC.md): product goals and non-goals.
- [Roadmap](../ROADMAP.md): current and future work.
- [Alpha Scope](../MVP_SCOPE.md): what the current alpha includes and excludes.
- [Architecture](architecture.md): crate layout and session flow.
- [Journals](audit-log.md): what receipts and journals can show.

## Integration Notes

- [Cgroup Setup](cgroup-setup.md): delegated cgroup setup for stronger process tagging.
- [Landlock Demo](landlock-demo.md): local write-denial demo.
- [eBPF File Journal](ebpf-file-journal.md): privileged file-journal setup.
- [OpenClaw Supervision](../integrations/openclaw/README.md): running OpenClaw through Warder.

## Maintainer Notes

- [GUI design notes](design/2026-04-28-gui-v1-design.md) are maintainer/design records, not first-read user docs.
