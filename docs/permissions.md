# Permissions And Policy

Warder policy describes what a tagged agent session may do around protected zones.

For users, policy should answer plain questions:

- Which folders are protected?
- Which agent label is running?
- Can this session write protected paths?
- Is a snapshot required before launch?
- Is file activity journaled?
- Is network activity journaled?
- What should happen if Landlock, cgroups, snapshots, or eBPF are unavailable?

## Current Policy Shape

Current Warder policy is local and explicit:

- protected paths are listed in config
- agents have labels and commands
- write policy can deny protected writes
- snapshots can be disabled, best-effort, or required
- enforcement can be disabled, best-effort, or required depending on the backend
- network journaling can be enabled or disabled

## What Policy Is Not

Warder policy is not a broad AI permission system. Semantic search, email/calendar actions, cloud connectors, browser automation, and approval queues are outside the current product unless they are reintroduced through Warder's supervised-session model.
