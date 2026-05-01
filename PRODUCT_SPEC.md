# Product Overview

Warder helps Linux users run local AI agents with protected zones, supervised sessions, and readable receipts.

The core product promise is simple:

> Before an agent runs, Warder shows what it should be allowed to do. After it runs, Warder gives the user a receipt of what happened and which protections actually held.

## Problem

Local agents often run as the user. That gives them access to the same repositories, notes, credentials, shell config, and system paths the user can reach.

Permissive execution modes make agents much faster, but they also increase the cost of a bad command, prompt mistake, compromised tool, or careless automated edit.

Users need a local control layer that is separate from any one agent app.

## Who It Is For

Warder is for Linux users who:

- run coding or automation agents locally
- use more than one agent tool
- want fewer approval prompts without giving agents unlimited access
- need a readable record of what an agent session did
- prefer explicit local policy over hidden app-specific defaults

## Main Concepts

### Protected Zones

A protected zone is a named group of local paths plus policy.

Examples:

- `credentials`: SSH keys, cloud credentials, kube config, `.env` files
- `notes`: personal notes or documents
- `project-readonly`: a repository an agent may inspect but not change
- `risky-project`: a project that should be snapshotted before edits

### Supervised Sessions

A supervised session is a command launched through Warder with an agent label and config.

The command can be Codex CLI, Claude Code, Goose, a local script, a shell command, or another local agent tool.

### Receipts

A receipt is the user-facing record of a session. It should answer:

- What command ran?
- Which protected zones applied?
- Which protections were active?
- Which protections degraded, and why?
- What file activity was observed?
- What network-journal coverage existed?
- Was a snapshot created?
- What should the user review next?

## Current Alpha Scope

The current alpha is a Linux-first CLI with a native desktop companion.

It can:

- load protected-zone policy from local config
- generate starter config with `warder init`
- explain policy before launch
- dry-run policy and host checks before launch
- run a supervised command through `warder run --launch`
- tag supervised sessions with cgroups where available
- deny writes to protected paths with Landlock where available
- journal protected-zone file activity with inotify
- store typed network-egress journal data and report live-network coverage limits
- optionally collect live eBPF TCP and UDP egress attempts where built and permitted
- create Btrfs snapshots for supported protected roots
- provide a guarded Btrfs revert path
- produce text and JSON receipts
- keep the daemon optional for normal supervised sessions

## Non-Goals

Warder is not:

- an AI chat app
- a replacement for every agent app's built-in sandbox
- a cloud security platform
- a RAG or semantic search system
- a browser, email, or calendar automation tool
- a guarantee that unsupported hosts can safely run permissive agents
- an always-on guard for commands launched outside Warder

## Product Direction

Warder should stay focused on one question:

> What did this local agent session have permission to do, what did it actually do, and can the user recover?

Future work should improve that answer before expanding the surface area.

Good next directions include:

- richer receipt exports
- dependency-change review
- safer protected-zone templates for common secret locations
- command and tool policy
- broader snapshot backend support
- stronger network gating
- optional daemon-backed observation
- a more complete desktop review experience

Features should remain outside Warder when they become broad AI governance, cloud scanning, model evaluation, application security review, semantic search, or general automation.
