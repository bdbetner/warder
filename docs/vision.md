# Vision

AI agents should be useful without requiring users to hand their whole Linux account to every local session.

Warder exists to make local agent work more accountable. A user should be able to choose a fast, permissive workflow and still know:

- which folders were protected
- which host protections were active
- what the agent was allowed to do
- what Warder observed
- what degraded
- whether recovery options exist

The first version is intentionally narrow:

- declare protected zones
- preview policy with `explain` and `dry-run`
- run a local agent command through Warder
- block protected writes where Linux supports it
- snapshot supported paths before risky sessions
- journal file and network activity within current limits
- produce a readable session receipt
- report gaps honestly

The larger vision is a dependable local safety layer for agent work across tools. The CLI should stay useful on its own, and the desktop app should make the same model easier to understand and review.

Warder should grow only where it strengthens supervised local execution, explicit policy, journaling, degraded-mode reporting, or recovery.
