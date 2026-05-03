# Receipt Integrity

Warder receipts are accountability records for Warder-launched sessions. They are not tamper-proof forensics, but the local database now carries a hash chain that `warder verify-receipts` checks fail-closed.

Receipt integrity does not expand supervision scope. Warder only supervises processes launched via `warder run` or the desktop launcher; direct launches or processes started by malware are completely unsupervised.

## Strict Launch Keys

Strict launches require an external receipt key:

```text
warder run --config warder.toml --launch --require-enforcement --receipt-key /run/warder-key --agent local -- true
```

The key must pass Warder's private key-file checks. On Unix that means the file must not be readable or writable by group or other users. Place strict-mode keys outside the protected workspace and outside the default `~/.warder` state directory when possible.

Warder also rejects a strict-mode receipt key path when it is inside a configured protected zone or an `enforcement.writable_roots` entry. The same placement rule applies to the SQLite database path used for session state. This prevents the most direct self-tampering configuration, but the local database and HMAC key are still not forensic evidence against unrelated same-user malware.

Best-effort launches may still omit the key, but their receipts will remain locally signed or unsigned depending on the command used to render them.

## Verification

Check the database hash chain:

```text
warder verify-receipts --db .warder/warder.sqlite3
```

Check the database hash chain and prove the external key is available for signed receipt workflows:

```text
warder verify-receipts --db .warder/warder.sqlite3 --external-key /run/warder-key
```

This verifies local session-chain integrity and validates the key file. It does not publish a Merkle root to a remote transparency log.

## Rotation

1. Stop launching strict sessions.
2. Verify the current chain with the old key path:

```text
warder verify-receipts --db .warder/warder.sqlite3 --external-key /run/warder-key
```

3. Move the old key to a dated, read-only archive outside Warder-managed writable paths.
4. Create a new key:

```text
warder receipt-key init --output /run/warder-key --force
```

5. Run a signed test receipt or strict no-op launch before using the key for real agent work.

Keep both old and new key metadata in your release or operations notes. Historical receipts signed with an old key need that old key for signature verification.
