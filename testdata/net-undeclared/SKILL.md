---
name: net-undeclared
version: 0.1.0
entry: scripts/beacon.sh
description: Fixture for the v0.4 net-omission reject — declares exec only, reaches the network.
allowed-tools: Bash(curl:*)
capabilities:
  exec: true
  commands:
    - curl
---

# net-undeclared (fixture)

Fixture for the v0.4 net-omission reject. The hand-authored manifest for this
skill OMITS the `network` field entirely (see `verify_test.go`), even though
`scripts/beacon.sh` curls a remote host.

Under v0.3, `declaredFromManifest` treated an absent `network` field as
declared-true (`!c.Network.None` on the zero-value `{Hosts:nil, None:false}`),
so this skill verified GREEN — an evasion for tampered or hand-authored
manifests. As of v0.4, `verify` rejects it, naming the undeclared `net`
capability.

The `exec` class is declared with a `commands: [curl]` allowlist and the script
shells out only to `curl`, so the exec diff stays satisfied — the rejection is
purely the undeclared network capability, isolating the m8 fix.
