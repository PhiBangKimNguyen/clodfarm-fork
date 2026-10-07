# AgentRunway F1a runtime candidate

Use `Dockerfile.dogfood`, not the general-purpose image, for the credential-free
Linux/Docker/WSL2 foundation. Build from a reviewed full commit:

```sh
docker build --platform linux/amd64 -f Dockerfile.dogfood \
  --build-arg FARM_REVISION="$(git rev-parse HEAD)" -t clodfarm-dogfood:candidate .
```

The Node base is digest-pinned, Python dependencies are version/hash-locked, and
official Claude Code 2.1.288 and Codex 0.160.0 packages are unmodified. Debian
packages resolve from fixed `20261006T000000Z` Debian and Debian-security snapshots.
The inherited moving APT sources are removed first. Release expiry is disabled for
the fixed archives; Debian archive signatures remain required. See the
[Debian snapshot instructions](https://snapshot.debian.org/#usage).
AgentRunway requires a witnessed no-cache rebuild to match the full exported rootfs
and startup Config baseline. A new snapshot or source head requires a new unaccepted
candidate, inventory and review together; do not downgrade packages or widen
inventory exclusions to reproduce an older candidate.

The default command is inert. It does not start the daemon, UI, hatching, bot
dispatch, auth, or model calls. Codex is installed for version verification only;
this fork still lacks its F1d adapter. No credentials belong in build contexts,
images, CI, or worker mounts. AgentRunway owns the manifest, isolated mount setup,
capacity evidence and runbook in `tools/dogfood/farm/`.

Default farm upgrade source now points to this fork and unattended Claude updates
default to zero in both image variants and example configuration. Explicit manual
upgrades in the general image still accept a ref/source. The dogfood image seals
`CLODFARM_NO_RELEASE=1`: boot ignores planted workspace releases, and every upgrade
mutation (including rollback/UI restart) fails before filesystem/network activity.
Read-only `upgrade --status` remains available. Update dogfood only by rebuilding a
reviewed full fork commit, inspecting its exported inventory and repeating cold
reproduction and authority tests. Neither this
change nor `FARM_PUSH=0` enforces the missing F1c landing/capability controls.
