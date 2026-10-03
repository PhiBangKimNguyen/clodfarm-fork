# AgentRunway F1a runtime candidate

Use `Dockerfile.dogfood`, not the general-purpose image, for the credential-free
Linux/Docker/WSL2 foundation. Build from a reviewed full commit:

```sh
docker build --platform linux/amd64 -f Dockerfile.dogfood \
  --build-arg FARM_REVISION="$(git rev-parse HEAD)" -t clodfarm-dogfood:candidate .
```

The Node base is digest-pinned, Python dependencies are version/hash-locked, and
official Claude Code 2.1.288 and Codex 0.160.0 packages are unmodified. Debian
security packages are resolved at rebuild time; record the resulting local image
ID and package inventory. Configuration reproduction is not byte-for-byte image
reproducibility. New builds need review and a new recorded image ID.

The default command is inert. It does not start the daemon, UI, hatching, bot
dispatch, auth, or model calls. Codex is installed for version verification only;
this fork still lacks its F1d adapter. No credentials belong in build contexts,
images, CI, or worker mounts. AgentRunway owns the manifest, isolated mount setup,
capacity evidence and runbook in `tools/dogfood/farm/`.

Default farm upgrade source now points to this fork and unattended Claude updates
default to zero in both image variants and example configuration. Explicit manual
upgrades still accept a ref/source: during validation use only a reviewed full
commit, rebuild, inspect versions/source, and re-run authority tests. Neither this
change nor `FARM_PUSH=0` enforces the missing F1c landing/capability controls.
