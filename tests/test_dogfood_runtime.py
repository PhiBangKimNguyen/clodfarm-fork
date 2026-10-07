"""Pin/source regressions, without login, network calls or starting agents."""
import json
import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest

from clodfarm import boot, config, upgrade


def docker_environment(text):
    values = {}
    assignments = []
    for line in text.replace("\\\n", " ").splitlines():
        if line.startswith("ENV "):
            for token in shlex.split(line[4:]):
                key, value = token.split("=", 1)
                values[key] = value
                assignments.append(key)
    return values, assignments


def test_fork_upgrade_source():
    assert upgrade.REPO == "https://github.com/PhiBangKimNguyen/clodfarm-fork"


def test_updates_default_off(monkeypatch):
    monkeypatch.delenv("FARM_CLAUDE_UPDATE", raising=False)
    monkeypatch.setenv("FARM_CLAUDE_NAME", "offline-test")
    assert config.load().claude_update == 0
    root = Path(__file__).resolve().parents[1]
    for path in ("Dockerfile", "Dockerfile.dogfood"):
        values, assignments = docker_environment((root / path).read_text())
        assert values["FARM_CLAUDE_UPDATE"] == "0"
        assert assignments.count("FARM_CLAUDE_UPDATE") == 1
    assignments = [line.split("=", 1)[1] for line in (root / ".env.example").read_text().splitlines()
                   if line.startswith("FARM_CLAUDE_UPDATE=")]
    assert assignments == ["0"]


def test_effective_environment_detects_later_override():
    values, assignments = docker_environment("ENV FARM_CLAUDE_UPDATE=0\nENV FARM_CLAUDE_UPDATE=3600\n")
    assert values["FARM_CLAUDE_UPDATE"] == "3600"
    assert assignments.count("FARM_CLAUDE_UPDATE") == 2


def test_fixed_apt_sources_replace_inherited_sources():
    text = (Path(__file__).resolve().parents[1] / "Dockerfile.dogfood").read_text()
    assert text.index("rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*") < text.index("apt-get update")
    sources = [line.strip().strip("' \\") for line in text.splitlines() if "'deb [" in line]
    assert len(sources) == 3
    assert all("snapshot.debian.org/archive/" in source and "/20261006T000000Z/" in source
               and "signed-by=/usr/share/keyrings/debian-archive-keyring.gpg" in source
               and "check-valid-until=no" in source for source in sources)
    assert {source.split()[-2] for source in sources} == {"bookworm", "bookworm-updates", "bookworm-security"}
    assert "deb.debian.org" not in text
    assert "trusted=yes" not in text and "AllowUnauthenticated" not in text


def test_dogfood_boot_ignores_workspace_release(monkeypatch):
    values, _ = docker_environment((Path(__file__).resolve().parents[1] / "Dockerfile.dogfood").read_text())
    assert values["CLODFARM_NO_RELEASE"] == "1"
    monkeypatch.setenv("CLODFARM_NO_RELEASE", values["CLODFARM_NO_RELEASE"])
    monkeypatch.setattr(boot, "target", lambda: pytest.fail("workspace release inspected"))
    monkeypatch.setattr(boot.os, "execve", lambda *args: pytest.fail("workspace release executed"))
    boot.boot(["--help"])


@pytest.mark.parametrize("options", [
    {}, {"ref": "main"}, {"ref": "a" * 40}, {"src": "./checkout"},
    {"src": "git+https://example.invalid/source"}, {"rollback": True}, {"restart_ui": True},
])
def test_dogfood_upgrade_rejects_mutations_before_side_effects(tmp_path, monkeypatch, options):
    monkeypatch.setenv("CLODFARM_NO_RELEASE", "1")
    def unexpected(*args, **kwargs):
        pytest.fail("upgrade performed a side effect")
    for name in ("install", "switch", "prune", "hand_over"):
        monkeypatch.setattr(upgrade, name, unexpected)
    monkeypatch.setattr(upgrade.subprocess, "run", unexpected)
    monkeypatch.setattr(upgrade.os, "makedirs", unexpected)
    args = SimpleNamespace(status=False, restart_ui=False, rollback=False, src=None,
                           ref="main", no_handover=False, wait=0)
    for key, value in options.items():
        setattr(args, key, value)
    with pytest.raises(SystemExit, match="workspace releases are disabled"):
        upgrade.main(SimpleNamespace(workspace=str(tmp_path)), args)
    assert list(tmp_path.iterdir()) == []


def test_dogfood_upgrade_status_is_read_only(monkeypatch):
    monkeypatch.setenv("CLODFARM_NO_RELEASE", "1")
    monkeypatch.setattr(upgrade, "status", lambda workspace: "image")
    assert upgrade.main(SimpleNamespace(workspace="unused"), SimpleNamespace(status=True)) == 0


def test_dogfood_has_exact_native_cli_versions():
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile.dogfood").read_text()
    package = json.loads((Path(__file__).resolve().parents[1] / "dogfood-cli/package.json").read_text())
    assert package["dependencies"]["@anthropic-ai/claude-code"] == "2.1.288"
    assert package["dependencies"]["@openai/codex"] == "0.160.0"
    assert "npm ci" in dockerfile
    assert "@latest" not in dockerfile
    assert "node:22-bookworm-slim@sha256:" in dockerfile
