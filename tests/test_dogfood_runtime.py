"""Pin/source regressions, without login, network calls or starting agents."""
import json
from pathlib import Path

from clodfarm import config, upgrade


def test_fork_upgrade_source():
    assert upgrade.REPO == "https://github.com/PhiBangKimNguyen/clodfarm-fork"


def test_updates_default_off(monkeypatch):
    monkeypatch.delenv("FARM_CLAUDE_UPDATE", raising=False)
    monkeypatch.setenv("FARM_CLAUDE_NAME", "offline-test")
    assert config.load().claude_update == 0
    root = Path(__file__).resolve().parents[1]
    for path in ("Dockerfile", "Dockerfile.dogfood", ".env.example"):
        assert "FARM_CLAUDE_UPDATE=0" in (root / path).read_text()


def test_dogfood_has_exact_native_cli_versions():
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile.dogfood").read_text()
    package = json.loads((Path(__file__).resolve().parents[1] / "dogfood-cli/package.json").read_text())
    assert package["dependencies"]["@anthropic-ai/claude-code"] == "2.1.288"
    assert package["dependencies"]["@openai/codex"] == "0.160.0"
    assert "npm ci" in dockerfile
    assert "@latest" not in dockerfile
    assert "node:22-bookworm-slim@sha256:" in dockerfile
