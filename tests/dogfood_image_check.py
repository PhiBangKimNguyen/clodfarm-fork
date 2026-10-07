"""Offline check of the installed dogfood image, with a planted workspace release."""
import os
from pathlib import Path
import subprocess
import tempfile

import clodfarm


def main():
    assert os.environ["CLODFARM_NO_RELEASE"] == "1"
    assert os.environ["FARM_CLAUDE_UPDATE"] == "0"
    assert Path(clodfarm.__file__).is_relative_to("/opt/clodfarm")
    with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
        workspace = Path(temporary)
        package = workspace / ".farm/releases/999.0.0-planted/lib/clodfarm"
        package.mkdir(parents=True)
        marker = workspace / "override-executed"
        (package / "__init__.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
            "raise RuntimeError('workspace override executed')\n"
        )
        (workspace / ".farm/releases/current").symlink_to(package.parents[1])
        env = {**os.environ, "FARM_WORKSPACE": str(workspace)}
        help_result = subprocess.run(["clodfarm", "--help"], env=env, capture_output=True, text=True)
        assert help_result.returncode == 0, help_result.stderr
        assert not marker.exists()
        before = sorted(str(path.relative_to(workspace)) for path in workspace.rglob("*"))
        for args in ([], ["--ref", "main"], ["--ref", "a" * 40], ["--from", str(workspace)],
                     ["--rollback"], ["--restart-ui"]):
            result = subprocess.run(["clodfarm", "upgrade", *args], env=env, capture_output=True, text=True)
            assert result.returncode != 0
            assert "workspace releases are disabled" in result.stderr, result.stderr
        assert not marker.exists()
        assert before == sorted(str(path.relative_to(workspace)) for path in workspace.rglob("*"))
        # Without the seal, the higher-version planted release must execute. This
        # proves the positive check isn't passing because boot prefers a newer image.
        unsealed = dict(env)
        unsealed.pop("CLODFARM_NO_RELEASE")
        result = subprocess.run(["clodfarm", "--help"], env=unsealed, capture_output=True, text=True)
        assert result.returncode != 0 and marker.exists(), result.stderr
    print("Installed /opt/clodfarm CLI ignores planted release; all dogfood upgrade mutations rejected.")


if __name__ == "__main__":
    main()
