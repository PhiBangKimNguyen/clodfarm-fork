"""Offline check of the installed dogfood image, with a planted workspace release."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

import clodfarm
from clodfarm import procs, runner


def main():
    assert os.environ["CLODFARM_NO_RELEASE"] == "1"
    assert os.environ["PYTHONSAFEPATH"] == "1"
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
        stale = workspace / ".farm/pids/ui-stale.json"
        stale.parent.mkdir()
        stale.write_text('{"pid":0,"started":0}')
        env = {**os.environ, "FARM_WORKSPACE": str(workspace)}
        help_result = subprocess.run(["clodfarm", "--help"], env=env, capture_output=True, text=True)
        assert help_result.returncode == 0, help_result.stderr
        assert not marker.exists()
        before = sorted(str(path.relative_to(workspace)) for path in workspace.rglob("*"))
        status = subprocess.run(["clodfarm", "upgrade", "--status"], env=env,
                                capture_output=True, text=True)
        assert status.returncode == 0 and "current release: image (" in status.stdout, status.stderr
        assert stale.read_text() == '{"pid":0,"started":0}'
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
        marker.unlink()
        poison = f"import os\nopen({str(marker)!r}, 'w').write('executed')\nos._exit(0)\n"
        (workspace / "json.py").write_text(poison)
        shim = workspace / ".farm/shim/json.py"
        shim.parent.mkdir()
        shim.write_text(poison)
        result = subprocess.run([sys.executable, "-c", "import json; print('completed')"],
                                cwd=workspace, capture_output=True, text=True)
        assert result.returncode == 0 and result.stdout.strip() == "completed"
        assert not marker.exists()
        # Removing the safe-path policy exposes the same planted CWD module.
        unsafe = dict(os.environ)
        unsafe.pop("PYTHONSAFEPATH")
        result = subprocess.run([sys.executable, "-c", "import json; print('completed')"],
                                cwd=workspace, env=unsafe, capture_output=True, text=True)
        assert result.returncode == 0 and not result.stdout and marker.exists()
        marker.unlink()
        completed = workspace / "child-completed"
        cmd = [sys.executable, "-I", "-c",
               f"from pathlib import Path; Path({str(completed)!r}).touch()"]
        procs.spawn_detached(str(workspace), cmd)
        deadline = time.monotonic() + 10
        while not completed.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert completed.exists() and not marker.exists()
        completed.unlink()
        handle = runner.start_run(str(workspace), str(workspace / ".farm/test-run"),
                                  cmd, str(workspace), dict(os.environ))
        assert handle.wait(10) == 0 and completed.exists() and not marker.exists()
        # The old writable shim invocation must expose its planted neighbour.
        result = subprocess.run([sys.executable, procs.shim_path(str(workspace)), "exec", "unused"],
                                env=unsafe, capture_output=True, text=True)
        assert result.returncode == 0 and marker.exists()
    print("Installed seal: release/CWD/shim controls, run/spawn completion and read-only status passed.")


if __name__ == "__main__":
    main()
