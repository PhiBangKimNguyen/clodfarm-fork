"""Trusted, local-only landing. Verification runs without host credentials or Git.

Candidates are supervisor-created commits. Neither verification output nor raw
review/transcript content is persisted. A changed candidate requires a new Claude
verdict. Existing mission approvals are never consulted.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

from .authority import Authority
from .tier0 import ID, Workspace, require


def git(repo, *args, data=None, env=None):
    result = subprocess.run(
        ["git", "-C", str(repo), *args], input=data, capture_output=True, env=env, timeout=60
    )
    require(result.returncode == 0, "candidate Git operation failed")
    return result.stdout


def candidate(repo, branch, task, version, verify_cmd, verifier_image):
    require(isinstance(verify_cmd, str) and bool(verify_cmd.strip()), "verification required")
    require(re.fullmatch(r"sha256:[a-f0-9]{64}", verifier_image), "pinned verifier image required")
    require(ID.fullmatch(task) and type(version) is int and version > 0, "invalid task")
    require(branch == f"farm/{task}-v{version}", "candidate branch scope denied")
    base = git(repo, "rev-parse", "refs/heads/main").decode().strip()
    commit = git(repo, "rev-parse", f"refs/heads/{branch}").decode().strip()
    parents = git(repo, "rev-list", "--parents", "-n", "1", commit).decode().split()
    require(parents == [commit, base], "candidate base changed; prepare and review again")
    diff = git(repo, "diff", "--binary", "--no-ext-diff", "--no-textconv", base, commit)
    require(bool(diff), "empty candidate denied")
    record = {
        "task": task,
        "version": version,
        "base": base,
        "commit": commit,
        "diff_sha256": hashlib.sha256(diff).hexdigest(),
        "verify_sha256": hashlib.sha256(verify_cmd.encode()).hexdigest(),
        "verifier_image": verifier_image,
    }
    record["identity"] = hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
    return record


def prepare(authority: Authority, repo: Path, task: str, version: int, paths: list[str]):
    """Import explicitly selected proposal files without executing worker code/hooks."""
    require(ID.fullmatch(task) and type(version) is int and version > 0, "invalid task")
    require(
        isinstance(paths, list) and 0 < len(paths) <= 256 and len(paths) == len(set(paths)),
        "explicit proposal paths required",
    )
    with authority.connect() as db:
        job = db.execute(
            "SELECT * FROM jobs WHERE task=? AND version=?", (task, version)
        ).fetchone()
    require(job and job["status"] == "proposed", "task not proposed")
    from .gitops import _locked

    with _locked(str(repo)):
        base = git(repo, "rev-parse", "refs/heads/main").decode().strip()
        workspace = Workspace(Path(job["input_root"]), Path(job["output_root"]))
        try:
            files = {path: workspace.read("output", path) for path in paths}
        finally:
            workspace.close()
        with tempfile.TemporaryDirectory(prefix="farm-index-") as temporary:
            env = {
                "PATH": os.environ["PATH"],
                "GIT_INDEX_FILE": str(Path(temporary) / "index"),
                "GIT_AUTHOR_NAME": "clodfarm",
                "GIT_AUTHOR_EMAIL": "clodfarm@localhost",
                "GIT_COMMITTER_NAME": "clodfarm",
                "GIT_COMMITTER_EMAIL": "clodfarm@localhost",
            }
            git(repo, "read-tree", base, env=env)
            for path, content in files.items():
                require(not path.startswith("-"), "option path denied")
                blob = (
                    git(repo, "hash-object", "-w", "--stdin", data=content, env=env)
                    .decode()
                    .strip()
                )
                git(repo, "update-index", "--add", "--cacheinfo", f"100644,{blob},{path}", env=env)
            tree = git(repo, "write-tree", env=env).decode().strip()
            commit = (
                git(
                    repo,
                    "commit-tree",
                    tree,
                    "-p",
                    base,
                    data=f"Proposal {task} v{version}\n".encode(),
                    env=env,
                )
                .decode()
                .strip()
            )
        branch = f"farm/{task}-v{version}"
        git(repo, "update-ref", f"refs/heads/{branch}", commit)
        return branch


class DockerVerifier:
    def __init__(self, image: str, timeout=300):
        require(re.fullmatch(r"sha256:[a-f0-9]{64}", image), "pinned verifier image required")
        require(type(timeout) is int and 0 < timeout <= 1800, "bounded verification required")
        self.image, self.timeout = image, timeout

    def __call__(self, repo: Path, record: dict, command: str):
        require(os.name == "posix", "verification requires Linux Docker")
        # Read committed blobs directly. git archive honors export-ignore/subst
        # attributes, which could omit or rewrite files the reviewer approved.
        entries = git(repo, "ls-tree", "-r", "-z", record["commit"]).split(b"\0")
        name = "farm-verify-" + record["identity"][:24]
        with tempfile.TemporaryDirectory(prefix="farm-verify-") as temporary:
            root = Path(temporary)
            os.chmod(root, 0o755)
            total = 0
            for entry in entries:
                if not entry:
                    continue
                metadata, raw_path = entry.split(b"\t", 1)
                mode, kind, blob = metadata.decode().split()
                path = raw_path.decode("utf-8")
                require(
                    mode in ("100644", "100755")
                    and kind == "blob"
                    and not path.startswith("/")
                    and ".." not in path.split("/")
                    and ".git" not in path.split("/"),
                    "unsafe verification tree",
                )
                data = git(repo, "cat-file", "blob", blob)
                total += len(data)
                require(total <= 64 * 1024 * 1024, "verification tree too large")
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                target.write_bytes(data)
                target.chmod(0o555 if mode == "100755" else 0o444)
            args = [
                "docker",
                "run",
                "--rm",
                "--name",
                name,
                "--pull=never",
                "--network=none",
                "--read-only",
                "--user=10001:10001",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit=64",
                "--memory=512m",
                "--cpus=0.5",
                "--log-driver=none",
                "--mount",
                f"type=bind,src={root},dst=/candidate,readonly",
                "--tmpfs",
                "/workspace:rw,nosuid,size=128m,uid=10001,gid=10001",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=64m,uid=10001,gid=10001",
                "--workdir=/workspace",
                "--entrypoint=/bin/sh",
                self.image,
                "-c",
                'cp -R /candidate/. /workspace/ && chmod -R u+w /workspace && exec /bin/sh -c "$1"',
                "verify",
                command,
            ]
            try:
                result = subprocess.run(
                    args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=self.timeout
                )
                return result.returncode == 0
            except subprocess.TimeoutExpired:
                return False
            finally:
                # Killing docker's client alone does not stop the container.
                subprocess.run(
                    ["docker", "rm", "-f", name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=False,
                )


def land(
    authority: Authority,
    repo: Path,
    task: str,
    version: int,
    verify_cmd: str,
    verifier: DockerVerifier,
):
    from .gitops import _locked

    require(isinstance(verifier, DockerVerifier), "isolated verifier required")
    require(os.environ.get("FARM_PUSH") == "0", "FARM_PUSH=0 required")
    branch = f"farm/{task}-v{version}"
    with _locked(str(repo)), authority.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        job = db.execute(
            "SELECT * FROM jobs WHERE task=? AND version=?", (task, version)
        ).fetchone()
        require(job and job["status"] == "proposed", "task not proposed")
        require(
            not db.execute(
                "SELECT 1 FROM landings WHERE task=? AND version=?", (task, version)
            ).fetchone(),
            "already landed",
        )
        record = candidate(repo, branch, task, version, verify_cmd, verifier.image)
        review = db.execute(
            "SELECT * FROM reviews WHERE task=? AND version=?", (task, version)
        ).fetchone()
        require(
            review
            and review["accepted"] == 1
            and review["reviewer"] == "parent-claude"
            and review["candidate"] == record["identity"]
            and json.loads(job["policy"])["worker"] != review["reviewer"],
            "missing or stale Claude review",
        )
        require(
            git(repo, "symbolic-ref", "HEAD").decode().strip() == "refs/heads/main",
            "main checkout required",
        )
        require(not git(repo, "status", "--porcelain"), "main worktree dirty")
        require(verifier(repo, record, verify_cmd) is True, "verification failed")
        require(
            candidate(repo, branch, task, version, verify_cmd, verifier.image) == record,
            "candidate changed during verification",
        )
        require(not git(repo, "status", "--porcelain"), "main changed during verification")
        # Ref compare-and-swap also rejects callers outside our Git lock. The
        # candidate is a direct child of the exact reviewed base.
        git(repo, "update-ref", "refs/heads/main", record["commit"], record["base"])
        git(repo, "-c", "core.hooksPath=/dev/null", "reset", "--hard", record["commit"])
        db.execute(
            "INSERT INTO landings VALUES (?,?,?,?)",
            (task, version, record["identity"], time.time()),
        )
        db.execute(
            "UPDATE jobs SET status='landed',token_hash=NULL WHERE task=? AND version=?",
            (task, version),
        )
        return {
            "status": "landed-locally",
            "commit": record["commit"],
            "candidate": record["identity"],
        }
