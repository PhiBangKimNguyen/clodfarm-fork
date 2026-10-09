"""Portable Docker CLI smoke. No test container receives the Docker socket.

All state lives in one uniquely named disposable volume. Only a trusted synthetic
bootstrap runs as root to set ownership. Broker uses UID 10002 and worker uses
UID 10001; both use socket group 10001.
"""

import argparse
import hashlib
import json
import subprocess
import time
import uuid


def docker(*args, data=None, check=True):
    result = subprocess.run(
        ["docker", *args], input=data, text=True, capture_output=True, timeout=90
    )
    if check and result.returncode:
        raise RuntimeError("synthetic Docker operation failed: " + result.stderr[:1500])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    if not args.image.startswith("sha256:") or len(args.image) != 71:
        raise ValueError("pinned image required")
    tag = "f1c-smoke-" + uuid.uuid4().hex[:12]
    broker = tag + "-broker"
    policy = {
        "format": "clodfarm.tier0/v1",
        "task": "smoke",
        "worker": "worker-one",
        "version": 1,
        "data_class": "private_code_without_secrets",
        "input_approved": True,
        "capabilities": ["workspace.read", "workspace.edit", "parent_claude.result"],
        "public_urls": [],
        "input_files": {"hello.txt": hashlib.sha256(b"synthetic input").hexdigest()},
    }
    raw = json.dumps(policy)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    boundary = [
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=64",
        "--memory=512m",
        "--cpus=0.5",
        "--log-driver=none",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m,uid=10001,gid=10001",
        "--pull=never",
    ]
    worker_args = [
        *boundary,
        "--user=10001:10001",
        "--env",
        "FARM_TIER0=1",
        "--env",
        "FARM_POLICY_SHA256=" + digest,
    ]
    for name, target, readonly in (
        ("input", "/input", True),
        ("output", "/workspace", False),
        ("policy", "/policy", True),
        ("capability", "/capability", True),
        ("rpc", "/rpc", True),
    ):
        worker_args.extend(
            [
                "--mount",
                f"type=volume,src={tag},dst={target},volume-subpath={name}"
                + (",readonly" if readonly else ""),
            ]
        )
    checks = []
    docker("volume", "create", tag)
    try:
        bootstrap = """import hashlib, json, os
from pathlib import Path
from clodfarm.authority import Authority
root = Path('/scratch')
for name in ['input', 'output', 'policy', 'capability', 'rpc', 'supervisor', 'other-worker']:
    path = root / name
    path.mkdir(mode=0o700 if name in ('supervisor', 'other-worker') else 0o750)
    owner = 10001 if name == 'output' else 10002
    os.chown(path, owner, 10002 if name == 'supervisor' else 10001)
policy = json.loads(POLICY)
(root/'input/hello.txt').write_text('synthetic input')
(root/'input/hello.txt').chmod(0o444)
(root/'policy/job.json').write_text(POLICY)
(root/'policy/job.json').chmod(0o444)
(root/'other-worker/private.txt').write_text('other worker private sentinel')
authority = Authority(root/'supervisor/authority.db')
token = authority.register(policy, root/'input', root/'output')
(root/'capability/token').write_text(token)
(root/'capability/token').chmod(0o400)
os.chown(root/'capability/token', 10001, 10001)
os.chown(root/'supervisor/authority.db', 10002, 10002)
""".replace("POLICY", repr(raw))
        docker(
            "run",
            "--rm",
            "--network=none",
            "--user=0:0",
            "--mount",
            f"type=volume,src={tag},dst=/scratch",
            args.image,
            "python",
            "-I",
            "-c",
            bootstrap,
        )
        docker(
            "run",
            "-d",
            "--name",
            broker,
            *boundary,
            "--user=10002:10001",
            "--mount",
            f"type=volume,src={tag},dst=/scratch",
            "--env",
            "FARM_AUTHORITY_DB=/scratch/supervisor/authority.db",
            args.image,
            "python",
            "-I",
            "-m",
            "clodfarm.f1c",
            "serve",
            "--socket",
            "/scratch/rpc/task.sock",
        )
        for _ in range(30):
            ready = docker(
                "exec",
                broker,
                "python",
                "-c",
                "import os; assert os.path.exists('/scratch/rpc/task.sock')",
                check=False,
            )
            if ready.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("synthetic broker not ready")

        def worker(requests, extra=()):
            result = docker(
                "run",
                "--rm",
                "-i",
                *worker_args,
                *extra,
                args.image,
                "python",
                "-I",
                "-m",
                "clodfarm.tier0",
                data="".join(json.dumps(r) + "\n" for r in requests),
                check=False,
            )
            return result, [json.loads(line) for line in result.stdout.splitlines()]

        requests = [
            {"tool": "workspace.read", "input": {"area": "input", "path": "hello.txt"}},
            {
                "tool": "workspace.edit",
                "input": {"path": "proposal.txt", "content": "synthetic proposal"},
            },
        ]
        requests.extend(
            {"tool": t, "input": {"command": "clodfarm farm public"}}
            for t in [
                "Bash",
                "git.merge",
                "git.push",
                "farm.admin",
                "SendMessage",
                "unknown",
                "review",
            ]
        )
        requests.extend(
            {"tool": "workspace.read", "input": {"area": "input", "path": p}}
            for p in [
                "../supervisor/authority.db",
                "/other-worker/private.txt",
                "/home/farm/.codex/auth.json",
            ]
        )
        requests.append(
            {"tool": "workspace.edit", "input": {"path": "../policy/job.json", "content": "bad"}}
        )
        result, responses = worker(requests)
        assert result.returncode == 0 and len(responses) == len(requests), "worker protocol failed"
        assert all(r["ok"] for r in responses[:2]) and all(not r["ok"] for r in responses[2:])
        checks.append("real-worker-own-read-edit-and-closed-tool-path-controls")
        evidence = responses[1]["result"]
        _, responses = worker(
            [
                {
                    "tool": "task.escalate",
                    "input": {
                        "reason": "credential-needed",
                        "authority": "credential",
                        "evidence": evidence,
                    },
                }
            ]
        )
        escalation = responses[0]["result"]
        docker("restart", broker)
        inbox = json.loads(
            docker("exec", broker, "python", "-I", "-m", "clodfarm.f1c", "inbox").stdout
        )
        assert inbox[0]["id"] == escalation["id"] and inbox[0]["status"] == "pending"
        assert "synthetic proposal" not in json.dumps(inbox) and inbox[0]["destination"] == "human"
        for action in ("acknowledge", "retry"):
            docker(
                "exec",
                broker,
                "python",
                "-I",
                "-m",
                "clodfarm.f1c",
                "disposition",
                escalation["id"],
                "--reviewer",
                "human-manager",
                "--actor",
                "synthetic-operator",
                "--action",
                action,
            )
        checks.append("real-broker-restart-inbox-and-trusted-disposition")
        _, responses = worker([{"tool": "parent_claude.result", "input": evidence}])
        assert responses[0]["result"]["status"] == "proposed"
        _, responses = worker(
            [{"tool": "workspace.edit", "input": {"path": "proposal.txt", "content": "late edit"}}]
        )
        assert responses[0]["ok"] is False
        checks.append("real-scoped-proposal-rpc-and-post-result-edit-denial")
        probe = """import errno, os, socket
for path in ['/input', '/policy', '/capability']:
    try:
        os.mkdir(path + '/unauthorized-directory')
        raise AssertionError('writable protected mount')
    except OSError as e:
        assert e.errno == errno.EROFS, (path, e.errno)
for path in ['/supervisor/authority.db', '/scratch',
             '/other-worker/private.txt', '/var/run/docker.sock']:
    assert not os.path.exists(path), path
assert os.listdir('/sys/class/net') == ['lo']
try:
    socket.create_connection(('1.1.1.1', 443), timeout=2)
    raise AssertionError('egress allowed')
except OSError as e:
    assert e.errno == errno.ENETUNREACH, e.errno
"""
        docker("run", "--rm", *worker_args, args.image, "python", "-I", "-c", probe)
        checks.append("kernel-readonly-mounts-private-state-auth-and-egress")
        docker(
            "run",
            "--rm",
            *worker_args,
            "--mount",
            f"type=volume,src={tag},dst=/supervisor,volume-subpath=supervisor,readonly",
            args.image,
            "python",
            "-I",
            "-c",
            "import errno; from pathlib import Path\n"
            "try: Path('/supervisor/authority.db').read_bytes(); raise AssertionError('DB')\n"
            "except OSError as e: assert e.errno == errno.EACCES",
        )
        checks.append("distinct-supervisor-uid-denies-accidental-private-mount")
        result = docker(
            "run", "--rm", *worker_args, args.image, "clodfarm", "farm", "public", check=False
        )
        assert result.returncode != 0
        checks.append("actual-farm-cli-bypass-denied")
        for bad in ("", "0" * 64):
            result, _ = worker([], ["--env", "FARM_POLICY_SHA256=" + bad])
            assert result.returncode != 0
        # Policy is root-owned: use a separate trusted synthetic bootstrap, never a worker.
        docker(
            "run",
            "--rm",
            "--network=none",
            "--user=0:0",
            "--mount",
            f"type=volume,src={tag},dst=/scratch",
            args.image,
            "python",
            "-c",
            "import os; os.chmod('/scratch/policy/job.json',0o666)",
        )
        result, _ = worker([])
        assert result.returncode != 0
        checks.append("invalid-hash-and-writable-policy-controls")
        print(
            json.dumps(
                {
                    "format": "clodfarm.f1c-smoke/v1",
                    "image": args.image,
                    "checks": checks,
                    "status": "passed",
                    "live_acceptance": False,
                },
                indent=2,
            )
        )
    finally:
        docker("rm", "-f", broker, check=False)
        docker("volume", "rm", tag, check=False)


if __name__ == "__main__":
    main()
