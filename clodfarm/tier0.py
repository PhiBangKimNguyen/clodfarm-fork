"""Closed Tier 0 tool executor. Run only in a kernel-isolated, networkless container.

No Claude Code hooks, shell, task store, credentials or Git are used here. The
supervisor supplies a read-only policy and one task-scoped Unix socket. Model
transport is deliberately separate (F1b); stdin is the offline protocol driver.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import socket
import stat
import sys
from pathlib import Path, PurePosixPath

LIMIT = 262144
CAPABILITIES = {"workspace.read", "workspace.edit", "parent_claude.result", "public_web.read"}
FIELDS = {
    "format",
    "task",
    "worker",
    "version",
    "data_class",
    "input_approved",
    "capabilities",
    "public_urls",
    "input_files",
}
ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
HASH = re.compile(r"[a-f0-9]{64}\Z")
BLOCKED = {".git", ".farm", ".claude", ".codex", ".ssh", ".aws", ".env", "policy"}


class Denied(ValueError):
    """Stable denial without echoing untrusted content into logs."""


def require(ok, reason):
    if not ok:
        raise Denied(reason)


def shape(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys), "invalid request shape")


def validate_policy(policy):
    shape(policy, FIELDS)
    require(policy["format"] == "clodfarm.tier0/v1", "invalid policy format")
    for key in ("task", "worker"):
        require(isinstance(policy[key], str) and ID.fullmatch(policy[key]), "invalid identity")
    require(type(policy["version"]) is int and policy["version"] > 0, "invalid task version")
    require(
        policy["data_class"] in ("public_safe", "private_code_without_secrets"), "data class denied"
    )
    require(policy["input_approved"] is True, "input not approved")
    caps = policy["capabilities"]
    require(
        isinstance(caps, list) and all(isinstance(c, str) for c in caps), "invalid capabilities"
    )
    require(len(caps) == len(set(caps)) and set(caps) <= CAPABILITIES, "unknown capability")
    require(
        {"workspace.read", "workspace.edit", "parent_claude.result"} <= set(caps),
        "missing capability",
    )
    files = policy["input_files"]
    require(isinstance(files, dict) and 0 < len(files) <= 256, "approved input inventory required")
    for path, digest in files.items():
        require(
            isinstance(path, str) and isinstance(digest, str) and HASH.fullmatch(digest),
            "input digest required",
        )
    urls = policy["public_urls"]
    require(isinstance(urls, list) and len(urls) <= 16, "invalid public URL list")
    from urllib.parse import urlsplit

    for url in urls:
        require(isinstance(url, str) and len(url) <= 2048, "invalid public URL")
        parsed = urlsplit(url)
        require(
            parsed.scheme == "https"
            and parsed.hostname
            and not parsed.username
            and not parsed.password
            and parsed.port in (None, 443)
            and not parsed.fragment
            and not parsed.query,
            "public URL denied",
        )
    require(not urls or "public_web.read" in caps, "web capability missing")
    return policy


def load_policy(path: Path, expected: str):
    require(HASH.fullmatch(expected or ""), "policy digest missing")
    # Read via one non-following descriptor; Docker must also enforce a RO bind.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and not meta.st_mode & 0o222, "policy writable")
        raw = stream.read(LIMIT + 1)
    require(
        len(raw) <= LIMIT and hashlib.sha256(raw).hexdigest() == expected, "policy digest mismatch"
    )
    try:
        return validate_policy(json.loads(raw))
    except (TypeError, KeyError, json.JSONDecodeError) as exc:
        raise Denied("invalid policy") from exc


class Workspace:
    """POSIX dirfd operations: never follow links, including during a rename race."""

    def __init__(self, input_root: Path, output_root: Path):
        require(os.name == "posix", "Tier 0 requires Linux isolation")
        self.roots = {}
        for name, root in (("input", input_root), ("output", output_root)):
            self.roots[name] = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def close(self):
        for fd in self.roots.values():
            os.close(fd)

    @contextlib.contextmanager
    def parent(self, area, path):
        require(area in self.roots, "workspace area denied")
        require(isinstance(path, str) and 0 < len(path) <= 512, "invalid path")
        parts = path.split("/")
        require(
            not PurePosixPath(path).is_absolute()
            and "\\" not in path
            and all(
                p not in ("", ".", "..")
                and p.casefold() not in BLOCKED
                and not p.casefold().startswith(".env.")
                for p in parts
            ),
            "path denied",
        )
        fd = os.dup(self.roots[area])
        try:
            for part in parts[:-1]:
                new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = new
            yield fd, parts[-1]
        finally:
            os.close(fd)

    def read(self, area, path):
        with self.parent(area, path) as (parent, leaf):
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(fd, "rb") as stream:
                meta = os.fstat(stream.fileno())
                require(
                    stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1, "linked or non-file input"
                )
                data = stream.read(LIMIT + 1)
        require(len(data) <= LIMIT, "file too large")
        return data

    def write(self, path, content):
        require(isinstance(content, str), "text content required")
        data = content.encode("utf-8")
        require(len(data) <= LIMIT, "file too large")
        with self.parent("output", path) as (parent, leaf):
            # Do not truncate an existing inode; replacement cannot modify a hardlink.
            if leaf in os.listdir(parent):
                meta = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1, "linked output denied")
            import secrets

            temporary = ".proposal-" + secrets.token_hex(16)
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.rename(temporary, leaf, src_dir_fd=parent, dst_dir_fd=parent)
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temporary, dir_fd=parent)
        return {"path": path, "sha256": hashlib.sha256(data).hexdigest()}


def rpc(socket_path: str, token: str, request: dict):
    raw = json.dumps({"token": token, "request": request}).encode() + b"\n"
    require(len(raw) <= LIMIT, "request too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(15)
        connection.connect(socket_path)
        connection.sendall(raw)
        with connection.makefile("rb") as stream:
            response = stream.readline(LIMIT + 1)
    require(len(response) <= LIMIT, "response too large")
    result = json.loads(response)
    require(result.get("ok") is True, "supervisor denied request")
    return result["result"]


class Tools:
    def __init__(self, policy, workspace, send):
        self.policy = validate_policy(policy)
        self.workspace, self.send = workspace, send

    def execute(self, request):
        shape(request, {"tool", "input"})
        tool, args = request["tool"], request["input"]
        require(isinstance(tool, str) and isinstance(args, dict), "invalid tool")
        if tool == "workspace.read":
            shape(args, {"area", "path"})
            data = self.workspace.read(args["area"], args["path"])
            if args["area"] == "input":
                require(
                    hashlib.sha256(data).hexdigest()
                    == self.policy["input_files"].get(args["path"]),
                    "unapproved or changed input",
                )
            return {"text": data.decode("utf-8")}
        if tool == "workspace.edit":
            shape(args, {"path", "content"})
            status = self.send({"tool": "task.status", "input": {}})
            require(status["status"] == "assigned", "task not accepting edits")
            return self.workspace.write(args["path"], args["content"])
        if tool in ("task.status", "parent_claude.result", "task.escalate", "public_web.read"):
            if tool == "public_web.read":
                shape(args, {"url"})
                require(
                    tool in self.policy["capabilities"]
                    and args["url"] in self.policy["public_urls"],
                    "public URL not approved",
                )
            return self.send(request)
        raise Denied("unknown tool denied")


def main():
    try:
        policy = load_policy(Path("/policy/job.json"), os.environ.get("FARM_POLICY_SHA256", ""))
        token = Path("/capability/token").read_text().strip()
        require(re.fullmatch(r"[a-f0-9]{64}", token), "capability missing")
        workspace = Workspace(Path("/input"), Path("/workspace"))
        tools = Tools(policy, workspace, lambda req: rpc("/rpc/task.sock", token, req))
        try:
            while True:
                line = sys.stdin.buffer.readline(LIMIT + 1)
                if not line:
                    break
                require(len(line) <= LIMIT, "request too large")
                try:
                    result = {"ok": True, "result": tools.execute(json.loads(line))}
                except (ValueError, OSError, TypeError, KeyError):
                    result = {"ok": False, "error": "tool denied"}
                print(json.dumps(result), flush=True)
        finally:
            workspace.close()
    except (ValueError, OSError, TypeError, KeyError):
        print('{"ok":false,"error":"Tier 0 startup denied"}', flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
