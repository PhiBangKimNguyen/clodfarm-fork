"""Supervisor-owned durable task RPC and escalation queue; no worker administration.

Only the trusted operator creates tasks and dispositions. Worker bearer tokens are
hashed at rest, revocable and bound to exactly one immutable task version. This
database, the manager interface and review records must never be mounted in workers.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import socketserver
import sqlite3
import stat
import time
from pathlib import Path

from .tier0 import HASH, LIMIT, Denied, Workspace, require, shape, validate_policy

AUTHORITIES = {"parent-claude", "credential", "budget", "policy", "terms", "external-action"}
REASONS = {
    "needs-clarification",
    "capability-denied",
    "private-route-unavailable",
    "verification-failed",
    "review-required",
    "credential-needed",
    "budget-decision",
    "policy-decision",
    "terms-decision",
    "external-action-request",
}
REASON_AUTHORITY = {
    "credential-needed": "credential",
    "budget-decision": "budget",
    "policy-decision": "policy",
    "terms-decision": "terms",
    "external-action-request": "external-action",
}


class Authority:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        require(not path.is_symlink(), "linked state denied")
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS jobs (
                    task TEXT, version INTEGER, policy TEXT, token_hash TEXT UNIQUE,
                    input_root TEXT, output_root TEXT, public_reads TEXT,
                    status TEXT NOT NULL, result TEXT, PRIMARY KEY(task, version));
                CREATE TABLE IF NOT EXISTS escalations (
                    id TEXT PRIMARY KEY, task TEXT, version INTEGER, worker TEXT,
                    data_class TEXT, reason TEXT, evidence TEXT, authority TEXT,
                    destination TEXT, created REAL, status TEXT, reviewer TEXT,
                    decided REAL, disposition TEXT);
                CREATE TABLE IF NOT EXISTS reviews (
                    task TEXT, version INTEGER, candidate TEXT, reviewer TEXT,
                    accepted INTEGER, evidence TEXT, created REAL,
                    PRIMARY KEY(task, version));
                CREATE TABLE IF NOT EXISTS landings (
                    task TEXT, version INTEGER, candidate TEXT, landed REAL,
                    PRIMARY KEY(task, version));
                CREATE TABLE IF NOT EXISTS landing_intents (
                    task TEXT, version INTEGER, candidate TEXT, base TEXT, commit_id TEXT,
                    created REAL, PRIMARY KEY(task, version));
            """)
            if "reviewer_run" not in {row[1] for row in db.execute("PRAGMA table_info(reviews)")}:
                db.execute("ALTER TABLE reviews ADD COLUMN reviewer_run TEXT")
        os.chmod(path, 0o600)

    @contextlib.contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def register(self, policy, input_root: Path, output_root: Path, public_reads=None):
        validate_policy(policy)
        require(
            policy["worker"] not in ("parent-claude", "human-manager"),
            "trusted identity cannot be worker",
        )
        require(input_root.resolve() != output_root.resolve(), "shared input/output denied")
        require(input_root.is_dir() and output_root.is_dir(), "workspace missing")
        require(
            all(root.absolute() == root.resolve(strict=True) for root in (input_root, output_root)),
            "noncanonical host workspace denied",
        )
        roots = (input_root.resolve(), output_root.resolve())
        require(
            not any(self.path.resolve().is_relative_to(r) for r in roots),
            "state inside worker mount denied",
        )
        require(
            not roots[0].is_relative_to(roots[1]) and not roots[1].is_relative_to(roots[0]),
            "nested mounts denied",
        )
        reads = public_reads or {}
        require(
            set(reads) == set(policy["public_urls"]), "public reads must be preapproved snapshots"
        )
        for digest in reads.values():
            require(
                isinstance(digest, str) and HASH.fullmatch(digest),
                "public snapshot digest required",
            )
        if policy["data_class"] == "public_safe":
            require(
                bool(reads)
                and policy["input_files"] == {"public-" + d + ".txt": d for d in reads.values()},
                "public-safe inputs require approved public snapshots",
            )
        workspace = Workspace(*roots)
        try:
            for name, digest in policy["input_files"].items():
                require(
                    hashlib.sha256(workspace.read("input", name)).hexdigest() == digest,
                    "approved input digest mismatch",
                )
        finally:
            workspace.close()
        token = secrets.token_hex(32)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute(
                "SELECT MAX(version) FROM jobs WHERE task=?", (policy["task"],)
            ).fetchone()[0]
            require(previous is None or policy["version"] > previous, "task version must advance")
            require(
                not db.execute(
                    "SELECT 1 FROM landing_intents WHERE task=?", (policy["task"],)
                ).fetchone(),
                "landing reconciliation required",
            )
            for other in db.execute(
                "SELECT * FROM jobs WHERE task!=? AND status!='revoked'", (policy["task"],)
            ):
                for root in roots:
                    for existing in (Path(other["input_root"]), Path(other["output_root"])):
                        require(
                            not root.is_relative_to(existing) and not existing.is_relative_to(root),
                            "cross-worker mounts denied",
                        )
            # Versions invalidate all former tokens and review verdicts. No rerouting.
            db.execute("UPDATE jobs SET status='revoked' WHERE task=?", (policy["task"],))
            db.execute(
                "UPDATE escalations SET status='superseded',reviewer='system:version-advance',"
                "decided=?,disposition='superseded' WHERE task=? "
                "AND status IN ('pending','acknowledged')",
                (time.time(), policy["task"]),
            )
            db.execute(
                "INSERT INTO jobs VALUES (?,?,?,?,?,?,?,'assigned',NULL)",
                (
                    policy["task"],
                    policy["version"],
                    json.dumps(policy, sort_keys=True),
                    hashlib.sha256(token.encode()).hexdigest(),
                    str(input_root.resolve()),
                    str(output_root.resolve()),
                    json.dumps(reads),
                ),
            )
        return token

    def revoke(self, task, version):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            require(
                not db.execute(
                    "SELECT 1 FROM landing_intents WHERE task=? AND version=?", (task, version)
                ).fetchone(),
                "landing reconciliation required",
            )
            db.execute(
                "UPDATE jobs SET status='revoked' WHERE task=? AND version=?", (task, version)
            )
            db.execute(
                "UPDATE escalations SET status='superseded',reviewer='system:revoke',"
                "decided=?,disposition='revoked' WHERE task=? AND version=? "
                "AND status IN ('pending','acknowledged')",
                (time.time(), task, version),
            )

    def _evidence(self, job, args):
        shape(args, {"path", "sha256"})
        require(
            isinstance(args["sha256"], str) and HASH.fullmatch(args["sha256"]), "digest required"
        )
        workspace = Workspace(Path(job["input_root"]), Path(job["output_root"]))
        try:
            data = workspace.read("output", args["path"])
        finally:
            workspace.close()
        require(hashlib.sha256(data).hexdigest() == args["sha256"], "evidence changed")
        # Only the digest persists; content/path cannot leak through metadata exports.
        return args["sha256"]

    def request(self, token, request):
        require(isinstance(token, str) and len(token) == 64, "invalid capability")
        shape(request, {"tool", "input"})
        tool, args = request["tool"], request["input"]
        require(isinstance(tool, str) and isinstance(args, dict), "invalid RPC")
        with self.connect() as db:
            if tool != "task.status":
                db.execute("BEGIN IMMEDIATE")
            job = db.execute(
                "SELECT * FROM jobs WHERE token_hash=?",
                (hashlib.sha256(token.encode()).hexdigest(),),
            ).fetchone()
            require(
                job
                and hmac.compare_digest(
                    job["token_hash"], hashlib.sha256(token.encode()).hexdigest()
                )
                and job["status"] != "revoked",
                "capability denied",
            )
            policy = json.loads(job["policy"])
            if tool == "task.status":
                shape(args, set())
                return {"task": job["task"], "version": job["version"], "status": job["status"]}
            require(job["status"] == "assigned", "task not accepting writes")
            if tool == "parent_claude.result":
                digest = self._evidence(job, args)
                db.execute(
                    "UPDATE jobs SET status='proposed', result=? WHERE task=? AND version=?",
                    (digest, job["task"], job["version"]),
                )
                return {"status": "proposed", "sha256": digest}
            if tool == "task.escalate":
                shape(args, {"reason", "evidence", "authority"})
                require(
                    args["reason"] in REASONS and args["authority"] in AUTHORITIES,
                    "escalation denied",
                )
                require(
                    args["authority"] == REASON_AUTHORITY.get(args["reason"], "parent-claude"),
                    "wrong escalation authority",
                )
                digest = self._evidence(job, args["evidence"])
                eid = secrets.token_hex(16)
                destination = "parent-claude" if args["authority"] == "parent-claude" else "human"
                db.execute(
                    "INSERT INTO escalations VALUES (?,?,?,?,?,?,?,?,?,?,'pending',NULL,NULL,NULL)",
                    (
                        eid,
                        job["task"],
                        job["version"],
                        policy["worker"],
                        policy["data_class"],
                        args["reason"],
                        digest,
                        args["authority"],
                        destination,
                        time.time(),
                    ),
                )
                db.execute(
                    "UPDATE jobs SET status='waiting' WHERE task=? AND version=?",
                    (job["task"], job["version"]),
                )
                return {"id": eid, "status": "pending", "destination": destination}
            if tool == "public_web.read":
                shape(args, {"url"})
                require(
                    "public_web.read" in policy["capabilities"]
                    and args["url"] in policy["public_urls"],
                    "public URL denied",
                )
                digest = json.loads(job["public_reads"])[args["url"]]
                workspace = Workspace(Path(job["input_root"]), Path(job["output_root"]))
                try:
                    data = workspace.read("input", "public-" + digest + ".txt")
                finally:
                    workspace.close()
                require(hashlib.sha256(data).hexdigest() == digest, "public snapshot changed")
                return {
                    "text": data.decode("utf-8"),
                    "sha256": digest,
                    "source": "approved-snapshot",
                }
            raise Denied("unknown RPC denied")

    def inbox(self):
        with self.connect() as db:
            rows = db.execute("SELECT * FROM escalations ORDER BY created,id").fetchall()
        return [
            dict(row) | {"age_seconds": max(0, int(time.time() - row["created"]))} for row in rows
        ]

    def disposition(self, eid, reviewer, action):
        require(action in ("acknowledge", "reject", "retry"), "invalid disposition")
        human = isinstance(reviewer, str) and re.fullmatch(
            r"human-manager:[a-z0-9][a-z0-9._-]{0,63}", reviewer
        )
        claude = isinstance(reviewer, str) and re.fullmatch(
            r"parent-claude:[a-z0-9][a-z0-9._-]{0,127}", reviewer
        )
        require(claude or human, "identified reviewer required")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM escalations WHERE id=?", (eid,)).fetchone()
            require(row and row["status"] in ("pending", "acknowledged"), "escalation not pending")
            require(
                row["destination"] != "human" or human,
                "human authority required",
            )
            job = db.execute(
                "SELECT * FROM jobs WHERE task=? AND version=?", (row["task"], row["version"])
            ).fetchone()
            require(job and job["status"] == "waiting", "stale task disposition")
            require(
                not claude or reviewer.split(":", 1)[1] != json.loads(job["policy"])["worker"],
                "self disposition denied",
            )
            status = {
                "acknowledge": "acknowledged",
                "reject": "rejected",
                "retry": "authorized-retry",
            }[action]
            db.execute(
                "UPDATE escalations SET status=?,reviewer=?,decided=?,disposition=? WHERE id=?",
                (status, reviewer, time.time(), action, eid),
            )
            if action != "acknowledge":
                db.execute(
                    "UPDATE jobs SET status=? WHERE task=? AND version=?",
                    ("assigned" if action == "retry" else "revoked", row["task"], row["version"]),
                )

    def trusted_evidence(self, path):
        path = Path(path)
        require(path.absolute() == path.resolve(strict=True), "linked review evidence denied")
        meta = path.stat()
        require(
            stat.S_ISREG(meta.st_mode)
            and meta.st_nlink == 1
            and meta.st_uid == os.geteuid()
            and not meta.st_mode & 0o022,
            "trusted review evidence ownership required",
        )
        with self.connect() as db:
            for job in db.execute("SELECT input_root,output_root FROM jobs"):
                require(
                    not any(path.is_relative_to(Path(root)) for root in job),
                    "worker-root review evidence denied",
                )
        return path

    def record_review(self, task, version, candidate, reviewer, accepted, evidence, reviewer_run):
        require(reviewer == "parent-claude", "Claude review required")
        require(isinstance(candidate, str) and HASH.fullmatch(candidate), "candidate required")
        require(
            isinstance(reviewer_run, str)
            and re.fullmatch(r"parent-claude:[a-z0-9][a-z0-9._-]{0,127}", reviewer_run),
            "trusted Claude run reference required",
        )
        require(
            type(accepted) is bool and isinstance(evidence, str) and HASH.fullmatch(evidence),
            "review evidence required",
        )
        with self.connect() as db:
            job = db.execute(
                "SELECT * FROM jobs WHERE task=? AND version=?", (task, version)
            ).fetchone()
            require(job and job["status"] == "proposed", "task not proposed")
            worker = json.loads(job["policy"])["worker"]
            require(reviewer_run.split(":", 1)[1] != worker, "self approval denied")
            db.execute(
                "INSERT OR REPLACE INTO reviews VALUES (?,?,?,?,?,?,?,?)",
                (
                    task,
                    version,
                    candidate,
                    reviewer,
                    int(accepted),
                    evidence,
                    time.time(),
                    reviewer_run,
                ),
            )


class TaskServer(socketserver.UnixStreamServer):
    """One bounded RPC at a time. No request bodies, tokens or exceptions are logged."""

    def __init__(self, path, authority):
        self.authority = authority
        if os.path.lexists(path):
            meta = os.lstat(path)
            require(
                stat.S_ISSOCK(meta.st_mode) and meta.st_uid == os.geteuid(),
                "unexpected socket path",
            )
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(1)
                try:
                    probe.connect(path)
                except ConnectionRefusedError:
                    os.unlink(path)
                else:
                    raise Denied("broker already running")
        super().__init__(path, TaskHandler)
        os.chmod(path, 0o660)


class TaskHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(10)
        try:
            raw = self.rfile.readline(LIMIT + 1)
            require(len(raw) <= LIMIT, "RPC too large")
            envelope = json.loads(raw)
            shape(envelope, {"token", "request"})
            result = self.server.authority.request(envelope["token"], envelope["request"])
            response = {"ok": True, "result": result}
        except (ValueError, OSError, TypeError, KeyError, sqlite3.Error):
            response = {"ok": False, "error": "RPC denied"}
        with contextlib.suppress(OSError):
            self.wfile.write(json.dumps(response).encode() + b"\n")
