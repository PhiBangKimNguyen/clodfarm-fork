"""Trusted local operator interface for the F1c candidate (never a worker tool).

This starts no scheduler, inference, login or external notification. Input
approval, snapshot staging and the Claude review artifact are supplied by the
trusted operator. Tier 0 uses only clodfarm.tier0 and the task RPC.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

from .authority import Authority, TaskServer
from .isolation import tier0
from .tier0 import load_policy, require


def manager_authority():
    require(not tier0(), "worker administration denied")
    path = os.environ.get("FARM_AUTHORITY_DB", "")
    require(path and Path(path).is_absolute(), "supervisor authority database required")
    return Authority(Path(path))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    register = sub.add_parser("register")
    register.add_argument("--policy", type=Path, required=True)
    register.add_argument("--input", type=Path, required=True)
    register.add_argument("--output", type=Path, required=True)
    register.add_argument("--token-file", type=Path, required=True)
    register.add_argument("--policy-sha256", required=True)
    register.add_argument("--public-reads", type=Path)
    serve = sub.add_parser("serve")
    serve.add_argument("--socket", type=Path, required=True)
    sub.add_parser("inbox")
    disposition = sub.add_parser("disposition")
    disposition.add_argument("id")
    disposition.add_argument(
        "--reviewer", choices=["parent-claude", "human-manager"], required=True
    )
    disposition.add_argument("--action", choices=["acknowledge", "reject", "retry"], required=True)
    disposition.add_argument(
        "--actor",
        required=True,
        help="Named operator or independently checked Claude run reference",
    )
    for name in ("prepare", "candidate", "review", "land", "revoke", "reconcile"):
        p = sub.add_parser(name)
        p.add_argument("--task", required=True)
        p.add_argument("--version", type=int, required=True)
        if name != "revoke":
            p.add_argument("--repo", type=Path, required=True)
        if name == "prepare":
            p.add_argument("--path", action="append", required=True)
        if name == "review":
            p.add_argument("--claude-evidence", type=Path, required=True)
        if name in ("candidate", "review", "land"):
            p.add_argument("--verifier-image", required=True)
    args = parser.parse_args(argv)
    authority = manager_authority()
    if args.command == "register":
        roots = [p.resolve() for p in (args.input, args.output)]
        for root in roots:
            require(
                not authority.path.resolve().is_relative_to(root),
                "state inside worker mount denied",
            )
            require(
                not args.token_file.resolve().is_relative_to(root)
                and not args.policy.resolve().is_relative_to(root),
                "capability/policy inside writable workspace",
            )
        policy = load_policy(args.policy, args.policy_sha256)
        reads = json.loads(args.public_reads.read_text()) if args.public_reads else {}
        require(not args.token_file.exists(), "token file exists")
        token = authority.register(policy, args.input, args.output, reads)
        # Never print a bearer token. The operator mounts this file read-only.
        fd = os.open(args.token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(fd, "w") as output:
            output.write(token)
        print(json.dumps({"registered": policy["task"], "version": policy["version"]}))
    elif args.command == "serve":
        require(os.name == "posix", "Linux Unix socket required")
        require(args.socket.is_absolute(), "absolute supervisor socket required")
        with TaskServer(str(args.socket), authority) as server:
            server.serve_forever()
    elif args.command == "inbox":
        print(json.dumps(authority.inbox(), indent=2))
    elif args.command == "disposition":
        reviewer = args.reviewer
        if reviewer == "human-manager":
            require(args.actor, "named human operator required")
            reviewer += ":" + args.actor
        else:
            reviewer += ":" + args.actor
        authority.disposition(args.id, reviewer, args.action)
    elif args.command == "revoke":
        authority.revoke(args.task, args.version)
    else:
        from .landing import DockerVerifier, candidate, land, prepare, reconcile

        if args.command == "prepare":
            print(prepare(authority, args.repo, args.task, args.version, args.path))
            return 0
        if args.command == "reconcile":
            print(json.dumps(reconcile(authority, args.repo, args.task, args.version)))
            return 0
        verify = os.environ.get("FARM_VERIFY_CMD", "")
        record = candidate(
            args.repo,
            f"farm/{args.task}-v{args.version}",
            args.task,
            args.version,
            verify,
            args.verifier_image,
        )
        if args.command == "candidate":
            print(json.dumps(record, indent=2))
        elif args.command == "review":
            raw = authority.trusted_evidence(args.claude_evidence).read_bytes()
            require(len(raw) <= 262144, "review too large")
            verdict = json.loads(raw)
            require(
                isinstance(verdict, dict)
                and set(verdict)
                == {"task", "version", "candidate", "reviewer", "accepted", "reviewer_run"},
                "exact-candidate Claude verdict required",
            )
            require(
                verdict["task"] == args.task
                and verdict["version"] == args.version
                and verdict["candidate"] == record["identity"],
                "stale review artifact",
            )
            authority.record_review(
                args.task,
                args.version,
                record["identity"],
                verdict["reviewer"],
                verdict["accepted"],
                hashlib.sha256(raw).hexdigest(),
                verdict["reviewer_run"],
            )
        elif args.command == "land":
            print(
                json.dumps(
                    land(
                        authority,
                        args.repo,
                        args.task,
                        args.version,
                        verify,
                        DockerVerifier(args.verifier_image),
                    )
                )
            )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, TypeError):
        print("F1c operation denied; inspect the local candidate and gate inputs.", file=sys.stderr)
        sys.exit(1)
