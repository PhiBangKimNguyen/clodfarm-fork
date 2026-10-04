"""Offline F1c authority controls, including actual Git state transitions on Linux."""

import hashlib
import json
import os
import socket
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from clodfarm.authority import Authority, TaskServer
from clodfarm.tier0 import Denied, Tools, Workspace, load_policy, rpc, validate_policy

IMAGE = "sha256:" + "1" * 64


def policy(task="job-one", worker="worker-one", version=1):
    return {
        "format": "clodfarm.tier0/v1",
        "task": task,
        "worker": worker,
        "version": version,
        "data_class": "private_code_without_secrets",
        "input_approved": True,
        "capabilities": ["workspace.read", "workspace.edit", "parent_claude.result"],
        "public_urls": [],
        "input_files": {"hello.txt": hashlib.sha256(b"synthetic input").hexdigest()},
    }


@unittest.skipUnless(os.name == "posix", "Linux dirfd and isolation contract")
class JobFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input, self.output = self.root / "input", self.root / "output"
        self.input.mkdir()
        self.output.mkdir()
        (self.input / "hello.txt").write_text("synthetic input")
        self.workspace = Workspace(self.input, self.output)
        self.addCleanup(self.workspace.close)
        self.authority = Authority(self.root / "supervisor" / "authority.db")
        self.pol = policy()
        self.token = self.authority.register(self.pol, self.input, self.output)
        self.tools = Tools(
            self.pol, self.workspace, lambda req: self.authority.request(self.token, req)
        )

    def call(self, tool, args):
        return self.tools.execute({"tool": tool, "input": args})

    def proposal(self, content="synthetic proposal"):
        return self.call("workspace.edit", {"path": "proposal.txt", "content": content})


class IsolationTests(JobFixture):
    def test_stale_socket_is_recovered_and_non_socket_path_denied(self):
        path = self.root / "stale.sock"
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(str(path))
        stale.close()
        restarted = TaskServer(str(path), self.authority)
        restarted.server_close()
        path.unlink()
        path.write_text("unexpected file")
        with self.assertRaises(Denied):
            TaskServer(str(path), self.authority)

    def test_changed_or_unlisted_input_is_denied(self):
        (self.input / "hello.txt").write_text("changed after approval")
        (self.input / "unlisted.txt").write_text("not approved")
        for path in ("hello.txt", "unlisted.txt"):
            with self.assertRaises(Denied):
                self.call("workspace.read", {"area": "input", "path": path})

    def test_harmless_job_and_scoped_socket_result(self):
        self.assertEqual(
            self.call("workspace.read", {"area": "input", "path": "hello.txt"})["text"],
            "synthetic input",
        )
        evidence = self.proposal()
        server = TaskServer(str(self.root / "task.sock"), self.authority)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = rpc(
                str(self.root / "task.sock"),
                self.token,
                {"tool": "parent_claude.result", "input": evidence},
            )
            self.assertEqual(result["status"], "proposed")
            with self.assertRaises(Denied):
                self.call("parent_claude.result", evidence)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_shell_git_unknown_tools_and_worker_self_approval_denied(self):
        for tool in (
            "Bash",
            "BashOutput",
            "Read",
            "Write",
            "SendMessage",
            "Agent",
            "git.merge",
            "git.push",
            "farm.admin",
            "task.approve",
            "task.retry",
            "review",
            "mcp__farm__spawn",
        ):
            with self.subTest(tool=tool), self.assertRaises(Denied):
                self.call(tool, {"command": "clodfarm farm public"})
        for tool in ("review", "disposition", "farm.admin", "workspace.read", "task.retry"):
            with self.subTest(tool=tool), self.assertRaises(Denied):
                self.authority.request(self.token, {"tool": tool, "input": {}})

    def test_path_escape_and_other_worker_auth_state_denied(self):
        for path in (
            "../supervisor/authority.db",
            "/etc/passwd",
            "a/../../outside",
            "a\\..\\secret",
            ".git/config",
            ".env",
            ".env.production",
            ".codex/auth.json",
            ".claude/settings.json",
            "policy/job.json",
            ".farm/state.db",
            "./hello.txt",
            "a//b",
        ):
            with self.subTest(path=path), self.assertRaises((Denied, OSError)):
                self.call("workspace.read", {"area": "input", "path": path})
        with self.assertRaises(Denied):
            self.call("workspace.read", {"area": "worker-two", "path": "hello.txt"})
        with self.assertRaises(Denied):
            self.call("workspace.edit", {"area": "input", "path": "hello.txt", "content": "bad"})
        with self.assertRaises(Denied):
            self.call("task.status", {"task": "job-two"})

    def test_symlink_hardlink_and_fifo_denied(self):
        outside = self.root / "secret"
        outside.write_text("private sentinel")
        (self.input / "link").symlink_to(outside)
        (self.output / "dir-link").symlink_to(self.input, target_is_directory=True)
        os.link(outside, self.output / "hardlink")
        os.mkfifo(self.input / "pipe")
        for area, path in (("input", "link"), ("input", "pipe"), ("output", "hardlink")):
            with self.subTest(path=path), self.assertRaises((Denied, OSError)):
                self.workspace.read(area, path)
        for path in ("hardlink", "dir-link/hello.txt"):
            with self.assertRaises((Denied, OSError)):
                self.workspace.write(path, "bad")
        self.assertEqual(outside.read_text(), "private sentinel")

    def test_policy_missing_writable_invalid_or_digest_changed_denied(self):
        path = self.root / "policy.json"
        raw = json.dumps(self.pol).encode()
        path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        with self.assertRaises(Denied):
            load_policy(path, digest)
        path.chmod(0o444)
        self.assertEqual(load_policy(path, digest), self.pol)
        for expected in ("", "0" * 64):
            with self.assertRaises(Denied):
                load_policy(path, expected)
        with self.assertRaises(OSError):
            load_policy(self.root / "missing", digest)
        for field, value in (
            ("capabilities", ["shell"]),
            ("input_approved", False),
            ("version", True),
        ):
            bad = self.pol | {field: value}
            with self.subTest(field=field), self.assertRaises(Denied):
                validate_policy(bad)

    def test_escalations_survive_restart_and_require_correct_authority(self):
        evidence = self.proposal()
        args = {"reason": "credential-needed", "evidence": evidence, "authority": "credential"}
        item = self.call("task.escalate", args)
        restarted = Authority(self.authority.path)
        self.assertEqual(restarted.inbox()[0]["destination"], "human")
        self.assertGreaterEqual(restarted.inbox()[0]["age_seconds"], 0)
        with self.assertRaises(Denied):
            restarted.disposition(item["id"], "parent-claude", "retry")
        restarted.disposition(item["id"], "human-manager:operator", "acknowledge")
        self.assertEqual(self.call("task.status", {})["status"], "waiting")
        with self.assertRaises(Denied):
            self.call("parent_claude.result", evidence)
        restarted.disposition(item["id"], "human-manager:operator", "retry")
        self.assertEqual(self.call("task.status", {})["status"], "assigned")
        second = self.call(
            "task.escalate",
            {"reason": "needs-clarification", "evidence": evidence, "authority": "parent-claude"},
        )
        restarted.disposition(second["id"], "parent-claude", "reject")
        self.assertEqual(restarted.inbox()[1]["status"], "rejected")
        with self.assertRaises(Denied):
            self.call("task.status", {})

    def test_wrong_authority_stale_version_and_shared_mounts_denied(self):
        evidence = self.proposal()
        with self.assertRaises(Denied):
            self.call(
                "task.escalate",
                {"reason": "terms-decision", "evidence": evidence, "authority": "parent-claude"},
            )
        item = self.call(
            "task.escalate",
            {"reason": "needs-clarification", "evidence": evidence, "authority": "parent-claude"},
        )
        self.authority.register(policy(version=2), self.input, self.output)
        superseded = self.authority.inbox()[0]
        self.assertEqual(superseded["status"], "superseded")
        self.assertEqual(superseded["reviewer"], "system:version-advance")
        self.assertIsNotNone(superseded["decided"])
        with self.assertRaises(Denied):
            self.call("task.status", {})
        with self.assertRaises(Denied):
            self.authority.disposition(item["id"], "parent-claude", "retry")
        with self.assertRaises(Denied):
            self.authority.register(policy(version=1), self.input, self.output)
        with self.assertRaises(Denied):
            self.authority.register(
                policy(task="other-job", worker="worker-two"), self.input, self.output
            )

    def test_no_tokens_or_private_content_in_persistence_exports(self):
        secret = "synthetic-private-sentinel-with-token-sk-test-123456789"
        evidence = self.proposal(secret)
        self.call(
            "task.escalate",
            {"reason": "needs-clarification", "evidence": evidence, "authority": "parent-claude"},
        )
        exported = json.dumps(self.authority.inbox())
        database = self.authority.path.read_bytes()
        self.assertNotIn(secret.encode(), database)
        self.assertNotIn(self.token.encode(), database)
        self.assertNotIn(secret, exported)
        self.assertNotIn(self.token, exported)
        with self.assertRaises(Denied):
            self.call(
                "task.escalate",
                {"reason": secret, "evidence": evidence, "authority": "parent-claude"},
            )

    def test_registration_rejects_host_alias_and_private_public_input(self):
        alias = self.root / "alias"
        alias.symlink_to(self.input, target_is_directory=True)
        with self.assertRaisesRegex(Denied, "noncanonical host"):
            self.authority.register(policy(task="alias"), alias, self.output)
        public = policy(task="public") | {"data_class": "public_safe"}
        with self.assertRaisesRegex(Denied, "approved public snapshots"):
            self.authority.register(public, self.input, self.output)

    def test_cli_registration_checks_exact_policy_bytes_before_job_creation(self):
        from clodfarm.f1c import main

        path = self.root / "job.json"
        path.write_bytes(json.dumps(policy(task="registration")).encode())
        path.chmod(0o444)
        with (
            patch.dict(os.environ, {"FARM_AUTHORITY_DB": str(self.authority.path)}),
            self.assertRaisesRegex(Denied, "policy digest mismatch"),
        ):
            main(
                [
                    "register",
                    "--policy",
                    str(path),
                    "--policy-sha256",
                    "0" * 64,
                    "--input",
                    str(self.input),
                    "--output",
                    str(self.output),
                    "--token-file",
                    str(self.root / "token"),
                ]
            )
        with self.authority.connect() as db:
            self.assertFalse(db.execute("SELECT * FROM jobs WHERE task='registration'").fetchone())
        self.assertFalse((self.root / "token").exists())

    def test_status_remains_read_only_while_a_write_transaction_is_held(self):
        import concurrent.futures

        with self.authority.connect() as db, concurrent.futures.ThreadPoolExecutor() as pool:
            db.execute("BEGIN IMMEDIATE")
            response = pool.submit(
                self.authority.request, self.token, {"tool": "task.status", "input": {}}
            ).result(2)
            self.assertEqual(response["status"], "assigned")

    def test_public_reads_are_exact_preapproved_snapshots_without_network(self):
        pol = policy(task="public-job", worker="public-worker")
        pol["data_class"] = "public_safe"
        pol["capabilities"].append("public_web.read")
        pol["public_urls"] = ["https://example.com/news"]
        input_root, output_root = self.root / "public-input", self.root / "public-output"
        input_root.mkdir()
        output_root.mkdir()
        raw = b"explicitly approved synthetic public text"
        digest = hashlib.sha256(raw).hexdigest()
        pol["input_files"] = {"public-" + digest + ".txt": digest}
        (input_root / ("public-" + digest + ".txt")).write_bytes(raw)
        token = self.authority.register(
            pol, input_root, output_root, {pol["public_urls"][0]: digest}
        )
        self.assertEqual(
            self.authority.request(
                token, {"tool": "public_web.read", "input": {"url": pol["public_urls"][0]}}
            )["text"],
            raw.decode(),
        )
        with self.assertRaises(Denied):
            self.authority.request(
                token, {"tool": "public_web.read", "input": {"url": "https://example.com/private"}}
            )
        (input_root / ("public-" + digest + ".txt")).write_text("changed")
        with self.assertRaises(Denied):
            self.authority.request(
                token, {"tool": "public_web.read", "input": {"url": pol["public_urls"][0]}}
            )


@unittest.skipUnless(os.name == "posix", "Linux Git locking")
class LandingTests(JobFixture):
    def test_verifier_uses_all_committed_blobs_and_closed_docker_boundary(self):
        from clodfarm.landing import DockerVerifier, git, land, prepare

        (self.repo / ".gitattributes").write_text("proposal.txt export-ignore\n")
        git(self.repo, "add", ".gitattributes")
        git(self.repo, "commit", "-m", "attributes control")
        prepare(self.authority, self.repo, "job-one", 1, ["proposal.txt"])
        self.record()
        run = subprocess.run
        calls = []

        def inspect_command(args, **kwargs):
            if args[0] != "docker":
                return run(args, **kwargs)
            calls.append(args)
            if args[1] == "run":
                mount = next(
                    a for a in args if isinstance(a, str) and a.startswith("type=bind,src=")
                )
                root = Path(mount.split("src=", 1)[1].split(",dst=", 1)[0])
                self.assertEqual((root / "proposal.txt").read_text(), "synthetic proposal")
                self.assertTrue((root / ".gitattributes").exists())
                for flag in (
                    "--network=none",
                    "--read-only",
                    "--cap-drop=ALL",
                    "--log-driver=none",
                    "--security-opt=no-new-privileges",
                    "--user=10001:10001",
                ):
                    self.assertIn(flag, args)
                self.assertNotIn("/var/run/docker.sock", " ".join(args))
                self.assertNotIn("env", kwargs)
            return subprocess.CompletedProcess(args, 0)

        with patch("clodfarm.landing.subprocess.run", side_effect=inspect_command):
            land(self.authority, self.repo, "job-one", 1, "true", DockerVerifier(IMAGE))
        self.assertEqual([c[1] for c in calls], ["run", "rm"])

    def setUp(self):
        super().setUp()
        from clodfarm.landing import git, prepare

        git_environment = patch.dict(
            os.environ, {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        )
        git_environment.start()
        self.addCleanup(git_environment.stop)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-b", "main")
        git(self.repo, "config", "user.name", "Test")
        git(self.repo, "config", "user.email", "test@localhost")
        (self.repo / "base.txt").write_text("base")
        git(self.repo, "add", "base.txt")
        git(self.repo, "commit", "-m", "base")
        self.base = git(self.repo, "rev-parse", "HEAD")
        evidence = self.proposal()
        self.call("parent_claude.result", evidence)
        self.branch = prepare(self.authority, self.repo, "job-one", 1, ["proposal.txt"])
        self.old_push = os.environ.get("FARM_PUSH")
        os.environ["FARM_PUSH"] = "0"
        self.addCleanup(self.restore_push)

    def restore_push(self):
        if self.old_push is None:
            os.environ.pop("FARM_PUSH", None)
        else:
            os.environ["FARM_PUSH"] = self.old_push

    def record(self, accepted=True, cmd="true", image=IMAGE):
        from clodfarm.landing import candidate

        record = candidate(self.repo, self.branch, "job-one", 1, cmd, image)
        self.authority.record_review(
            "job-one",
            1,
            record["identity"],
            "parent-claude",
            accepted,
            "a" * 64,
            "parent-claude:trusted-test",
        )
        return record

    def verifier(self, passed=True, mutate=None, image=IMAGE):
        from clodfarm.landing import DockerVerifier

        class Verifier(DockerVerifier):
            def __call__(self, repo, record, command):
                if mutate:
                    mutate(repo)
                return passed

        return Verifier(image)

    def test_required_verification_and_missing_rejected_self_review(self):
        from clodfarm.landing import git, land

        for cmd in ("true",):
            with self.subTest(cmd=cmd), self.assertRaises(Denied):
                land(self.authority, self.repo, "job-one", 1, cmd, self.verifier())
        with self.assertRaises(Denied):
            self.authority.record_review(
                "job-one", 1, "a" * 64, "worker-one", True, "b" * 64, "parent-claude:trusted-test"
            )
        self.record(False)
        with self.assertRaises(Denied):
            land(self.authority, self.repo, "job-one", 1, "true", self.verifier())
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.base)

    def test_failed_verification_and_changed_command_or_image_block_landing(self):
        from clodfarm.landing import git, land

        self.record()
        for cmd, verifier in (
            ("true", self.verifier(False)),
            ("false", self.verifier()),
            ("true", self.verifier(image="sha256:" + "2" * 64)),
        ):
            with self.subTest(cmd=cmd), self.assertRaises(Denied):
                land(self.authority, self.repo, "job-one", 1, cmd, verifier)
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.base)

    def test_candidate_or_base_changed_before_or_during_verify_blocked(self):
        from clodfarm.landing import git, land

        self.record()

        def mutate(repo):
            (repo / "new.txt").write_text("new main")
            git(repo, "add", "new.txt")
            git(repo, "commit", "-m", "new main")

        with self.assertRaises(Denied):
            land(self.authority, self.repo, "job-one", 1, "true", self.verifier(mutate=mutate))
        self.assertFalse((self.repo / "proposal.txt").exists())
        with self.assertRaises(Denied):
            land(self.authority, self.repo, "job-one", 1, "true", self.verifier())

    def test_candidate_mutation_requires_new_verdict_and_success_is_local_once(self):
        from clodfarm.landing import land, prepare

        self.record()
        self.workspace.write("proposal.txt", "changed proposal")
        prepare(self.authority, self.repo, "job-one", 1, ["proposal.txt"])
        with self.assertRaises(Denied):
            land(self.authority, self.repo, "job-one", 1, "true", self.verifier())
        record = self.record()
        result = land(self.authority, self.repo, "job-one", 1, "true", self.verifier())
        self.assertEqual(result["commit"], record["commit"])
        self.assertEqual((self.repo / "proposal.txt").read_text(), "changed proposal")
        with self.assertRaises(Denied):
            land(self.authority, self.repo, "job-one", 1, "true", self.verifier())
        with self.assertRaises(Denied):
            self.call("task.status", {})

    def test_each_gate_from_valid_review_has_specific_denial(self):
        from clodfarm.landing import git, land

        self.record()
        for command in ("", " "):
            with (
                self.subTest(command=command),
                self.assertRaisesRegex(Denied, "verification required"),
            ):
                land(self.authority, self.repo, "job-one", 1, command, self.verifier())
        for push in (None, "1", "false"):
            with self.subTest(push=push), patch.dict(os.environ, {}, clear=False):
                if push is None:
                    os.environ.pop("FARM_PUSH", None)
                else:
                    os.environ["FARM_PUSH"] = push
                with self.assertRaisesRegex(Denied, "FARM_PUSH=0 required"):
                    land(self.authority, self.repo, "job-one", 1, "true", self.verifier())
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.base)

    def test_review_evidence_worker_root_and_self_run_are_denied(self):
        record = self.record()
        from clodfarm.f1c import main

        path = self.output / "verdict.json"
        path.write_text(
            json.dumps(
                {
                    "task": "job-one",
                    "version": 1,
                    "candidate": record["identity"],
                    "reviewer": "parent-claude",
                    "accepted": True,
                    "reviewer_run": "parent-claude:trusted-test",
                }
            )
        )
        with self.assertRaisesRegex(Denied, "worker-root review evidence denied"):
            self.authority.trusted_evidence(path)
        with (
            patch.dict(
                os.environ,
                {"FARM_AUTHORITY_DB": str(self.authority.path), "FARM_VERIFY_CMD": "true"},
            ),
            self.assertRaisesRegex(Denied, "worker-root review evidence denied"),
        ):
            main(
                [
                    "review",
                    "--task",
                    "job-one",
                    "--version",
                    "1",
                    "--repo",
                    str(self.repo),
                    "--verifier-image",
                    IMAGE,
                    "--claude-evidence",
                    str(path),
                ]
            )
        with self.assertRaisesRegex(Denied, "self approval denied"):
            self.authority.record_review(
                "job-one", 1, "a" * 64, "parent-claude", True, "b" * 64, "parent-claude:worker-one"
            )
        path = self.root / "trusted-verdict.json"
        path.write_text("{}")
        path.chmod(0o600)
        self.assertEqual(self.authority.trusted_evidence(path), path)

    def test_git_attributes_and_host_filters_cannot_execute_at_landing(self):
        from clodfarm.landing import git, land, prepare

        self.workspace.write(".gitattributes", "* filter=untrusted")
        with self.assertRaisesRegex(Denied, "Git configuration proposal denied"):
            prepare(self.authority, self.repo, "job-one", 1, [".gitattributes"])
        self.record()
        git(self.repo, "config", "filter.untrusted.smudge", "touch /tmp/should-not-run")
        with self.assertRaisesRegex(Denied, "host Git filters denied"):
            land(self.authority, self.repo, "job-one", 1, "true", self.verifier())
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.base)

    def test_slow_verification_does_not_block_other_task_escalation_or_disposition(self):
        import concurrent.futures

        from clodfarm.landing import land

        other_input, other_output = self.root / "other-input", self.root / "other-output"
        other_input.mkdir()
        other_output.mkdir()
        (other_input / "hello.txt").write_bytes(b"synthetic input")
        (other_output / "question.txt").write_bytes(b"question")
        token = self.authority.register(
            policy(task="other", worker="other-worker"), other_input, other_output
        )
        evidence = {"path": "question.txt", "sha256": hashlib.sha256(b"question").hexdigest()}
        self.record()
        started, release = threading.Event(), threading.Event()

        def slow(repo):
            started.set()
            if not release.wait(10):
                raise AssertionError("RPC blocked by verifier transaction")

        with concurrent.futures.ThreadPoolExecutor() as pool:
            pending = pool.submit(
                land, self.authority, self.repo, "job-one", 1, "true", self.verifier(mutate=slow)
            )
            self.assertTrue(started.wait(5))
            try:
                status = pool.submit(
                    self.authority.request, token, {"tool": "task.status", "input": {}}
                ).result(2)
                self.assertEqual(status["status"], "assigned")
                item = pool.submit(
                    self.authority.request,
                    token,
                    {
                        "tool": "task.escalate",
                        "input": {
                            "reason": "needs-clarification",
                            "authority": "parent-claude",
                            "evidence": evidence,
                        },
                    },
                ).result(2)
                pool.submit(
                    self.authority.disposition, item["id"], "parent-claude", "retry"
                ).result(2)
                self.assertEqual(self.authority.inbox()[0]["status"], "authorized-retry")
            finally:
                release.set()
            self.assertEqual(pending.result(5)["status"], "landed-locally")

    def test_reset_failure_has_durable_intent_and_explicit_reconciliation(self):
        from clodfarm import landing

        self.record()
        real_git = landing.git

        def fail_reset(repo, *args, **kwargs):
            if "reset" in args:
                raise Denied("injected reset failure")
            return real_git(repo, *args, **kwargs)

        with (
            patch("clodfarm.landing.git", side_effect=fail_reset),
            self.assertRaisesRegex(Denied, "injected reset failure"),
        ):
            landing.land(self.authority, self.repo, "job-one", 1, "true", self.verifier())
        restarted = Authority(self.authority.path)
        with restarted.connect() as db:
            intent = db.execute("SELECT * FROM landing_intents").fetchone()
            self.assertIsNotNone(intent)
            self.assertFalse(db.execute("SELECT * FROM landings").fetchone())
        with self.assertRaisesRegex(Denied, "inspect and repair"):
            landing.reconcile(restarted, self.repo, "job-one", 1)
        real_git(self.repo, "reset", "--hard", intent["commit_id"])
        self.assertEqual(
            landing.reconcile(restarted, self.repo, "job-one", 1)["status"], "landed-locally"
        )
        with restarted.connect() as db:
            self.assertFalse(db.execute("SELECT * FROM landing_intents").fetchone())
            self.assertTrue(db.execute("SELECT * FROM landings").fetchone())

    def test_crash_after_reset_reconciles_without_reexecuting_candidate(self):
        from clodfarm import landing

        self.record()
        with (
            patch("clodfarm.landing._finish", side_effect=RuntimeError("injected crash")),
            self.assertRaisesRegex(RuntimeError, "injected crash"),
        ):
            landing.land(self.authority, self.repo, "job-one", 1, "true", self.verifier())
        self.assertEqual(
            landing.reconcile(Authority(self.authority.path), self.repo, "job-one", 1)["status"],
            "landed-locally",
        )

    @unittest.skipUnless(os.environ.get("F1C_SMOKE_IMAGE"), "opt-in actual Docker verifier")
    def test_real_networkless_verifier_pass_failure_and_private_environment(self):
        from clodfarm.landing import DockerVerifier, git, land

        image = os.environ["F1C_SMOKE_IMAGE"]
        self.record(cmd="exit 3", image=image)
        with self.assertRaisesRegex(Denied, "verification failed"):
            land(self.authority, self.repo, "job-one", 1, "exit 3", DockerVerifier(image))
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.base)
        command = (
            'test -f /workspace/proposal.txt && python -c "import os; '
            "assert not os.path.exists('/candidate/.git'); "
            "assert 'F1C_PRIVATE_SENTINEL' not in os.environ; "
            "assert not os.path.exists('/rpc/task.sock')\""
        )
        os.environ["F1C_PRIVATE_SENTINEL"] = "must-never-enter-verifier"
        self.addCleanup(os.environ.pop, "F1C_PRIVATE_SENTINEL", None)
        self.record(cmd=command, image=image)
        land(self.authority, self.repo, "job-one", 1, command, DockerVerifier(image))


class LegacyIsolationTests(unittest.TestCase):
    flags = (None, "1", "true", "unexpected", "")

    def flag(self, value):
        if value is None:
            os.environ.pop("FARM_REQUIRE_ISOLATION", None)
        else:
            os.environ["FARM_REQUIRE_ISOLATION"] = value

    def test_shared_runner_denied_before_run_directory_or_environment_persistence(self):
        from clodfarm import runner

        for flag in self.flags:
            with (
                self.subTest(flag=flag),
                tempfile.TemporaryDirectory() as tmp,
                patch.dict(os.environ),
            ):
                self.flag(flag)
                root = Path(tmp)
                sentinel = "private-sentinel-sk-test-123456789"
                with (
                    patch("clodfarm.runner.subprocess.run") as spawn,
                    self.assertRaisesRegex(ValueError, "persistence disabled"),
                ):
                    runner.start_run(
                        tmp,
                        str(root / "run"),
                        ["unused"],
                        tmp,
                        {"SECRET": sentinel},
                        stdin=sentinel,
                    )
                spawn.assert_not_called()
                self.assertFalse((root / "run").exists())
                self.assertNotIn(
                    sentinel, "".join(p.read_text() for p in root.rglob("*") if p.is_file())
                )

    def test_direct_git_merge_denied_before_git_execution(self):
        from clodfarm import gitops

        for flag in self.flags:
            with (
                self.subTest(flag=flag),
                patch.dict(os.environ),
                patch("clodfarm.gitops.git") as git,
            ):
                self.flag(flag)
                with self.assertRaisesRegex(gitops.GitError, "trusted F1c"):
                    gitops.merge("unused", "unused", "farm/test")
                git.assert_not_called()

    def test_legacy_dispatch_denied_before_startup(self):
        from clodfarm.supervisor import Farm

        for flag in self.flags:
            with self.subTest(flag=flag), patch.dict(os.environ):
                self.flag(flag)
                with self.assertRaisesRegex(ValueError, "Legacy shared runner disabled"):
                    Farm.__new__(Farm).run()

    def test_supervisor_landing_keeps_proposal_without_store_or_git_access(self):
        from clodfarm.supervisor import Farm

        for flag in self.flags:
            with self.subTest(flag=flag), patch.dict(os.environ):
                self.flag(flag)
                self.assertEqual(
                    Farm.__new__(Farm).land({}, "unused", "farm/test", None)[1], "review_required"
                )

    def test_flag_has_only_explicit_opt_outs(self):
        from clodfarm.isolation import isolation_required

        for value in ("0", "false", "off", "no"):
            self.assertFalse(isolation_required({"FARM_REQUIRE_ISOLATION": value}))
        for value in ("", "true", "1", "typo"):
            self.assertTrue(isolation_required({"FARM_REQUIRE_ISOLATION": value}))


if __name__ == "__main__":
    unittest.main()
