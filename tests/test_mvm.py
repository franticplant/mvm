"""Unit tests for bin/mvm (stdlib unittest, no KVM/podman required)."""

from __future__ import annotations

import fcntl
import importlib.machinery
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def load_mvm():
    repo_root = Path(__file__).resolve().parent.parent
    script = repo_root / "bin" / "mvm"
    loader = importlib.machinery.SourceFileLoader("mvm_mod", str(script))
    spec = importlib.util.spec_from_loader("mvm_mod", loader)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class TestMvm(unittest.TestCase):
    def setUp(self):
        self.mvm = load_mvm()
        self.tmp = tempfile.TemporaryDirectory()
        self.mvm.CACHE_ROOT = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_invalid_cache_names_rejected(self):
        for bad in ("", ".", "..", "a/b", "/etc/passwd"):
            with self.assertRaises(SystemExit):
                self.mvm.cache_img_path(bad)

    def test_cache_init_ls_grow_rm(self):
        rc = self.mvm.cmd_cache(["init", "demo", "16M"])
        self.assertEqual(rc, 0)
        img = self.mvm.cache_img_path("demo")
        self.assertTrue(img.is_file())
        self.assertEqual(img.stat().st_size, 16 * 1024 * 1024)

        rc = self.mvm.cmd_cache(["grow", "demo", "32M"])
        self.assertEqual(rc, 0)
        self.assertEqual(img.stat().st_size, 32 * 1024 * 1024)

        rc = self.mvm.cmd_cache(["rm", "demo"])
        self.assertEqual(rc, 0)
        self.assertFalse(img.exists())

    def test_cache_import_populates_ext4(self):
        src = Path(self.tmp.name) / "src-cache"
        src.mkdir()
        (src / "hello.txt").write_text("hi from host\n")

        rc = self.mvm.cmd_cache(["import", "imported", str(src), "16M"])
        self.assertEqual(rc, 0)
        img = self.mvm.cache_img_path("imported")
        self.assertTrue(img.is_file())

    def test_flock_shared_and_exclusive(self):
        # Shared locks can be acquired concurrently
        locks1 = self.mvm.acquire_locks([("shared", "/m", False, "16M")])
        locks2 = self.mvm.acquire_locks([("shared", "/m", False, "16M")])
        try:
            # Exclusive non-blocking lock must fail while shared locks are held
            with open(self.mvm.cache_lock_path("shared"), "w") as probe:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            self.mvm.release_locks(locks2)
            self.mvm.release_locks(locks1)

        # After release, exclusive lock succeeds
        with open(self.mvm.cache_lock_path("shared"), "w") as probe:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(probe, fcntl.LOCK_UN)

    def test_go_profile_offline_vs_net_podman_command(self):
        # Pre-create tiny cache images so ensure_cache_img does not run mkfs
        for name in ("go-mod", "go-build"):
            self.mvm.cache_img_path(name).write_bytes(b"")

        captured = []

        def fake_run(cmd, *args, **kwargs):
            captured.append(cmd)
            return subprocess.CompletedProcess(cmd, 0)

        with mock.patch.object(subprocess, "run", side_effect=fake_run):
            rc = self.mvm.main(["--go", "--", "go", "version"])
            self.assertEqual(rc, 0)
            offline_cmd = captured[-1]

            rc = self.mvm.main(["--net", "--go", "--", "go", "mod", "download"])
            self.assertEqual(rc, 0)
            net_cmd = captured[-1]

        # Offline: --runtime krun, --network=none, /src:ro,z, go-mod ro
        self.assertIn("--runtime", offline_cmd)
        self.assertIn("krun", offline_cmd)
        self.assertIn("--network=none", offline_cmd)
        self.assertTrue(any(arg.endswith(":/src:ro,z") for arg in offline_cmd))
        self.assertTrue(any("go-mod.img:/run/mvm-imgs/0-go-mod.img:ro,z" in arg for arg in offline_cmd))
        self.assertIn("mount -o loop,ro", offline_cmd[-1])
        self.assertIn("trap cleanup EXIT", offline_cmd[-1])

        # Online: no --network=none, go-mod upgraded to rw
        self.assertNotIn("--network=none", net_cmd)
        self.assertTrue(any("go-mod.img:/run/mvm-imgs/0-go-mod.img:z" in arg for arg in net_cmd))
        self.assertNotIn("mount -o loop,ro", net_cmd[-1])

    def test_crun_rejects_cache_mounts(self):
        with self.assertRaises(SystemExit):
            self.mvm.main(["--crun", "--go", "--", "go", "version"])

    def test_shell_quoting_in_wrapper(self):
        self.mvm.cache_img_path("c1").write_bytes(b"")
        captured = []

        def fake_run(cmd, *args, **kwargs):
            captured.append(cmd)
            return subprocess.CompletedProcess(cmd, 0)

        with mock.patch.object(subprocess, "run", side_effect=fake_run):
            rc = self.mvm.main(
                ["-i", "alpine:latest", "-c", "c1:/mnt/c1", "--", "echo", "hello world; rm -rf /"]
            )
            self.assertEqual(rc, 0)

        wrapper = captured[-1][-1]
        self.assertIn("echo 'hello world; rm -rf /'", wrapper)


if __name__ == "__main__":
    unittest.main()
