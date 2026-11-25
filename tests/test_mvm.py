"""Tests for bin/mvm (stdlib unittest).

Unit tests need no podman/KVM. Real tests (class RealTests) boot krun microVMs
and run only with MVM_REAL=1; each takes a few seconds.
"""

from __future__ import annotations

import fcntl
import importlib.machinery
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "bin" / "mvm"


def load_mvm():
    loader = importlib.machinery.SourceFileLoader("mvm_mod", str(SCRIPT))
    spec = importlib.util.spec_from_loader("mvm_mod", loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["mvm_mod"] = mod          # dataclasses resolve annotations via sys.modules
    loader.exec_module(mod)
    return mod


class Base(unittest.TestCase):
    def setUp(self):
        self.mvm = load_mvm()
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.mvm.CACHE_ROOT = t / "cache"
        self.mvm.STATE_ROOT = t / "state"
        self.mvm.CONFIG_PATH = t / "config.toml"
        self.proj = t / "proj"
        self.proj.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel: str, text: str = "") -> Path:
        p = self.proj / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p


class ProjectTests(Base):
    def test_invalid_cache_names_rejected(self):
        for bad in ("", ".", "..", "a/b", "/etc/passwd", "-x"):
            with self.assertRaises(SystemExit):
                self.mvm.cache_img(bad)

    def test_detect_ecosystems(self):
        self.assertEqual(self.mvm.detect_ecos(self.proj), [])
        self.write("go.mod", "module x\n")
        self.write("package.json", "{}")
        self.assertEqual(self.mvm.detect_ecos(self.proj), ["go", "node"])

    def test_fetch_tree_has_only_manifests(self):
        self.write("go.mod", "module x\n")
        self.write("go.sum")
        self.write("main.go", "package main")
        self.write(".env", "SECRET=1")
        self.write("sub/go.mod", "module y\n")
        self.write("node_modules/dep/go.mod")          # skipped dir
        out = Path(self.tmp.name) / "tree"
        out.mkdir()
        self.mvm.manifest_tree(self.proj, self.mvm.ECOS["go"], out)
        files = sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file())
        self.assertEqual(files, ["go.mod", "go.sum", "sub/go.mod"])

    def test_fetch_tree_stubs_cargo_targets(self):
        self.write("Cargo.toml", '[package]\nname="a"\n[[bin]]\nname="t"\npath="tools/t.rs"\n')
        self.write("Cargo.lock")
        self.write("src/lib.rs", "pub fn secret() {}")
        self.write("tools/t.rs", "fn main() {}")
        out = Path(self.tmp.name) / "tree"
        out.mkdir()
        self.mvm.manifest_tree(self.proj, self.mvm.ECOS["rust"], out)
        self.assertEqual((out / "src/lib.rs").read_text(), "")      # stub, no source
        self.assertEqual((out / "tools/t.rs").read_text(), "")
        self.assertFalse((out / "src/main.rs").exists())             # absent stays absent

    def test_only_changed_manifests_flow_back(self):
        self.write("package.json", '{"a":1}')
        self.write("package-lock.json", "old")
        tree = Path(self.tmp.name) / "tree"
        (tree / "node_modules").mkdir(parents=True)
        (tree / "package.json").write_text('{"a":1}')          # unchanged
        (tree / "package-lock.json").write_text("new")          # changed
        (tree / "evil.js").write_text("x")                      # not a manifest
        (tree / "sub").mkdir()
        (tree / "sub" / "package.json").write_text("{}")        # new manifest
        got = self.mvm.changed_manifests(self.proj, tree, self.mvm.ECOS["node"])
        self.assertEqual(got, ["package-lock.json", "sub/package.json"])

    def test_symlinks_in_fetch_tree_never_followed(self):
        """A hostile fetch VM may plant symlinks; host files must never be copied in."""
        secret = Path(self.tmp.name) / "id_ed25519"
        secret.write_text("PRIVATE KEY")
        (Path(self.tmp.name) / "outside").mkdir()
        (Path(self.tmp.name) / "outside" / "go.mod").write_text("STOLEN")
        self.write("go.mod", "module x\n")
        tree = Path(self.tmp.name) / "tree"
        tree.mkdir()
        (tree / "go.mod").symlink_to(secret)                       # file symlink
        (tree / "sub").symlink_to(Path(self.tmp.name) / "outside") # dir symlink
        (tree / "real").mkdir()
        (tree / "real" / "go.sum").write_text("ok")
        got = self.mvm.changed_manifests(self.proj, tree, self.mvm.ECOS["go"])
        self.assertEqual(got, ["real/go.sum"])
        os.unlink(tree / "real" / "go.sum")
        (tree / "real" / "go.sum").symlink_to(secret)              # swapped after vetting
        with self.assertRaises(OSError):
            self.mvm.copy_back(tree, self.proj, "real/go.sum")
        self.assertFalse((self.proj / "real" / "go.sum").exists())

    def test_masks_found_and_skip_dirs_ignored(self):
        (self.proj / ".git").mkdir()
        self.write(".env", "x")
        self.write("deploy/.env.prod", "x")
        self.write("certs/tls.key", "x")
        self.write("node_modules/pkg/.env", "x")        # inside a skipped dir
        self.write("README.md")
        dirs, files = self.mvm.find_masks(self.proj, self.mvm.DEFAULT_MASK)
        self.assertEqual(dirs, [".git"])
        self.assertEqual(files, [".env", "certs/tls.key", "deploy/.env.prod"])

    def test_writable_dir_must_stay_inside_project(self):
        self.assertEqual(self.mvm.check_writable(self.proj, ["out/bin"]), ["out/bin"])
        self.assertTrue((self.proj / "out/bin").is_dir())
        for bad in ("..", ".", "../elsewhere", "/tmp"):
            with self.assertRaises(SystemExit):
                self.mvm.check_writable(self.proj, [bad])

    def test_parse_opts(self):
        opts, cmd = self.mvm.parse_opts(["go", "-w", "b", "--it", "--", "go", "build"], False)
        self.assertEqual((opts["positional"], opts["writable"], opts["interactive"]), (["go"], ["b"], True))
        self.assertEqual(cmd, ["go", "build"])
        for bad in (["--net", "--", "x"], ["-i", "img", "--", "x"], ["go"], ["--"]):
            with self.assertRaises(SystemExit):
                self.mvm.parse_opts(bad, False)

    def test_image_repo_strips_tag_not_port(self):
        self.assertEqual(self.mvm.image_repo("docker.io/library/golang:1.27-alpine"), "docker.io/library/golang")
        self.assertEqual(self.mvm.image_repo("localhost:5000/x"), "localhost:5000/x")
        self.assertEqual(self.mvm.image_repo("localhost:5000/x:t"), "localhost:5000/x")


class PodmanArgvTests(Base):
    def plan(self, **kw):
        base = dict(kind="build", eco="go", image="img@sha256:abc", memory="2g",
                    cmd=["echo", "hello world; rm -rf /"], src=self.proj)
        base.update(kw)
        return self.mvm.Plan(**base)

    def test_offline_by_default_and_masks_and_quoting(self):
        C = self.mvm.Cache
        p = self.plan(caches=[C("go-mod", "/cache/go-mod", False), C("go-build", "/cache/go-build", True)],
                      writable=["build"], masks=([".git"], [".env"]))
        argv = self.mvm.podman_argv(p, "RID", {"go-mod": Path("/c/go-mod.img"), "go-build": Path("/c/copy")},
                                    Path("/empty"))
        joined = " ".join(argv)
        self.assertIn("--network=none", argv)
        self.assertIn(f"{self.proj}:/src:ro,z", argv)
        self.assertIn("/empty:/src/.git:ro,z", argv)
        self.assertIn("/dev/null:/src/.env:ro", argv)
        self.assertIn(f"{self.proj}/build:/src/build:z", argv)
        self.assertIn("/c/go-mod.img:/run/mvm-imgs/0-go-mod.img:ro,z", argv)
        self.assertIn("/c/copy:/run/mvm-imgs/1-go-build.img:z", argv)
        self.assertIn("mount -o loop,ro", argv[-1])
        self.assertIn("echo 'hello world; rm -rf /'", argv[-1])
        self.assertIn("--runtime krun", joined)

    def test_mask_inside_writable_dir_still_hides(self):
        p = self.plan(writable=["config"], masks=([], ["config/.env"]))
        argv = self.mvm.podman_argv(p, "RID", {}, Path("/e"))
        w = argv.index(f"{self.proj}/config:/src/config:z")
        m = argv.index("/dev/null:/src/config/.env:ro")
        self.assertLess(w, m)        # podman applies mounts in order; the mask must come last

    def test_fetch_has_network(self):
        argv = self.mvm.podman_argv(self.plan(kind="fetch", net=True), "RID", {}, Path("/e"))
        self.assertNotIn("--network=none", argv)


class CommitTests(Base):
    """Commit-on-clean: writes reach the cache only when the command exits 0."""

    def setUp(self):
        super().setUp()
        self.cache = self.mvm.Cache("c1", "/c1", True, "16M")
        self.mvm.ensure_cache(self.cache)
        self.img = self.mvm.cache_img("c1")
        self.img.write_bytes(b"ORIGINAL")

    def run_with(self, behaviour):
        def fake(argv):
            # the mounted image is the run copy, never the real cache
            src = next(a for a in argv if a.endswith(":/run/mvm-imgs/0-c1.img:z")).split(":")[0]
            self.assertIn(".img.run-", src)
            Path(src).write_bytes(b"WRITTEN")
            return behaviour()
        plan = self.mvm.Plan(kind="build", eco="go", image="i", memory="1g", cmd=["x"],
                             src=None, caches=[self.cache])
        with mock.patch.object(self.mvm, "run_podman", side_effect=fake), \
                mock.patch.object(self.mvm, "reap_orphans", return_value=[]), \
                mock.patch.object(self.mvm, "kill_container"):
            return self.mvm.execute(plan)

    def gen(self):
        return self.mvm.read_json(self.mvm.cache_meta("c1"), {})["generation"]

    def last_record(self):
        return json.loads(sorted((self.mvm.STATE_ROOT / "runs").glob("*.json"))[-1].read_text())

    def test_exit_0_commits(self):
        self.assertEqual(self.run_with(lambda: 0), 0)
        self.assertEqual(self.img.read_bytes(), b"WRITTEN")
        self.assertEqual(self.gen(), 1)
        self.assertEqual(self.last_record()["result"], "committed")
        self.assertEqual(self.mvm.run_copies("c1"), [])

    def test_failure_discards(self):
        self.assertEqual(self.run_with(lambda: 1), 1)
        self.assertEqual(self.img.read_bytes(), b"ORIGINAL")
        self.assertEqual(self.gen(), 0)
        self.assertEqual(self.last_record()["result"], "failed")
        self.assertEqual(self.mvm.run_copies("c1"), [])

    def test_interrupt_discards(self):
        def boom():
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.run_with(boom)
        self.assertEqual(self.img.read_bytes(), b"ORIGINAL")
        self.assertEqual(self.last_record()["result"], "interrupted")
        self.assertEqual(self.mvm.run_copies("c1"), [])

    def test_stale_copy_removed_next_run(self):
        stale = self.img.with_name("c1.img.run-old")
        stale.write_bytes(b"POISON")
        self.run_with(lambda: 0)
        self.assertFalse(stale.exists())


class LockTests(Base):
    def test_shared_and_exclusive(self):
        C = self.mvm.Cache
        with self.mvm.Locks([C("s", "/m", False)]), self.mvm.Locks([C("s", "/m", False)]):
            with open(self.mvm.cache_lock("s"), "a") as probe:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_cache_rm_refuses_while_in_use(self):
        c = self.mvm.Cache("busy", "/m", True, "16M")
        self.mvm.ensure_cache(c)
        with self.mvm.Locks([c]):
            with self.assertRaises(SystemExit):
                self.mvm.cmd_cache(["rm", "busy"])
        self.assertEqual(self.mvm.cmd_cache(["rm", "busy"]), 0)
        self.assertFalse(self.mvm.cache_img("busy").exists())


# ---------------------------------------------------------------- real microVM tests

GO_IMAGE = "docker.io/library/golang:1.27-alpine"


@unittest.skipUnless(os.environ.get("MVM_REAL") == "1", "set MVM_REAL=1 to boot real krun microVMs")
class RealTests(unittest.TestCase):
    """Each test boots one or two microVMs and takes a few seconds."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path.home() / ".cache")   # btrfs for reflinks
        t = Path(self.tmp.name)
        self.env = {**os.environ, "MVM_CACHE_DIR": str(t / "cache"),
                    "MVM_STATE_DIR": str(t / "state"), "MVM_CONFIG": str(t / "none.toml")}
        self.proj = t / "proj"
        self.proj.mkdir()
        (self.proj / "go.mod").write_text("module example.com/x\n\ngo 1.27\n")
        self.cache = t / "cache"

    def tearDown(self):
        subprocess.run([sys.executable, str(SCRIPT), "cache", "gc"], env=self.env, capture_output=True)
        self.tmp.cleanup()

    def mvm(self, *args, **kw):
        return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=self.proj, env=self.env,
                              capture_output=True, text=True, timeout=120, **kw)

    def gen(self, name):
        meta = self.cache / f"{name}.meta.json"
        return json.loads(meta.read_text())["generation"] if meta.exists() else None

    def has_file(self, name, path):
        r = subprocess.run(["/usr/sbin/debugfs", "-R", f"stat {path}", str(self.cache / f"{name}.img")],
                           capture_output=True, text=True)
        return "Inode:" in r.stdout

    def test_clean_commit(self):
        """Proves: a run that exits 0 commits its cache writes atomically and records the run."""
        r = self.mvm("build", "--", "sh", "-c", "echo ok > /cache/go-build/marker")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.gen("go-build"), 1)
        self.assertTrue(self.has_file("go-build", "/marker"))

    def test_kill_mid_run(self):
        """Proves: SIGKILL of mvm mid-run leaves the cache unchanged; gc reaps the orphan VM."""
        self.assertEqual(self.mvm("build", "--", "true").returncode, 0)      # gen 1, clean image
        p = subprocess.Popen([sys.executable, str(SCRIPT), "build", "--", "sh", "-c",
                              "echo bad > /cache/go-build/poison; sync; sleep 60"],
                             cwd=self.proj, env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 60
        while time.time() < deadline:
            if subprocess.run(["podman", "ps", "-q", "--filter", f"label=mvm.pid={p.pid}"],
                              capture_output=True, text=True).stdout.strip():
                break
            time.sleep(0.5)
        else:
            p.kill()
            self.fail("microVM never started")
        time.sleep(3)
        copies = list(self.cache.glob("go-build.img.run-*"))
        self.assertEqual(len(copies), 1)
        r = subprocess.run(["/usr/sbin/debugfs", "-R", "stat /poison", str(copies[0])],
                           capture_output=True, text=True)
        self.assertIn("Inode:", r.stdout, "control: poison must exist in the run copy before the kill")
        os.kill(p.pid, signal.SIGKILL)
        p.wait()
        self.assertEqual(self.gen("go-build"), 1)
        self.assertFalse(self.has_file("go-build", "/poison"))
        r = subprocess.run([sys.executable, str(SCRIPT), "cache", "gc"], env=self.env, capture_output=True, text=True)
        self.assertIn("killed orphaned container", r.stderr)
        self.assertEqual(list(self.cache.glob("*.run-*")), [])

    def test_masks_hide_secrets(self):
        """Proves: .git and .env are hidden inside the VM and the project is read-only."""
        (self.proj / ".git").mkdir()
        (self.proj / ".git" / "config").write_text("token")
        (self.proj / ".env").write_text("SECRET=1")
        r = self.mvm("run", "-i", GO_IMAGE, "--", "sh", "-c",
                     'echo "env=[$(cat .env)] git=[$(ls -A .git)]"; touch x 2>/dev/null && echo writable || echo readonly')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("env=[] git=[]", r.stdout)
        self.assertIn("readonly", r.stdout)


if __name__ == "__main__":
    unittest.main()
