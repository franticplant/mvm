"""Tests for bin/mvm (stdlib unittest).

Unit tests need no podman/KVM. Real tests (class RealTests) boot krun microVMs
and run only with MVM_REAL=1; each takes a few seconds.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "bin" / "mvm"


class _Facade:
    """One object over the mvm package modules, like the old single-file module.

    Reads come from the first module (in dependency order) that has the name;
    writes (test overrides, mock.patch) go to every module holding it, so names
    imported into other modules are overridden too.
    """

    def __init__(self, mods):
        object.__setattr__(self, "_mods", mods)

    def __getattr__(self, name):
        for m in self._mods:
            if hasattr(m, name):
                return getattr(m, name)
        raise AttributeError(name)

    def __setattr__(self, name, value):
        hit = [m for m in self._mods if hasattr(m, name)]
        if not hit:
            raise AttributeError(name)
        for m in hit:
            setattr(m, name, value)


def load_mvm():
    sys.path.insert(0, str(REPO))
    import importlib
    names = ["core", "ecos", "cache", "project", "egress", "observer", "check", "runtime", "pull", "imagebuild", "cli"]
    mods = [importlib.reload(importlib.import_module(f"mvm.{n}")) for n in names]
    # reload in dependency order so cross-module imports see fresh objects
    return _Facade(mods)


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


class ConfigTests(Base):
    def test_valid_config_loads(self):
        self.mvm.CONFIG_PATH.write_text('mask = [".env"]\n[images]\ngo = "x:1"\n[memory]\nrun = "1g"\n')
        self.assertEqual(self.mvm.load_config()["mask"], [".env"])

    def test_eta_fields_are_sanitized_and_logged_opt_in(self):
        line = json.dumps({"dst": "1.1.1.1", "dst_port": 443, "proto": "TLS", "sni": "a.example", "ja4": "j",
                           "ts_start": 1.5, "duration_ms": 9, "pkts_out": 3, "pkts_in": True, "data_ratio": 0.25,
                           "alpn": "h2", "tls_version": "13",
                           "splt": [[517, 1.0], [-1400, "x"], [1, 2, 3], [-90, 0.5]] + [[1, 1.0]] * 30})
        f = self.mvm.observer.summarize([line], ["a.example"])["flows"][0]
        self.assertEqual((f["pkts_in"], f["duration_ms"], f["alpn"]), (None, 9.0, "h2"))   # a bool is no count
        self.assertEqual(f["splt"][:2], [[517, 1.0], [-90, 0.5]])
        self.assertEqual(len(f["splt"]), 20)
        self.assertIsNone(self.mvm.observer.log_path(self.mvm.load_config()))               # off by default
        log = Path(self.tmp.name) / "corpus" / "flows.jsonl"
        self.mvm.CONFIG_PATH.write_text(f'[observer]\nlog = "{log}"\n')
        self.assertEqual(self.mvm.observer.log_path(self.mvm.load_config()), log)
        for _ in range(2):
            self.mvm.observer.append_log(log, {"run_id": "R", "kind": "fetch", "eco": "go"}, [f])
        rows = [json.loads(x) for x in log.read_text().splitlines()]
        self.assertEqual([(r["run_id"], r["kind"], r["eco"], r["sni"]) for r in rows], [("R", "fetch", "go", "a.example")] * 2)
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)
        for bad in ('[observer]\nlog = "relative.jsonl"\n', '[observer]\nlog = 1\n'):
            self.mvm.CONFIG_PATH.write_text(bad)
            with self.assertRaises(SystemExit, msg=bad):
                self.mvm.load_config()

    def test_state_dir_is_private(self):
        self.mvm.STATE_ROOT.mkdir(mode=0o755)
        os.chmod(self.mvm.STATE_ROOT, 0o755)  # noqa: S103  (the old default, to be tightened)
        self.mvm.ensure_state_dir()
        self.assertEqual(self.mvm.STATE_ROOT.stat().st_mode & 0o777, 0o700)

    def test_observer_config(self):
        self.assertTrue(self.mvm.observer.enabled(self.mvm.load_config()))      # on by default
        self.mvm.CONFIG_PATH.write_text("[observer]\nenabled = false\n")
        self.assertFalse(self.mvm.observer.enabled(self.mvm.load_config()))

    def test_wrong_shapes_rejected(self):
        for bad in ('mask = ".env"\n', 'mask = [""]\n', 'masks = []\n', '[images]\npython = "x"\n',
                    '[memory]\ngo = "lots"\n', 'mask = [\n', '[observer]\nenabled = "yes"\n',
                    '[observer]\nenabled = true\nmode = "x"\n', 'observer = true\n'):
            self.mvm.CONFIG_PATH.write_text(bad)
            with self.assertRaises(SystemExit, msg=bad):
                self.mvm.load_config()


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

    def test_network_only_through_confinement(self):
        plan = self.plan(kind="fetch", net=True)
        with self.assertRaises(self.mvm.MvmError):          # no unconfined network exists
            self.mvm.podman_argv(plan, "RID", {}, Path("/e"))
        net = self.mvm.vm_network_args(4321)
        argv = self.mvm.podman_argv(plan, "RID", {}, Path("/e"), net)
        self.assertNotIn("--network=none", argv)
        self.assertIn("--dns=none", argv)
        self.assertIn("--network=pasta:-4,-o,127.0.0.1,--no-map-gw,-T,4321,--dns-host,192.0.2.1", argv)


class PullTests(Base):
    def test_every_podman_run_refuses_to_pull(self):
        """An image missing locally must fail the run, never be pulled outside the egress."""
        p = self.mvm.Plan(kind="pull", eco=None, image="localhost/mvm-skopeo:1", memory="1g", cmd=["/skopeo"],
                          src=None, volumes=["/w/ca.crt:/etc/mvm/ca.crt:ro,z"])
        argv = self.mvm.podman_argv(p, "RID", {}, Path("/e"))
        self.assertIn("--pull=never", argv)
        self.assertIn("/w/ca.crt:/etc/mvm/ca.crt:ro,z", argv)
        self.assertEqual(argv[-2:], ["localhost/mvm-skopeo:1", "/skopeo"])          # PID 1, no shell
        self.assertIn("--pull=never", self.mvm.observer.sidecar_argv("pod", "n", "r", "eth0", Path("/o")))
        for mod in ("egress", "observer", "runtime"):
            src = Path(REPO / "mvm" / f"{mod}.py").read_text()
            self.assertEqual(src.count('"podman", "run"'), src.count('"podman", "run", "-d", "--pull=never"')
                             + src.count('"podman", "run", "--rm", "--pull=never"'), mod)

    def test_copy_argv_and_policy(self):
        argv = self.mvm.pull.copy_argv("docker.io/library/alpine:3.24")
        self.assertEqual(argv[0], "/skopeo")
        self.assertEqual(argv[-2:], ["docker://docker.io/library/alpine:3.24", "dir:/out/img"])
        pol = self.mvm.pull.POLICY
        self.assertEqual(pol["default"], [{"type": "reject"}])
        self.assertEqual(set(pol["transports"]), {"docker", "dir"})

    def test_pull_allowlist(self):
        allow = self.mvm.egress.allowlist({}, "pull")
        self.assertIn("registry-1.docker.io", allow)
        self.assertIn("production.cloudfront.docker.com", allow)        # seen in a real pull
        self.assertFalse([h for h in allow if h.startswith("*.")])     # no wildcard (any R2 bucket)
        self.mvm.CONFIG_PATH.write_text('[allow]\npull = ["quay.io", "cdn01.quay.io"]\n')
        cfg = self.mvm.load_config()
        self.assertIn("quay.io", self.mvm.egress.allowlist(cfg, "pull"))
        self.mvm.CONFIG_PATH.write_text('[allow]\npulls = ["quay.io"]\n')
        with self.assertRaises(SystemExit):
            self.mvm.load_config()

    def test_ca_bundle_probes_distro_paths_in_order(self):
        t = Path(self.tmp.name)
        fedora, debian, suse = t / "fedora.crt", t / "debian.crt", t / "suse.pem"
        with mock.patch.object(self.mvm.pull, "CA_BUNDLES", (fedora, debian, suse)):
            self.assertIsNone(self.mvm.pull.ca_bundle())
            suse.write_text("x")
            self.assertEqual(self.mvm.pull.ca_bundle(), suse)
            debian.write_text("x")
            self.assertEqual(self.mvm.pull.ca_bundle(), debian)
            fedora.write_text("x")
            self.assertEqual(self.mvm.pull.ca_bundle(), fedora)
            fedora.unlink()
            fedora.mkdir()                      # a directory is not a bundle
            self.assertEqual(self.mvm.pull.ca_bundle(), debian)

    def test_local_images_are_never_pulled(self):
        with self.assertRaises(self.mvm.MvmError):
            self.mvm.pull.confined_pull("localhost/mvm-skopeo:1", {})

    def layout(self, manifest: dict | None = None) -> Path:
        img = Path(tempfile.mkdtemp(dir=self.tmp.name))
        blobs = {}
        for data in (b"config", b"layer"):
            h = hashlib.sha256(data).hexdigest()
            (img / h).write_bytes(data)
            blobs[data] = h
        m = manifest or {"schemaVersion": 2, "config": {"digest": "sha256:" + blobs[b"config"]},
                         "layers": [{"digest": "sha256:" + blobs[b"layer"]}]}
        (img / "manifest.json").write_bytes(json.dumps(m).encode())
        (img / "version").write_text("Directory Transport Version: 1.1\n")
        return img

    def test_digest_is_of_the_manifest_bytes(self):
        img = self.layout()
        self.assertEqual(self.mvm.pull.manifest_digest(img),
                         "sha256:" + hashlib.sha256((img / "manifest.json").read_bytes()).hexdigest())

    def test_hostile_layouts_are_refused_before_the_host_loads_them(self):
        """The VM writes the dir: layout; agy review: symlinks, indexes, foreign URLs, missing blobs."""
        cfg, lay = hashlib.sha256(b"config").hexdigest(), hashlib.sha256(b"layer").hexdigest()
        cases = {
            "symlinked manifest": lambda img: ((img / "manifest.json").unlink(),
                                               (img / "manifest.json").symlink_to("/etc/passwd")),
            "symlinked blob": lambda img: ((img / lay).unlink(), (img / lay).symlink_to("/etc/passwd")),
            "subdirectory": lambda img: (img / "sub").mkdir(),
            "stray file": lambda img: (img / "notes.txt").write_text("x"),
            "index": lambda img: (img / "manifest.json").write_text('{"manifests": [], "layers": []}'),
            "foreign urls": lambda img: (img / "manifest.json").write_text(json.dumps(
                {"config": {"digest": "sha256:" + cfg},
                 "layers": [{"digest": "sha256:" + lay, "urls": ["https://evil.example/l"]}]})),
            "missing blob": lambda img: (img / lay).unlink(),
            "bad digest": lambda img: (img / "manifest.json").write_text(json.dumps(
                {"config": {"digest": "sha256:" + cfg}, "layers": [{"digest": "sha256:../../x"}]})),
            "not json": lambda img: (img / "manifest.json").write_text("{"),
        }
        for name, spoil in cases.items():
            img = self.layout()
            spoil(img)
            with self.assertRaises(self.mvm.MvmError, msg=name):
                self.mvm.pull.manifest_digest(img)
        link = Path(self.tmp.name) / "imglink"
        link.symlink_to(self.layout())
        with self.assertRaises(self.mvm.MvmError):
            self.mvm.pull.manifest_digest(link)

    def test_missing_pinned_image_is_refused_not_pulled(self):
        self.mvm.write_json_atomic(self.mvm.pins_path(), {"docker.io/x/y:1": {"ref": "docker.io/x/y@sha256:ab"}})
        gone = subprocess.CompletedProcess([], 1)
        with mock.patch.object(sys.modules["mvm.core"].subprocess, "run", return_value=gone):
            with self.assertRaisesRegex(self.mvm.MvmError, "mvm pull docker.io/x/y:1"):
                self.mvm.pinned("docker.io/x/y:1")


class ImageBuildTests(Base):
    def test_base_images_and_refusals(self):
        ib = self.mvm.imagebuild
        cf = ("# comment\nARG X=1\nFROM --platform=linux/amd64 docker.io/library/golang:1.27-alpine AS build\n"
              "RUN go version \\\n  && echo ok\nFROM scratch\nCOPY --from=build /x /x\n"
              "FROM build AS again\nFROM localhost/mine:1\nRUN <<EOF\nFROM docker.io/evil/inside:heredoc\nEOF\n"
              "from docker.io/library/alpine:3.24\n")
        self.assertEqual(ib.base_images(cf), ["docker.io/library/golang:1.27-alpine", "localhost/mine:1",
                                              "docker.io/library/alpine:3.24"])
        for bad in ("FROM alpine:3.24\n", "ARG B=x\nFROM docker.io/library/$B\n", "FROM\n",
                    "FROM docker.io/library/alpine:3.24\nADD https://example.com/x /x\n",
                    "FROM docker.io/library/alpine:3.24\nADD --chmod=644 git@github.com:a/b.git /b\n",
                    "FROM docker.io/library/alpine:3.24\nRUN --network=host wget x\n",
                    "FROM docker.io/library/alpine:3.24\nRUN --mount=type=cache,target=/c --network host true\n"):
            with self.assertRaises(self.mvm.MvmError, msg=bad):
                ib.base_images(bad)
        ib.base_images("FROM docker.io/library/alpine:3.24\nADD <<EOF /x\nhello\nEOF\nRUN echo --network=x\n")
        for bad in ('FROM docker.io/library/alpine:3.24\nADD ["https://evil.example/x", "/x"]\n',   # JSON form
                    "FROM docker.io/library/alpine:3.24\nADD ./local /x\n",
                    "FROM docker.io/library/alpine:3.24\nRUN --security=insecure id\n",
                    "# escape=`\nFROM docker.io/library/alpine:3.24\nRUN echo `\n  ADD https://e/x /x\n"):
            with self.assertRaises(self.mvm.MvmError, msg=bad):
                ib.base_images(bad)
        ib.base_images("# escape=\\\nFROM docker.io/library/alpine:3.24\n")

    def test_from_is_rewritten_to_the_pinned_digest(self):
        ib = self.mvm.imagebuild
        cf = ("FROM --platform=linux/amd64 docker.io/library/golang:1.27-alpine AS build\n"
              "RUN <<EOF\nFROM docker.io/library/golang:1.27-alpine\nEOF\n"
              "FROM build\nfrom docker.io/library/alpine:3.24\n")
        out = ib.pin_from(cf, {"docker.io/library/golang:1.27-alpine": "docker.io/library/golang@sha256:aa",
                               "docker.io/library/alpine:3.24": "docker.io/library/alpine@sha256:bb"})
        self.assertEqual(out.splitlines(), [
            "FROM --platform=linux/amd64 docker.io/library/golang@sha256:aa AS build",
            "RUN <<EOF", "FROM docker.io/library/golang:1.27-alpine", "EOF",         # heredoc body untouched
            "FROM build", "from docker.io/library/alpine@sha256:bb"])
        with self.assertRaises(self.mvm.MvmError):
            ib.pin_from("FROM \\\n  docker.io/library/alpine:3.24\n", {})

    def test_build_argv_is_krun_confined_and_offline_for_images(self):
        net = self.mvm.vm_network_args(4321)
        argv = self.mvm.imagebuild.build_argv("localhost/mvm-build-tmp:ab", Path("/ctx"), "2g", net, 4321)
        self.assertEqual(argv[:4], ["podman", "--runtime", "krun", "build"])   # RUN steps in KVM
        for flag in ("--pull=never", "--no-cache", "--layers=false", "--dns=none", *net):
            self.assertIn(flag, argv)
        self.assertNotIn("--network=host", argv)
        for k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
            self.assertIn(f"{k}=http://127.0.0.1:4321", argv)
        self.assertEqual(argv[-1], "/ctx")
        self.assertEqual(argv[argv.index("-f") + 1], "/ctx/Containerfile")
        self.assertEqual(argv[argv.index("-t") + 1], "localhost/mvm-build-tmp:ab")

    def test_context_holds_only_the_containerfile_and_failures_tag_nothing(self):
        ib = self.mvm.imagebuild
        self.write("Containerfile", "FROM docker.io/library/alpine:3.24\nRUN true\n")
        self.write(".env", "SECRET=1")
        seen, calls = {}, []

        def fake_execute(plan):
            argv = plan.argv_fn(self.mvm.vm_network_args(1), 1)
            ctx = Path(argv[-1])
            seen["files"] = sorted(p.name for p in ctx.iterdir())
            seen["cf"] = (ctx / "Containerfile").read_text()
            seen["plan"] = plan
            return 3

        def fake_run(argv, *a, **k):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "", "")
        with mock.patch.object(sys.modules["mvm.runtime"], "execute", fake_execute), \
                mock.patch.object(ib.subprocess, "run", fake_run), \
                mock.patch.object(ib.core, "pinned", return_value="docker.io/library/alpine@sha256:cc"):
            rc, _ = ib.build("localhost/x:1", self.proj / "Containerfile", {})
        self.assertEqual(rc, 3)
        self.assertEqual(seen["cf"], "FROM docker.io/library/alpine@sha256:cc\nRUN true\n")    # the pin, not the tag
        self.assertEqual(seen["files"], ["Containerfile"])
        self.assertEqual((seen["plan"].kind, seen["plan"].net), ("image-build", True))
        self.assertIn("dl-cdn.alpinelinux.org", seen["plan"].allow)
        self.assertFalse([c for c in calls if c[:2] == ["podman", "tag"]])           # nothing tagged
        self.assertTrue([c for c in calls if c[:3] == ["podman", "rmi", "-f"]])        # temp image removed
        for bad in ("docker.io/x:1", "localhost/x", "localhost/x@sha256:ab"):
            with self.assertRaises(self.mvm.MvmError, msg=bad):
                ib.build(bad, self.proj / "Containerfile", {})


class EgressTests(Base):
    def test_acl_is_default_policy_with_quoted_hosts(self):
        acl = self.mvm.acl_yaml(["proxy.golang.org", "*.example.com"], "enforce")
        self.assertIn("default:\n  project: mvm\n  action: enforce\n", acl)
        self.assertIn('    - "proxy.golang.org"\n', acl)
        self.assertIn('    - "*.example.com"\n', acl)
        self.assertIn("allowed_domains: []", self.mvm.acl_yaml([], "report"))
        with self.assertRaises(self.mvm.MvmError):
            self.mvm.acl_yaml([], "open")                    # never an open proxy

    def test_allowlist_defaults_plus_config(self):
        cfg = {"allow": {"go": ["github.com"]}}
        self.assertEqual(self.mvm.allowlist(cfg, "go"), ["github.com", "proxy.golang.org", "storage.googleapis.com", "sum.golang.org"])
        self.assertEqual(self.mvm.allowlist({}, "node"), ["registry.npmjs.org"])

    def test_bad_allow_config_rejected(self):
        for bad in ('[allow]\ngo = "x.org"\n', '[allow]\npython = ["x"]\n', '[allow]\ngo = ["http://x"]\n'):
            self.mvm.CONFIG_PATH.write_text(bad)
            with self.assertRaises(SystemExit, msg=bad):
                self.mvm.load_config()

    def test_fetch_fails_closed_without_proxy_binary(self):
        self.mvm.LIB_DIR = Path(self.tmp.name) / "no-lib"
        with mock.patch("subprocess.run") as run:
            with self.assertRaises(self.mvm.MvmError) as e:
                with self.mvm.Proxy("RID", ["a.org"], "enforce"):
                    pass
        self.assertIn("refuses", str(e.exception))
        run.assert_not_called()                      # nothing started, no podman call at all

    def test_execute_refuses_networked_run_before_touching_anything(self):
        self.mvm.LIB_DIR = Path(self.tmp.name) / "no-lib"
        plan = self.mvm.Plan(kind="fetch", eco="go", image="i", memory="1g", cmd=["x"], src=None,
                             net=True, caches=[self.mvm.Cache("c9", "/c9", True, "16M")])
        with self.assertRaises(self.mvm.MvmError):
            self.mvm.execute(plan)
        self.assertFalse(self.mvm.cache_img("c9").exists())           # no cache created
        self.assertFalse((self.mvm.STATE_ROOT / "runs").exists())     # no run record

    def test_host_names_normalised_in_summary(self):
        D = "CANONICAL-PROXY-DECISION"
        lines = ['{"msg":"%s","id":"%d","requested_host":"%s","allow":true}' % (D, i, h)
                 for i, h in enumerate(["PROXY.GOLANG.ORG:443", "proxy.golang.org.:443", "proxy.golang.org:443"])]
        s = self.mvm.summarize(lines)
        self.assertEqual(list(s["allowed"]), ["proxy.golang.org"])
        self.assertEqual(s["allowed"]["proxy.golang.org"]["connections"], 3)

    def test_allow_hosts_validated(self):
        ok = ["github.com", "*.github.com", "codeload.github.com", "a-b.example.co"]
        bad = ["*.com", "com", ".", "..", "1.2.3.4", "*.1.2.3", "http://x.org", "x..org", "-x.org", 5]
        for h in ok:
            self.assertTrue(self.mvm.valid_allow_host(h), h)
        for h in bad:
            self.assertFalse(self.mvm.valid_allow_host(h), h)

    def test_summarize_never_drops_a_decision(self):
        D = "CANONICAL-PROXY-DECISION"
        lines = ['{"msg":"%s","id":"same","requested_host":"a.org:443","allow":false}' % D,
                 '{"msg":"%s","id":"same","requested_host":"a.org:443","allow":false}' % D,   # same id
                 '{"msg":"%s","allow":false,"decision_reason":"bad request"}' % D,             # no host
                 '{"msg":"%s","id":"v6","requested_host":"[2001:db8::1]:443","allow":false}' % D]
        s = self.mvm.summarize(lines)
        self.assertEqual(s["denied"]["a.org"]["connections"], 2)
        self.assertIn("(unknown)", s["denied"])
        self.assertIn("2001:db8::1", s["denied"])

    def test_proxy_start_failure_cleans_up(self):
        self.mvm.LIB_DIR = Path(self.tmp.name) / "lib"
        self.mvm.LIB_DIR.mkdir()
        (self.mvm.LIB_DIR / "smokescreen").write_text("")
        px = self.mvm.Proxy("RID", ["a.org"], "enforce")
        stopped = []
        with mock.patch.object(sys.modules["mvm.core"], "pinned", return_value="img@sha256:x"), \
                mock.patch.object(sys.modules["mvm.egress"], "firewall_image_present", return_value=True), \
                mock.patch.object(px, "_start", side_effect=KeyboardInterrupt), \
                mock.patch.object(px, "_stop", side_effect=lambda: stopped.append(1) or []):
            with self.assertRaises(KeyboardInterrupt):
                px.__enter__()
        self.assertEqual(stopped, [1])

    def test_port_filter_rules(self):
        fw = self.mvm.FIREWALL_SH
        self.assertIn("policy drop;", fw)
        self.assertIn("tcp dport 443 accept", fw)
        self.assertIn("th dport 53 accept", fw)            # DNS only to the pod's resolver
        self.assertNotIn("dport 80", fw)
        self.assertIn("table inet", fw)                     # IPv4 and IPv6
        for rng in ("10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"):
            self.assertIn(rng, fw)
        # the private-range reject must come before the 443 accept
        self.assertLess(fw.index("100.64.0.0/10"), fw.index("tcp dport 443 accept"))

    def _start_with(self, fw_stdout, fw_rc=0):
        self.mvm.LIB_DIR = Path(self.tmp.name) / "lib"
        self.mvm.LIB_DIR.mkdir(exist_ok=True)
        (self.mvm.LIB_DIR / "smokescreen").write_text("")
        calls = []
        def fake_run(argv, *a, **k):
            calls.append(argv)
            out = fw_stdout if "/firewall.sh" in argv else ""
            return subprocess.CompletedProcess(argv, fw_rc if "/firewall.sh" in argv else 0, out, "")
        px = self.mvm.Proxy("RID", ["a.org"], "enforce")
        with mock.patch.object(sys.modules["mvm.core"], "pinned", return_value="img@sha256:x"), \
                mock.patch.object(sys.modules["mvm.egress"], "firewall_image_present", return_value=True), \
                mock.patch("subprocess.run", side_effect=fake_run), \
                mock.patch.object(px, "_wait_ready"):
            try:
                px.__enter__()
            finally:
                pass
        return calls

    def test_proxy_pod_order_firewall_before_smokescreen(self):
        calls = self._start_with("MVM_EGRESS_FIREWALL_LOADED\n")
        kinds = [c[1:3] for c in calls[:3]]
        self.assertEqual(kinds[0], ["pod", "create"])
        self.assertIn("--cap-add=NET_ADMIN", calls[1])           # only the one-shot firewall
        self.assertIn("/smokescreen", calls[2])
        self.assertIn("--cap-drop=all", calls[2])
        self.assertNotIn("--cap-add=NET_ADMIN", calls[2])        # proxy runs with no capabilities

    def test_firewall_sets_mtu_and_reports_interface(self):
        fw = self.mvm.FIREWALL_SH
        self.assertLess(fw.index("mtu 1500"), fw.index("nft -f"))
        calls = self._start_with("MVM_IF=wlp4s0\nMVM_EGRESS_FIREWALL_LOADED\n")
        self.assertIn("--cap-add=NET_ADMIN", calls[1])

    def test_proxy_refuses_when_firewall_does_not_load(self):
        with self.assertRaises(self.mvm.MvmError):
            self._start_with("", fw_rc=1)

    def test_non_443_port_counts_as_denied(self):
        D = "CANONICAL-PROXY-DECISION"
        lines = ['{"msg":"%s","id":"1","requested_host":"proxy.golang.org:22","allow":true}' % D,
                 '{"msg":"%s","id":"2","requested_host":"proxy.golang.org:443","allow":true}' % D,
                 '{"msg":"%s","id":"3","requested_host":"[2001:db8::1]:8443","allow":true}' % D]
        s = self.mvm.summarize(lines)
        self.assertEqual(s["allowed"]["proxy.golang.org"]["connections"], 1)
        self.assertEqual(s["denied"]["proxy.golang.org"]["reason"], "port 22 blocked (443 only)")
        self.assertIn("2001:db8::1", s["denied"])

    def test_summarize_real_smokescreen_log_shapes(self):
        # Field shapes copied from a real Smokescreen v2 run (report mode, go mod download).
        D, C = "CANONICAL-PROXY-DECISION", "CANONICAL-PROXY-CN-CLOSE"
        lines = [
            '{"msg":"starting"}',
            '{"msg":"%s","id":"a","requested_host":"proxy.golang.org:443","allow":true,"enforce_would_deny":false}' % D,
            '{"msg":"%s","id":"a","requested_host":"proxy.golang.org:443","bytes_in":11372,"bytes_out":1620}' % C,
            '{"msg":"%s","id":"b","requested_host":"storage.googleapis.com:443","allow":true,"enforce_would_deny":true}' % D,
            '{"msg":"%s","id":"b","requested_host":"storage.googleapis.com:443","bytes_in":5,"bytes_out":1}' % C,
            '{"msg":"%s","id":"c","requested_host":"evil.example:443","allow":false,"decision_reason":"host not allowed"}' % D,
            "not json",
        ]
        s = self.mvm.summarize(lines)
        self.assertEqual(s["allowed"]["proxy.golang.org"], {"connections": 1, "bytes_in": 11372, "bytes_out": 1620})
        self.assertEqual(s["denied"]["evil.example"]["reason"], "host not allowed")
        self.assertEqual(s["outside_allowlist"], ["storage.googleapis.com"])   # denied hosts are never suggested
        line = self.mvm.summary_line(s)
        self.assertIn("DENIED: evil.example (1x)", line)
        self.assertIn("outside the allowlist (learn mode): storage.googleapis.com", line)


class TlsSensorTests(Base):
    """mvm/tlsobs.py: ClientHello parsing, JA4 and TCP reassembly (clean-room; the real
    ClientHellos below were captured by the sensor, JA4 checked against nDPI 5.0)."""
    HELLOS = json.loads((Path(__file__).parent / "data" / "clienthellos.json").read_text())

    @staticmethod
    def hello(ciphers=(0x1301, 0x1302), exts=None, legacy=0x0303) -> bytes:
        """A ClientHello in one handshake record. exts: list of (type, data)."""
        body = struct.pack(">H", legacy) + b"\0" * 32 + b"\0" + struct.pack(">H", 2 * len(ciphers))
        body += b"".join(struct.pack(">H", c) for c in ciphers) + b"\x01\x00"
        if exts is not None:
            e = b"".join(struct.pack(">HH", t, len(d)) + d for t, d in exts)
            body += struct.pack(">H", len(e)) + e
        hs = b"\x01" + len(body).to_bytes(3, "big") + body
        return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs

    @staticmethod
    def sni(name: bytes) -> tuple:
        entry = b"\x00" + struct.pack(">H", len(name)) + name
        return (0x0000, struct.pack(">H", len(entry)) + entry)

    @staticmethod
    def alpn(*protos: bytes) -> tuple:
        lst = b"".join(bytes([len(p)]) + p for p in protos)
        return (0x0010, struct.pack(">H", len(lst)) + lst)

    def test_real_client_hellos_match_ndpi(self):
        t = self.mvm.tlsobs
        for h in self.HELLOS:
            r = t.classify(bytes.fromhex(h["stream_hex"]))
            self.assertEqual((r["proto"], r["sni"], r["ja4"]), ("TLS", h["sni"], h["ja4_ndpi_5_0"]), h["client"])

    def test_reassembly_in_any_segmentation_and_order(self):
        t = self.mvm.tlsobs
        stream = bytes.fromhex(self.HELLOS[0]["stream_hex"])
        want = t.classify(stream)
        for size in (1, 7, 536, 1448):
            segs = [(o, stream[o:o + size]) for o in range(0, len(stream), size)]
            for order in (segs, segs[::-1], segs[1::2] + segs[::2]):
                f = t.Flow("1.2.3.4", 1000)
                for o, d in order:
                    f.client_data(1001 + o, d)
                f.client_data(1001, stream[:5])                  # a harmless retransmission
                self.assertEqual((f.result, f.fault), (want, ""), (size, len(order)))
        f = t.Flow("1.2.3.4", 1000)                               # a conflicting retransmission
        f.client_data(1001 + 10, stream[10:20])
        f.client_data(1001 + 10, b"X" * 10)
        self.assertEqual(f.fault, "conflicting retransmission")
        f = t.Flow("1.2.3.4", 0xfffffff0)                         # sequence numbers wrap
        for o in range(0, len(stream), 100):
            f.client_data((0xfffffff1 + o) & 0xffffffff, stream[o:o + 100])
        self.assertEqual(f.result, want)

    def test_hello_split_across_records(self):
        t = self.mvm.tlsobs
        stream = bytes.fromhex(self.HELLOS[1]["stream_hex"])
        hs = t.handshake_bytes(stream)
        full = b"\x01" + len(hs).to_bytes(3, "big") + hs
        split = b"".join(b"\x16\x03\x03" + struct.pack(">H", len(full[i:i + 300])) + full[i:i + 300]
                         for i in range(0, len(full), 300))
        self.assertEqual(t.classify(split), t.classify(stream))

    def test_ja4_rules(self):
        t = self.mvm.tlsobs
        grease = 0x3a3a
        versions = (0x002b, bytes([6]) + struct.pack(">HHH", grease, 0x0304, 0x0303))
        sig = (0x000d, struct.pack(">HHHH", 6, 0x0804, grease, 0x0403))
        r = t.classify(self.hello(ciphers=(grease, 0x1302, 0x1301),
                                  exts=[(grease, b""), self.sni(b"a.org"), self.alpn(b"h2", b"http/1.1"),
                                        versions, sig, (0x000a, b"\0\0")]))
        a, b, c = r["ja4"].split("_")
        self.assertEqual(a, "t13d0205h2")                          # GREASE never counted; version from 0x002b
        self.assertEqual(b, hashlib.sha256(b"1301,1302").hexdigest()[:12])       # sorted
        self.assertEqual(c, hashlib.sha256(b"000a,000d,002b_0804,0403").hexdigest()[:12])  # no SNI/ALPN; sigalgs in wire order
        self.assertEqual(r["sni"], "a.org")
        r = t.classify(self.hello(exts=[self.alpn(b"\xab\xcd")]))
        self.assertTrue(r["ja4"].startswith("t12i0201ad_"))       # no SNI: i; non-alnum ALPN: hex first/last
        r = t.classify(self.hello(exts=None, legacy=0x0301))
        self.assertTrue(r["ja4"].startswith("t10i020000_") and r["ja4"].endswith("_000000000000"))
        self.assertEqual(r["sni"], "")

    def test_non_tls_and_malformed(self):
        t = self.mvm.tlsobs
        self.assertEqual(t.classify(b"GET / HTTP/1.0\r\nHost: proxy.golang.org\r\n\r\n")["proto"], "non-TLS")
        self.assertEqual(t.classify(b"\x14\x03\x03\x00\x01\x01")["proto"], "non-TLS")      # not a handshake
        self.assertEqual(t.classify(b"\x16\x03\x03\x00\x05\x02\x00\x00\x01\x00")["proto"], "non-TLS")  # ServerHello
        self.assertIsNone(t.classify(self.hello()[:30]))                                     # a prefix: need more
        broken = bytearray(self.hello(exts=[self.sni(b"a.org")]))
        broken[-7] = 0xff                                         # the host name's length now overruns
        self.assertEqual(t.classify(bytes(broken))["proto"], "non-TLS")
        f = t.Flow("1.2.3.4", 1)
        f.client_data(2, self.hello()[:30])
        f.closed = True
        self.assertEqual(f.record()["why"], "connection ended before a ClientHello")
        f = t.Flow("1.2.3.4", 1)                                  # never completes: capped, not buffered forever
        f.client_data(2, b"\x16\x03\x03\x40\x00" + b"\x01\x00\x40\x00" + b"\0" * (t.HELLO_CAP + 100))
        self.assertEqual(f.result["proto"], "non-TLS")

    def test_ambiguous_hellos_are_not_tls(self):
        """Anything a server might read differently from us is refused (held): duplicate
        extensions or host names (first-wins here, last-wins there), trailing or odd bytes."""
        t = self.mvm.tlsobs
        two = b"\x00\x00\x05allow" + b"\x00\x00\x04evil"
        cases = {"duplicate SNI extension": [self.sni(b"allowed.org"), self.sni(b"evil.org")],
                 "two host names": [(0x0000, struct.pack(">H", len(two)) + two)],
                 "duplicate other extension": [self.sni(b"a.org"), (0x000a, b"\0\0"), (0x000a, b"\0\0")],
                 "trailing bytes in SNI": [(0x0000, self.sni(b"a.org")[1] + b"evil.org")],
                 "odd sigalgs": [self.sni(b"a.org"), (0x000d, b"\x00\x03\x08\x04\x01")]}
        for name, exts in cases.items():
            self.assertEqual(t.classify(self.hello(exts=exts))["proto"], "non-TLS", name)
        versions = (0x002b, bytes([6]) + struct.pack(">HHH", 0x7f1c, 0x0304, 0xffff))   # drafts/unknown
        self.assertTrue(t.classify(self.hello(exts=[versions]))["ja4"].startswith("t13i"))

    @staticmethod
    def ip4(src, dst, sport, dport, seq, flags, payload=b"", doff=5):
        tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, doff << 4, flags, 65535, 0, 0) + payload
        hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0,
                          socket.inet_aton(src), socket.inet_aton(dst))
        return hdr + tcp

    def test_tracker(self):
        t = self.mvm.tlsobs
        tr = t.Tracker()
        stream = bytes.fromhex(self.HELLOS[0]["stream_hex"])
        c, s = ("10.0.0.2", 40000), ("104.16.9.34", 443)
        tr.packet(self.ip4(*c[:1], *s[:1], c[1], 443, 100, 0x02), True)            # SYN
        tr.packet(self.ip4(s[0], c[0], 443, c[1], 9000, 0x12), False)              # SYN-ACK
        tr.packet(self.ip4(c[0], s[0], c[1], 443, 101, 0x18, stream), True)
        tr.packet(self.ip4(s[0], c[0], 443, c[1], 9001, 0x18, b"x" * 500)[:60], False)   # truncated inbound
        tr.packet(self.ip4(c[0], s[0], c[1], 443, 101 + len(stream), 0x11), True)  # FIN
        tr.packet(self.ip4(c[0], s[0], 40001, 443, 7, 0x02), True)                  # never answered: not a flow
        tr.packet(self.ip4(c[0], s[0], c[1], 443, 5000, 0x02), True)                # the port reused
        tr.packet(self.ip4(s[0], c[0], 443, c[1], 1, 0x12), False)
        tr.packet(self.ip4(c[0], s[0], c[1], 443, 5001, 0x18, b"GET /"), True)
        tr.packet(self.ip4(c[0], s[0], 40002, 80, 1, 0x02), True)                   # not port 443
        r = tr.records()
        self.assertEqual([(x["proto"], x["sni"]) for x in r], [("TLS", "registry.npmjs.org"), ("non-TLS", "")])
        self.assertEqual((r[0]["bytes_out"], r[0]["bytes_in"]), (len(stream), 500))
        tr = t.Tracker()                                          # port reused after an unanswered SYN
        tr.packet(self.ip4("10.0.0.2", "1.1.1.1", 50000, 443, 100, 0x02), True)
        tr.packet(self.ip4("10.0.0.2", "1.1.1.1", 50000, 443, 100, 0x02), True)     # its retransmission
        tr.packet(self.ip4("10.0.0.2", "1.1.1.1", 50000, 443, 7000, 0x02), True)    # a new connection
        tr.packet(self.ip4("1.1.1.1", "10.0.0.2", 443, 50000, 1, 0x12), False)
        tr.packet(self.ip4("10.0.0.2", "1.1.1.1", 50000, 443, 7001, 0x18, stream), True)
        self.assertEqual([x["sni"] for x in tr.records()], ["registry.npmjs.org"])
        tr.packet(self.ip4("10.0.0.2", "1.1.1.1", 50001, 443, 1, 0x02), True)       # urgent data
        tr.packet(self.ip4("1.1.1.1", "10.0.0.2", 443, 50001, 1, 0x12), False)
        tr.packet(self.ip4("10.0.0.2", "1.1.1.1", 50001, 443, 2, 0x38, stream), True)
        self.assertEqual(tr.records()[-1]["fault"], "TCP urgent data")
        self.assertIsNone(t._tcp(self.ip4("10.0.0.2", "1.1.1.1", 50002, 443, 1, 0x18, stream, doff=3)))
        tr = t.Tracker()
        for i in range(t.MAX_FLOWS + 3):
            tr.packet(self.ip4("10.0.0.2", "1.1.1.1", 1024 + i, 443, 1, 0x02), True)
        self.assertEqual(tr.overflow, 3)


    def test_eta_features(self):
        """Observe-only ETA fields: kernel timestamps, packet counts, data ratio, ALPN, version, SPLT."""
        t = self.mvm.tlsobs
        tr = t.Tracker()
        stream = bytes.fromhex(self.HELLOS[1]["stream_hex"])          # Python urllib: ALPN http/1.1
        c, s = "10.0.0.2", "1.1.1.1"
        t0 = 1795700000.0
        tr.packet(self.ip4(c, s, 40000, 443, 100, 0x02), True, t0)                          # SYN
        tr.packet(self.ip4(s, c, 443, 40000, 9000, 0x12), False, t0 + 0.010)                # SYN-ACK
        tr.packet(self.ip4(c, s, 40000, 443, 101, 0x10), True, t0 + 0.011)                  # ACK, no data
        tr.packet(self.ip4(c, s, 40000, 443, 101, 0x18, stream), True, t0 + 0.012)
        tr.packet(self.ip4(s, c, 443, 40000, 9001, 0x18, b"y" * 3000)[:60], False, t0 + 0.050)
        for i in range(25):                                                             # more than SPLT_LEN
            tr.packet(self.ip4(s, c, 443, 40000, 12001 + i * 100, 0x10, b"z" * 100)[:60], False, t0 + 0.060 + i / 1000)
        tr.packet(self.ip4(c, s, 40000, 443, 101 + len(stream), 0x11), True, t0 + 0.200)    # FIN
        r = tr.records()[0]
        self.assertEqual((r["alpn"], r["tls_version"]), ("http/1.1", "13"))
        self.assertEqual(r["ts_start"], t0)
        self.assertAlmostEqual(r["duration_ms"], 200.0, places=2)
        self.assertEqual((r["pkts_out"], r["pkts_in"]), (4, 27))
        self.assertEqual(r["data_ratio"], round(len(stream) / (len(stream) + 12001 + 24 * 100 + 100 - 9001), 4))
        self.assertEqual(len(r["splt"]), t.SPLT_LEN)
        self.assertEqual(r["splt"][0], [len(stream), 12.0])                 # first: since the SYN
        self.assertEqual(r["splt"][1], [-3000, 38.0])                       # inbound is negative
        self.assertEqual(r["splt"][2], [-100, 10.0])
        json.dumps(r)                                                       # a flow line stays JSON
        f = t.Flow("1.1.1.1", 1)
        self.assertIsNone(f.record()["data_ratio"])                         # no bytes: no ratio


class ObserverTests(Base):
    # One flow line as the sensor writes it (real values: registry.npmjs.org via wget).
    REAL = ('{"dst": "104.16.9.34", "dst_port": 443, "proto": "TLS", "sni": "registry.npmjs.org", '
            '"ja4": "t13d301100_1d37bd780c83_8e6e362c5eac", "why": "", "fault": "", '
            '"bytes_out": 1759, "bytes_in": 26661}')
    DNS = '{"dst": "169.254.1.1", "dst_port": 53, "proto": "DNS", "sni": "registry.npmjs.org"}'

    def test_summarize_real_flow(self):
        s = self.mvm.observer.summarize([self.REAL, self.DNS, "garbage", "[]"], ["registry.npmjs.org"])
        keys = ("sni", "ja4", "dst", "proto", "why", "fault", "bytes_out", "bytes_in")
        self.assertEqual([{k: f[k] for k in keys} for f in s["flows"]],
                         [{"sni": "registry.npmjs.org", "ja4": "t13d301100_1d37bd780c83_8e6e362c5eac",
                           "dst": "104.16.9.34", "proto": "TLS", "why": "", "fault": "",
                           "bytes_out": 1759, "bytes_in": 26661}])
        self.assertEqual((s["flows"][0]["splt"], s["flows"][0]["pkts_out"]), ([], None))   # older lines
        self.assertEqual(s["outside_allowlist"], [])
        self.assertIn("JA4 t13d301100", self.mvm.observer.summary_line(s))

    def test_plaintext_and_faults_are_held(self):
        """Plaintext HTTP with an allowed Host header sent through CONNECT :443 never had its
        name checked; a reassembly fault means the bytes seen may not be what the server got."""
        http = ('{"dst": "142.250.1.1", "dst_port": 443, "proto": "non-TLS", "sni": "", "ja4": "", '
                '"why": "first byte 0x47 is not a TLS handshake record"}')
        s = self.mvm.observer.summarize([http, self.REAL], ["proxy.golang.org", "registry.npmjs.org"])
        self.assertEqual(s["outside_allowlist"], ["(non-tls)"])
        fault = self.REAL.replace('"fault": ""', '"fault": "conflicting retransmission"')
        s = self.mvm.observer.summarize([fault], ["registry.npmjs.org"])
        self.assertEqual(s["outside_allowlist"], ["(fault: conflicting retransmission)"])

    def test_sni_outside_allowlist_and_missing_sni(self):
        fronted = self.REAL.replace("registry.npmjs.org", "evil.example")
        no_sni = self.REAL.replace('"sni": "registry.npmjs.org"', '"sni": ""')
        sub = self.REAL.replace("registry.npmjs.org", "Codeload.GitHub.com.")
        s = self.mvm.observer.summarize([fronted, no_sni, sub, self.REAL], ["registry.npmjs.org", "*.github.com"])
        self.assertEqual(len(s["flows"]), 4)
        self.assertEqual(s["outside_allowlist"], ["(no sni)", "evil.example"])
        self.assertIn("SNI OUTSIDE THE ALLOWLIST", self.mvm.observer.summary_line(s))
        self.assertEqual(self.mvm.observer.summarize([sub], ["*.codeload.github.com"])["outside_allowlist"],
                         ["Codeload.GitHub.com."])          # *.x never matches x itself
        m = self.mvm.observer._matches
        self.assertTrue(m("a.b.github.com", ["*.github.com"]))        # any depth, as Smokescreen
        for bad in (".github.com", "a..github.com", "github.com", "evilgithub.com", ""):
            self.assertFalse(m(bad, ["*.github.com"]), bad)

    def test_stop_health_needs_clean_exit_flows_and_zero_drops(self):
        st = self.mvm.tlsobs.STATS
        ok = st + '{"packets": 9, "drops": 0, "overflow": 0, "unparsed": 0, "faults": 0}\n'
        cases = [(ok, "0", True, self.REAL), (ok, "0", True, ""),              # quiet fetch: still a stats line
                 (ok.replace('"drops": 0', '"drops": 3'), "0", False, self.REAL),
                 (ok.replace('"drops": 0', '"drops": false'), "0", False, self.REAL),
                 (ok.replace('"overflow": 0', '"overflow": 1'), "0", False, self.REAL),
                 (ok.replace('"unparsed": 0', '"unparsed": 2'), "0", False, self.REAL),
                 (ok, "0", False, self.REAL[:40]),                               # a truncated flow line
                 ("", "0", False, ""),                                          # no stats line: not trusted
                 (st + "{not json\n", "0", False, self.REAL),
                 (ok, "137", False, self.REAL)]
        for logs, code, healthy, flows in cases:
            ob = self.mvm.observer.Observer("RID", "pod", "eth0", ["a.org"])
            ob.keep = ""
            ob._dir = tempfile.TemporaryDirectory()
            (Path(ob._dir.name) / "flows.jsonl").write_text(flows + "\n")
            ret = subprocess.CompletedProcess([], 0, code + "\n", "")
            with mock.patch.object(ob, "_running", return_value=True), \
                    mock.patch.object(ob, "_logs", return_value=logs), \
                    mock.patch("subprocess.run", return_value=ret):
                lines = ob._stop()
            self.assertEqual(ob.healthy, healthy, (logs, code, flows[:9]))
            self.assertEqual(len(lines), 1)
            ob._dir.cleanup()

    def test_sidecar_is_capture_only(self):
        argv = self.mvm.observer.sidecar_argv("pod", "pod-observer", "RID", "eth0", Path("/o"))
        for flag in ("--cap-drop=all", "--cap-add=NET_RAW", "--read-only", "no-new-privileges",
                     "--pids-limit", "--memory", "mvm.run=RID", "SIGINT"):
            self.assertIn(flag, argv)
        self.assertNotIn("--cap-add=NET_ADMIN", argv)
        sensor = str(self.mvm.observer.SENSOR)
        self.assertEqual([a for a in argv if a.startswith("-v") or ":/" in a],
                         ["-v", f"{sensor}:/obs/tlsobs.py:ro,z", "-v", "/o:/out:z"])   # the sensor read-only
        self.assertEqual(argv[argv.index(self.mvm.observer.OBSERVER_IMAGE) + 1:],
                         ["python3", "-I", "-B", "/obs/tlsobs.py", "eth0", "/out/flows.jsonl"])
        self.assertIn("@sha256:", self.mvm.observer.OBSERVER_IMAGE)


class CheckTests(Base):
    # Shape of real osv-scanner v2.7.1 --all-packages JSON (trimmed) for a lockfile with
    # flatmap-stream@0.1.1 (MAL-2025-20690), lodash@4.17.15 (GHSA) and left-pad (clean).
    OSV = {"results": [{"source": {"path": "/src/package-lock.json", "type": "lockfile"}, "packages": [
        {"package": {"name": "flatmap-stream", "version": "0.1.1", "ecosystem": "npm"},
         "vulnerabilities": [{"id": "MAL-2025-20690"}, {"id": "GHSA-9x64-5r7x-2q53"}]},
        {"package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
         "vulnerabilities": [{"id": "GHSA-29mw-wpgm-hmr9"}]},
        {"package": {"name": "left-pad", "version": "1.3.0", "ecosystem": "npm"}}]}],
        "experimental_config": {}}

    def test_parse_real_shape(self):
        s = self.mvm.check.parse(self.OSV)
        self.assertEqual(s["packages"], 3)
        self.assertEqual([m["package"] for m in s["malicious"]], ["flatmap-stream"])
        self.assertEqual(s["malicious"][0]["source"], "package-lock.json")
        self.assertEqual([v["package"] for v in s["vulnerable"]], ["lodash"])
        line = self.mvm.check.summary_line(s)
        self.assertIn("MALICIOUS: flatmap-stream@0.1.1 (MAL-2025-20690)", line)
        self.assertIn("1 with known vulnerabilities: lodash@4.17.15", line)
        clean = self.mvm.check.parse({"results": [{"packages": [{"package": {"name": "x", "version": "1"}}]}]})
        self.assertIn("1 package(s), no known vulnerabilities", self.mvm.check.summary_line(clean))
        self.assertEqual(self.mvm.check.parse({"results": None})["packages"], 0)

    def test_lockfiles_per_ecosystem(self):
        for rel in ("package-lock.json", "sub/package-lock.json", "package.json", "Cargo.lock", "go.mod", "go.sum"):
            self.write(rel, "x")
        lf = self.mvm.check.lockfiles
        self.assertEqual(lf(self.proj, "node"), ["package-lock.json", "sub/package-lock.json"])
        self.assertEqual(lf(self.proj, "rust"), ["Cargo.lock"])
        self.assertEqual(lf(self.proj, "go"), ["go.mod"])

    def test_lockfiles_never_follow_symlinks(self):
        """The fetch tree was writable in the VM: a planted symlink must not pull host files in."""
        secret = Path(self.tmp.name) / "id_ed25519"
        secret.write_text("PRIVATE")
        outside = Path(self.tmp.name) / "outside"
        outside.mkdir()
        (outside / "package-lock.json").write_text("{}")
        tree = Path(self.tmp.name) / "tree"
        (tree / "sub").mkdir(parents=True)
        (tree / "package-lock.json").symlink_to(secret)
        (tree / "linked").symlink_to(outside)
        (tree / "sub" / "package-lock.json").write_text("{}")
        self.assertEqual(self.mvm.check.lockfiles(tree, "node"), ["sub/package-lock.json"])
        with self.assertRaises(OSError):                          # ELOOP: never read through a link
            self.mvm.check._read_nofollow(tree / "package-lock.json", 100)

    def test_scan_without_lockfile_skips_without_a_vm(self):
        self.write("package.json", "{}")
        with mock.patch.object(sys.modules["mvm.runtime"], "execute") as ex:
            s = self.mvm.check.scan_project(self.proj, "node", {})
        ex.assert_not_called()
        self.assertEqual(s["skipped"], "no lockfile")

    def test_scan_failure_raises(self):
        """Fail closed: a scan that did not complete is an error, never 'no findings'."""
        self.write("package-lock.json", "{}")
        with mock.patch.object(sys.modules["mvm.core"], "pinned", return_value="osv@sha256:x"), \
                mock.patch.object(sys.modules["mvm.runtime"], "execute", return_value=2):
            with self.assertRaises(self.mvm.MvmError):
                self.mvm.check.scan_project(self.proj, "node", {})
        with mock.patch.object(sys.modules["mvm.core"], "pinned", return_value="osv@sha256:x"), \
                mock.patch.object(sys.modules["mvm.runtime"], "execute", return_value=0):
            with self.assertRaises(self.mvm.MvmError):         # exit 0 but no result file
                self.mvm.check.scan_project(self.proj, "node", {})

    def test_no_packages_exit_only_for_a_provably_empty_lockfile(self):
        """osv-scanner exits 128 on a fresh `npm init` lockfile: that is 0 packages, not an
        error, but only when the lockfile copied in really lists nothing."""
        fresh = '{"name": "x", "lockfileVersion": 3, "requires": true, "packages": {"": {"name": "x"}}}'
        def blank_it(plan):                        # the VM may rewrite its copy: never trusted
            (plan.src / "package-lock.json").write_text(fresh)
            return 128
        for lock, effect, ok in ((fresh, None, True),
                                 (fresh.replace('}}}', '}, "node_modules/a": {"version": "1.0.0"}}}'), None, False),
                                 ('{"dependencies": {"a": {"version": "1.0.0"}}}', None, False),
                                 ("not json", None, False),
                                 ('{"packages": [""]}', None, False),
                                 ('{"packages": {"": {}, "node_modules/a": {}}}', blank_it, False)):
            self.write("package-lock.json", lock)
            with mock.patch.object(sys.modules["mvm.core"], "pinned", return_value="osv@sha256:x"), \
                    mock.patch.object(sys.modules["mvm.runtime"], "execute", return_value=128, side_effect=effect):
                if ok:
                    s = self.mvm.check.scan_project(self.proj, "node", {})
                    self.assertEqual((s["packages"], s["malicious"], s["lockfiles"]), (0, [], ["package-lock.json"]))
                else:
                    with self.assertRaises(self.mvm.MvmError, msg=lock):
                        self.mvm.check.scan_project(self.proj, "node", {})
        e = self.mvm.check.lockfile_empty
        self.assertTrue(e(b"version = 3\n", "Cargo.lock"))
        self.assertFalse(e(b'[[ package ]]\nname = "a"\n', "Cargo.lock"))
        self.assertTrue(e(b"module x\n\ngo 1.22\n", "go.mod"))
        self.assertFalse(e(b"module x\nrequire(\n a v1\n)\n", "go.mod"))

    def test_scanner_sees_only_lockfiles_and_osv(self):
        self.write("package-lock.json", "{}")
        self.write("src/secret.js", "x")
        seen = {}
        def fake(plan):
            seen["files"] = sorted(str(p.relative_to(plan.src)) for p in plan.src.rglob("*") if p.is_file())
            seen["plan"] = plan
            (plan.src / ".mvm-osv.json").write_text('{"results": []}')
            return 0
        with mock.patch.object(sys.modules["mvm.core"], "pinned", return_value="osv@sha256:x"), \
                mock.patch.object(sys.modules["mvm.runtime"], "execute", side_effect=fake):
            self.mvm.check.scan_project(self.proj, "node", {})
        self.assertEqual(seen["files"], ["package-lock.json"])
        p = seen["plan"]
        self.assertEqual(p.allow, ["api.osv.dev"])
        self.assertTrue(p.net)
        self.assertEqual(p.caches, [])
        self.assertIn("--no-call-analysis=all", p.cmd)               # rust call analysis runs build scripts
        self.assertIn("--no-resolve", p.cmd)

    def test_check_and_notify_config(self):
        self.assertTrue(self.mvm.check.before_fetch(self.mvm.load_config()))          # on by default
        self.mvm.CONFIG_PATH.write_text('[check]\nbefore_fetch = false\n[notify]\nntfy = "https://ntfy.sh/t-1"\n')
        cfg = self.mvm.load_config()
        self.assertFalse(self.mvm.check.before_fetch(cfg))
        self.assertEqual(self.mvm.check.notify_url(cfg), "https://ntfy.sh/t-1")
        for bad in ('[check]\nbefore_fetch = "no"\n', '[check]\nx = 1\n', '[notify]\nntfy = "http://ntfy.sh/t"\n',
                    '[notify]\nntfy = "file:///etc/passwd"\n', '[notify]\nurl = "https://a/b"\n'):
            self.mvm.CONFIG_PATH.write_text(bad)
            with self.assertRaises(SystemExit, msg=bad):
                self.mvm.load_config()

    def test_notify_posts_and_never_raises(self):
        import http.server
        import threading
        got = []
        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                got.append((self.headers["Title"], self.rfile.read(int(self.headers["Content-Length"])).decode()))
                self.send_response(200)
                self.end_headers()
            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.handle_request, daemon=True).start()
        url = f"http://127.0.0.1:{srv.server_address[1]}/t"
        self.assertTrue(self.mvm.check.notify(url, "mvm check: x", "body"))
        srv.server_close()
        self.assertEqual(got, [("mvm check: x", "body")])
        self.assertFalse(self.mvm.check.notify("http://127.0.0.1:9/t", "t", "m"))   # refused: no raise
        self.assertFalse(self.mvm.check.notify("", "t", "m"))
        self.assertFalse(self.mvm.check.notify("file:///etc/passwd", "t", "m"))
        import http.client
        with mock.patch("urllib.request.urlopen", side_effect=http.client.BadStatusLine("x")):
            self.assertFalse(self.mvm.check.notify("https://n.example/t", "t", "m"))   # not an OSError

    def test_fetch_refused_when_lockfile_is_malicious(self):
        self.write("package.json", "{}")
        mal = {"packages": 1, "malicious": [{"package": "flatmap-stream", "version": "0.1.1", "ids": ["MAL-1"]}],
               "vulnerable": []}
        cwd = os.getcwd()
        os.chdir(self.proj)
        try:
            with mock.patch.object(sys.modules["mvm.check"], "scan_project", return_value=mal), \
                    mock.patch.object(sys.modules["mvm.cli"], "execute") as ex:
                rc = self.mvm.cmd_fetch([])
        finally:
            os.chdir(cwd)
        self.assertEqual(rc, self.mvm.EXIT_MALICIOUS)
        ex.assert_not_called()                       # nothing downloaded
        rec = json.loads(next((self.mvm.STATE_ROOT / "checks").glob("*.json")).read_text())
        self.assertEqual(rec["ecos"]["node"]["malicious"][0]["package"], "flatmap-stream")

    def test_plain_fetch_is_gated_too(self):
        """cargo fetch without Cargo.lock writes one: the gate must run without a custom command."""
        self.write("Cargo.toml", '[package]\nname = "r"\nversion = "0.1.0"\n')
        plans = []
        clean = {"skipped": "no lockfile", "packages": 0, "malicious": [], "vulnerable": []}
        cwd = os.getcwd()
        os.chdir(self.proj)
        try:
            with mock.patch.object(sys.modules["mvm.check"], "scan_project", return_value=clean), \
                    mock.patch.object(sys.modules["mvm.cli"], "image_for", return_value="img"), \
                    mock.patch.object(sys.modules["mvm.cli"], "execute", side_effect=lambda p: plans.append(p) or 0):
                self.assertEqual(self.mvm.cmd_fetch([]), 0)
                self.assertEqual(self.mvm.cmd_fetch(["--learn"]), 0)
        finally:
            os.chdir(cwd)
        self.assertIsNotNone(plans[0].gate)
        self.assertIsNone(plans[1].gate)                          # learn never commits

    def test_post_check_scans_only_a_changed_lockfile(self):
        self.write("package.json", "{}")
        tree = Path(self.tmp.name) / "tree"
        tree.mkdir()
        (tree / "package.json").write_text("{}")
        with mock.patch.object(sys.modules["mvm.check"], "scan_tree") as st:
            self.assertEqual(self.mvm.post_check(self.proj, tree, "node", {}), "")
        st.assert_not_called()
        (tree / "package-lock.json").write_text("{}")
        mal = {"packages": 1, "malicious": [{"package": "evil", "version": "1", "ids": ["MAL-1"]}], "vulnerable": []}
        with mock.patch.object(sys.modules["mvm.check"], "scan_tree", return_value=mal):
            self.assertIn("evil@1", self.mvm.post_check(self.proj, tree, "node", {}))

    def test_known_projects_from_records(self):
        gone = Path(self.tmp.name) / "gone"
        for i, (kind, cwd) in enumerate([("fetch", self.proj), ("build", Path(self.tmp.name)), ("fetch", gone)]):
            self.mvm.write_json_atomic(self.mvm.STATE_ROOT / "runs" / f"{i}.json", {"kind": kind, "cwd": str(cwd)})
        self.assertEqual(self.mvm.check.known_projects(), [self.proj])


class CommitTests(Base):
    """Commit-on-clean: writes reach the cache only when the command exits 0."""

    def setUp(self):
        super().setUp()
        self.cache = self.mvm.Cache("c1", "/c1", True, "16M")
        self.mvm.ensure_cache(self.cache)
        self.img = self.mvm.cache_img("c1")
        self.img.write_bytes(b"ORIGINAL")

    def run_with(self, behaviour):
        def fake(argv, *_a, **_k):
            # the mounted image is the run copy, never the real cache
            src = next(a for a in argv if a.endswith(":/run/mvm-imgs/0-c1.img:z")).split(":")[0]
            self.assertIn(".img.run-", src)
            Path(src).write_bytes(b"WRITTEN")
            return behaviour()
        plan = self.mvm.Plan(kind="build", eco="go", image="i", memory="1g", cmd=["x"],
                             src=None, caches=[self.cache])
        with mock.patch.object(sys.modules["mvm.runtime"], "run_podman", side_effect=fake), \
                mock.patch.object(sys.modules["mvm.runtime"], "reap_orphans", return_value=[]), \
                mock.patch.object(sys.modules["mvm.runtime"], "kill_container"):
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

    def test_learn_never_commits(self):
        class FakeProxy:
            def __init__(self, *a): self.port = 1; self.healthy = True; self.summary = {"allowed": {}, "denied": {}}
            def __enter__(self): return self
            def __exit__(self, *e): return False
        self.mvm.LIB_DIR = Path(self.tmp.name) / "lib"
        self.mvm.LIB_DIR.mkdir()
        (self.mvm.LIB_DIR / "smokescreen").write_text("")       # present; the proxy itself is faked
        with mock.patch.object(sys.modules["mvm.egress"], "Proxy", FakeProxy):
            def fake(argv, *_a, **_k):
                src = next(a for a in argv if a.endswith(":/run/mvm-imgs/0-c1.img:z")).split(":")[0]
                Path(src).write_bytes(b"LEARNED")
                return 0
            plan = self.mvm.Plan(kind="fetch", eco="go", image="i", memory="1g", cmd=["x"], src=None,
                                 caches=[self.cache], net=True, learn=True, allow=["a.org"])
            with mock.patch.object(sys.modules["mvm.runtime"], "run_podman", side_effect=fake), \
                    mock.patch.object(sys.modules["mvm.runtime"], "reap_orphans", return_value=[]):
                self.assertEqual(self.mvm.execute(plan), 0)
        self.assertEqual(self.img.read_bytes(), b"ORIGINAL")
        self.assertEqual(self.last_record()["result"], "learned")
        self.assertEqual(self.last_record()["egress"]["mode"], "learn")

    def _net_run(self, summary, healthy=True, observed=None):
        """observed: None = observer off, else (observer summary, observer healthy)."""
        class FakeProxy:
            def __init__(self, *a):
                self.port = 1; self.healthy = healthy; self.summary = summary
                self.name = "pod"; self.iface = "eth0"
            def __enter__(self): return self
            def __exit__(self, *e): return False
        class FakeObserver:
            def __init__(self, *a):
                self.summary, self.healthy = observed
            def __enter__(self): return self
            def __exit__(self, *e): return False
        self.mvm.LIB_DIR = Path(self.tmp.name) / "lib"
        self.mvm.LIB_DIR.mkdir(exist_ok=True)
        (self.mvm.LIB_DIR / "smokescreen").write_text("")
        def fake(argv, *_a, **_k):
            src = next(a for a in argv if a.endswith(":/run/mvm-imgs/0-c1.img:z")).split(":")[0]
            Path(src).write_bytes(b"WRITTEN")
            return 0
        plan = self.mvm.Plan(kind="fetch", eco="go", image="i", memory="1g", cmd=["x"], src=None,
                             caches=[self.cache], net=True, allow=["a.org"], observe=observed is not None)
        with mock.patch.object(sys.modules["mvm.egress"], "Proxy", FakeProxy), \
                mock.patch.object(sys.modules["mvm.observer"], "Observer", FakeObserver), \
                mock.patch.object(sys.modules["mvm.observer"], "image_present", return_value=True), \
                mock.patch.object(sys.modules["mvm.runtime"], "run_podman", side_effect=fake), \
                mock.patch.object(sys.modules["mvm.runtime"], "reap_orphans", return_value=[]):
            return self.mvm.execute(plan)

    OK = {"allowed": {"a.org": {"connections": 1}}, "denied": {}}

    def test_observed_clean_run_commits(self):
        rc = self._net_run(self.OK, observed=({"flows": [{"sni": "a.org"}], "ja4": ["t13"], "outside_allowlist": []}, True))
        self.assertEqual(rc, 0)
        self.assertEqual(self.img.read_bytes(), b"WRITTEN")
        self.assertEqual(self.last_record()["observer"]["ja4"], ["t13"])

    def test_dead_observer_fails_the_run(self):
        """Fail closed: when the observer is on, a run it did not fully observe never commits."""
        rc = self._net_run(self.OK, observed=({"flows": [], "ja4": [], "outside_allowlist": []}, False))
        self.assertEqual(rc, self.mvm.EXIT_OBSERVER_FAILED)
        self.assertEqual(self.img.read_bytes(), b"ORIGINAL")
        self.assertEqual(self.last_record()["result"], "observer-failed")

    def test_unobserved_connection_fails_the_run(self):
        """A proxy connection with no observed flow (capture missed it) is not trusted."""
        two = {"allowed": {"a.org": {"connections": 2}}, "denied": {}}
        rc = self._net_run(two, observed=({"flows": [{"sni": "a.org"}], "ja4": [], "outside_allowlist": []}, True))
        self.assertEqual(rc, self.mvm.EXIT_OBSERVER_FAILED)
        self.assertEqual(self.img.read_bytes(), b"ORIGINAL")
        self.assertEqual(self.last_record()["observer"]["unobserved_connections"], 1)
        self.assertFalse(self.last_record()["observer"]["healthy"])

    def test_sni_outside_allowlist_holds_the_run(self):
        """Domain fronting: CONNECT to an allowed host, TLS SNI for another name."""
        rc = self._net_run(self.OK, observed=({"flows": [{"sni": "evil.example"}], "ja4": [],
                                               "outside_allowlist": ["evil.example"]}, True))
        self.assertEqual(rc, self.mvm.EXIT_EGRESS_DENIED)
        self.assertEqual(self.img.read_bytes(), b"ORIGINAL")
        self.assertEqual(self.last_record()["result"], "held")

    def test_observer_on_without_image_refuses_before_touching_anything(self):
        self.mvm.LIB_DIR = Path(self.tmp.name) / "lib"
        self.mvm.LIB_DIR.mkdir(exist_ok=True)
        (self.mvm.LIB_DIR / "smokescreen").write_text("")
        plan = self.mvm.Plan(kind="fetch", eco="go", image="i", memory="1g", cmd=["x"], src=None, net=True,
                             caches=[self.mvm.Cache("c9", "/c9", True, "16M")], observe=True)
        with mock.patch.object(sys.modules["mvm.observer"], "image_present", return_value=False):
            with self.assertRaises(self.mvm.MvmError) as e:
                self.mvm.execute(plan)
        self.assertIn("make observer", str(e.exception))
        self.assertFalse(self.mvm.cache_img("c9").exists())
        self.assertFalse((self.mvm.STATE_ROOT / "runs").exists())

    def test_denied_egress_holds_the_run(self):
        """Exit 0 is not enough: a run that tried a denied host is not committed."""
        rc = self._net_run({"allowed": {}, "denied": {"evil.example": {"connections": 1}}})
        self.assertEqual(rc, self.mvm.EXIT_EGRESS_DENIED)
        self.assertEqual(self.img.read_bytes(), b"ORIGINAL")
        self.assertEqual(self.last_record()["result"], "held")

    def test_dead_proxy_fails_the_run(self):
        rc = self._net_run({"allowed": {}, "denied": {}}, healthy=False)
        self.assertEqual(rc, self.mvm.EXIT_PROXY_FAILED)
        self.assertEqual(self.img.read_bytes(), b"ORIGINAL")
        self.assertEqual(self.last_record()["result"], "proxy-failed")

    def test_clean_net_run_commits(self):
        self.assertEqual(self._net_run({"allowed": {"a.org": {"connections": 1}}, "denied": {}}), 0)
        self.assertEqual(self.img.read_bytes(), b"WRITTEN")

    def _gated(self, gate=None, rc=0, ok_exit=(0,), notify=""):
        def fake(argv, *_a, **_k):
            src = next(a for a in argv if a.endswith(":/run/mvm-imgs/0-c1.img:z")).split(":")[0]
            Path(src).write_bytes(b"WRITTEN")
            return rc
        plan = self.mvm.Plan(kind="build", eco="go", image="i", memory="1g", cmd=["x"], src=None,
                             caches=[self.cache], gate=gate, ok_exit=ok_exit, notify=notify)
        with mock.patch.object(sys.modules["mvm.runtime"], "run_podman", side_effect=fake), \
                mock.patch.object(sys.modules["mvm.runtime"], "reap_orphans", return_value=[]):
            return self.mvm.execute(plan)

    def test_gate_reason_refuses_commit(self):
        with mock.patch.object(sys.modules["mvm.check"], "notify") as n:
            rc = self._gated(gate=lambda: "the new lockfile pins evil@1", notify="https://n/t")
        self.assertEqual(rc, self.mvm.EXIT_MALICIOUS)
        self.assertEqual(self.img.read_bytes(), b"ORIGINAL")
        self.assertEqual(self.last_record()["result"], "malicious")
        n.assert_called_once()                       # a trip is notified

    def test_empty_gate_commits_and_ok_exit_counts_as_clean(self):
        self.assertEqual(self._gated(gate=lambda: ""), 0)
        self.assertEqual(self.img.read_bytes(), b"WRITTEN")
        self.img.write_bytes(b"ORIGINAL")
        self.assertEqual(self._gated(rc=1, ok_exit=(0, 1)), 1)       # osv-scanner: 1 = findings
        self.assertEqual(self.last_record()["result"], "committed")

    def test_gate_error_discards_and_records_error(self):
        def boom():
            raise self.mvm.MvmError("scan failed")
        with self.assertRaises(self.mvm.MvmError):
            self._gated(gate=boom)
        self.assertEqual(self.img.read_bytes(), b"ORIGINAL")
        self.assertEqual(self.last_record()["result"], "error")       # not "interrupted"

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

    @staticmethod
    def observer_image() -> bool:
        sys.path.insert(0, str(REPO))
        from mvm import observer
        return observer.image_present()

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

    def test_confined_pull(self):
        """Proves: an image pull goes through the proxy and observer, loads offline by digest,
        runs; a registry outside the allowlist is held (exit 3) with the [allow] line."""
        tag = "docker.io/library/busybox:1.37"
        r = self.mvm("pull", tag)
        self.assertEqual(r.returncode, 0, r.stderr)
        ref = json.loads((Path(self.env["MVM_STATE_DIR"]) / "pins.json").read_text())[tag]["ref"]
        self.assertIn(f"pulled {tag} -> {ref}", r.stderr)
        rec = json.loads(sorted((Path(self.env["MVM_STATE_DIR"]) / "runs").glob("*.json"))[-1].read_text())
        self.assertEqual((rec["kind"], rec["result"]), ("pull", "ok"))
        self.assertIn("registry-1.docker.io", rec["egress"]["allowed"])
        if self.observer_image():
            self.assertTrue(rec["observer"]["healthy"])
            self.assertEqual(rec["observer"]["outside_allowlist"], [])
        self.assertEqual(list((self.cache / "pulls").iterdir()), [])        # the download is gone
        r = self.mvm("run", "-i", tag, "--", "echo", "pulled-and-ran")
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "pulled-and-ran"), r.stderr)
        r = self.mvm("pull", "quay.io/prometheus/busybox:latest")
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn("HELD, nothing loaded", r.stderr)
        self.assertIn('[allow]  pull = ["quay.io"]', r.stderr)

    def test_confined_image_build(self):
        """Proves: mvm image build pulls a missing base through the egress, runs RUN steps in
        krun with apk through the proxy, tags only a clean build, leaks no proxy env; a step
        reaching a disallowed host is held (exit 3) and nothing is tagged."""
        cf = self.proj / "Containerfile"
        cf.write_text("FROM docker.io/library/busybox:1.37 AS b\nFROM docker.io/library/alpine:3.24\n"
                      "COPY --from=b /bin/busybox /bb\nRUN apk add --no-cache jq && uname -r > /kernel\n")
        tag = "localhost/mvm-test-build:1"
        try:
            r = self.mvm("image", "build", "-t", tag, "-f", str(cf))
            self.assertEqual(r.returncode, 0, r.stderr)
            env = subprocess.run(["podman", "image", "inspect", "--format", "{{json .Config.Env}}", tag],
                                 capture_output=True, text=True, check=True).stdout
            self.assertNotIn("127.0.0.1", env)
            r = self.mvm("run", "-i", tag, "--", "sh", "-c", "jq --version && cat /kernel")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("jq-", r.stdout)
            self.assertNotEqual(r.stdout.split()[-1], os.uname().release)          # built in the guest kernel
            cf.write_text("FROM docker.io/library/alpine:3.24\nRUN wget -q -O- https://example.com/ || true\n")
            neg = "localhost/mvm-test-build:neg"
            r = self.mvm("image", "build", "-t", neg, "-f", str(cf))
            self.assertEqual(r.returncode, 3, r.stderr)
            self.assertIn('[allow]  image-build = ["example.com"]', r.stderr)
            self.assertNotEqual(subprocess.run(["podman", "image", "exists", neg]).returncode, 0)
            tmp = subprocess.run(["podman", "images", "-q", "localhost/mvm-build-tmp"], capture_output=True, text=True)
            self.assertEqual(tmp.stdout.strip(), "")
        finally:
            subprocess.run(["podman", "rmi", "-f", tag, "docker.io/library/busybox:1.37"], capture_output=True)

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

    def test_escape(self):
        """Proves: a fetch VM's only way out is the allowlist proxy. Direct TCP, DNS and
        CONNECT to an unlisted host fail; CONNECT to an allowed host succeeds; the denial
        lands in the run record and holds the run (exit 3, nothing committed).
        Needs the Smokescreen binary (MVM_LIB_DIR or ~/.local/lib/mvm) and internet."""
        lib = Path(os.environ.get("MVM_LIB_DIR", Path.home() / ".local/lib/mvm"))
        if not (lib / "smokescreen").is_file():
            self.skipTest(f"no smokescreen in {lib} (make smokescreen)")
        probe = (
            'P=${HTTPS_PROXY##*:}; '
            'conn() { printf "CONNECT $1:443 HTTP/1.1\\r\\nHost: $1:443\\r\\n\\r\\n" | nc -w 8 127.0.0.1 $P | head -1; }; '
            'echo "direct=$(nc -w 3 1.1.1.1 443 </dev/null >/dev/null 2>&1 && echo OPEN || echo closed)"; '
            'echo "dns=$(nslookup -timeout=2 example.com 169.254.1.1 2>&1 | grep -c "Address: [0-9]")"; '
            'echo "unlisted=$(conn example.com)"; '
            'echo "allowed=$(conn proxy.golang.org)"; '
            'echo "allowed_port22=$(printf "CONNECT proxy.golang.org:22 HTTP/1.1\\r\\n\\r\\n" | nc -w 8 127.0.0.1 $P | head -1)"'
        )
        r = self.mvm("fetch", "go", "--", "sh", "-c", probe)
        # The probe itself tried an unlisted host, so the run is held (exit 3), not committed.
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn("direct=closed", r.stdout)
        self.assertIn("dns=0", r.stdout)
        self.assertRegex(r.stdout, r"unlisted=HTTP/1\.[01] 40[37]")
        self.assertRegex(r.stdout, r"allowed=HTTP/1\.[01] 200")
        self.assertRegex(r.stdout, r"allowed_port22=HTTP/1\.[01] 50[24]")    # kernel filter: 443 only
        self.assertNotIn("allowed_port22=HTTP/1.0 200", r.stdout)
        recs = sorted((Path(self.env["MVM_STATE_DIR"]) / "runs").glob("*.json"))
        rec = json.loads(recs[-1].read_text())
        self.assertEqual(rec["egress"]["mode"], "enforce")
        self.assertEqual(rec["result"], "held")
        self.assertIn("example.com", rec["egress"]["denied"])
        self.assertIn("proxy.golang.org", rec["egress"]["allowed"])
        self.assertIn("tried hosts that are not allowed: example.com, proxy.golang.org (port 22 blocked", r.stderr)
        self.assertIn('[allow]  go = ["example.com"]', r.stderr)          # the exact line; never a port refusal
        self.assertNotIn("egress allowed:", r.stderr)                     # details only with -v

    FRONT_GO = r"""package main

import ("bufio"; "crypto/tls"; "fmt"; "net"; "net/http"; "os"; "strings")

// CONNECT to an allowed host, then send a TLS ClientHello whose SNI is `sni`.
func hello(sni string) {
	px := strings.TrimPrefix(os.Getenv("HTTPS_PROXY"), "http://")
	c, err := net.Dial("tcp", px)
	if err != nil { fmt.Println("dial", err); return }
	defer c.Close()
	fmt.Fprintf(c, "CONNECT proxy.golang.org:443 HTTP/1.1\r\nHost: proxy.golang.org:443\r\n\r\n")
	r, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || r.StatusCode != 200 { fmt.Println("connect", err); return }
	err = tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).Handshake()
	fmt.Println("hello", sni, err == nil)
}

func main() { hello("proxy.golang.org"); hello("example.com") }
"""

    def test_observer_catches_domain_fronting(self):
        """Proves: with the observer on, a TLS ClientHello whose SNI is outside the allowlist,
        sent through a CONNECT the proxy allowed, holds the run (exit 3, nothing committed).
        Negative control in the same run: the honest SNI is observed and not flagged.
        Needs smokescreen, the observer image (make observer) and internet."""
        lib = Path(os.environ.get("MVM_LIB_DIR", Path.home() / ".local/lib/mvm"))
        if not (lib / "smokescreen").is_file():
            self.skipTest(f"no smokescreen in {lib} (make smokescreen)")
        if not self.observer_image():
            self.skipTest("no observer image (make observer)")
        cfg = Path(self.tmp.name) / "obs.toml"
        cfg.write_text("[observer]\nenabled = true\n")
        self.env["MVM_CONFIG"] = str(cfg)
        import base64
        b64 = base64.b64encode(self.FRONT_GO.encode()).decode()
        r = self.mvm("fetch", "go", "--", "sh", "-c",
                     f"echo {b64} | base64 -d > /tmp/f.go && cd /tmp && GOCACHE=/tmp/gc go run f.go")
        self.assertIn("hello proxy.golang.org", r.stdout, r.stderr)     # control: both hellos were sent
        self.assertIn("hello example.com", r.stdout, r.stderr)
        self.assertEqual(r.returncode, 3, r.stderr)
        rec = json.loads(sorted((Path(self.env["MVM_STATE_DIR"]) / "runs").glob("*.json"))[-1].read_text())
        self.assertEqual(rec["result"], "held")
        self.assertEqual(rec["egress"]["denied"], {})                    # the proxy saw nothing wrong
        self.assertTrue(rec["observer"]["healthy"])
        self.assertEqual(rec["observer"]["capture"]["drops"], 0)
        self.assertEqual(rec["observer"]["unobserved_connections"], 0)
        self.assertEqual(rec["observer"]["outside_allowlist"], ["example.com"])
        self.assertEqual(sorted({f["sni"] for f in rec["observer"]["flows"]}), ["example.com", "proxy.golang.org"])
        self.assertTrue(all(f["ja4"] for f in rec["observer"]["flows"]))
        self.assertIn("HELD, nothing committed: through a tunnel to an allowed host it sent TLS to example.com",
                      r.stderr)

    def test_sensor_matches_ndpi_on_real_fetches(self):
        """Proves: on real go, rust and node fetches (registry clients' own ClientHellos,
        Go's with a post-quantum key share spanning TCP segments), mvm's sensor reports the
        same SNI and JA4 per connection as nDPI 5.0 reading the very same packets.
        Needs smokescreen, the observer image, `make ndpi-oracle` and internet."""
        lib = Path(os.environ.get("MVM_LIB_DIR", Path.home() / ".local/lib/mvm"))
        if not (lib / "smokescreen").is_file():
            self.skipTest(f"no smokescreen in {lib} (make smokescreen)")
        oracle = "localhost/mvm-ndpi-oracle:5.0"
        if subprocess.run(["podman", "image", "exists", oracle]).returncode != 0:
            self.skipTest(f"no {oracle} (make ndpi-oracle)")
        if not self.observer_image():
            self.skipTest("no observer image (make observer)")
        keep = Path(self.tmp.name) / "keep"
        keep.mkdir()
        self.env["MVM_OBSERVER_PCAP"] = str(keep)
        (self.proj / "go.mod").write_text("module example.com/x\n\ngo 1.27\n\nrequire rsc.io/quote v1.5.2\n")
        r = self.mvm("fetch", "go")
        self.assertEqual(r.returncode, 0, r.stderr)
        (self.proj / "go.mod").unlink()
        (self.proj / "Cargo.toml").write_text('[package]\nname = "x"\nversion = "0.1.0"\nedition = "2021"\n\n'
                                              '[dependencies]\nitoa = "1"\n')
        (self.proj / "src").mkdir()
        (self.proj / "src" / "main.rs").write_text("fn main() {}\n")
        r = self.mvm("fetch", "rust")
        self.assertEqual(r.returncode, 0, r.stderr)
        for f in ("Cargo.toml", "Cargo.lock"):
            (self.proj / f).unlink(missing_ok=True)
        (self.proj / "package.json").write_text('{"name":"p","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}')
        (self.proj / "package-lock.json").write_text(json.dumps(
            {"name": "p", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": {
                "": {"name": "p", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}},
                "node_modules/left-pad": {"version": "1.3.0", "resolved":
                    "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", "integrity":
                    "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="}}}))
        r = self.mvm("fetch", "node")
        self.assertEqual(r.returncode, 0, r.stderr)
        compared = set()
        for pcap in sorted(keep.glob("*-cap.pcap")):
            ours = sorted((d["sni"], d["ja4"]) for d in map(json.loads, Path(str(pcap).replace("-cap.pcap", "-flows.jsonl"))
                                                                .read_text().splitlines()) if d["proto"] == "TLS")
            out = Path(self.tmp.name) / "oracle"
            out.mkdir(exist_ok=True)
            subprocess.run(["podman", "run", "--rm", "--network=none", "--cap-drop=all",
                            "-v", f"{keep}:/in:ro,z", "-v", f"{out}:/out:z", oracle,
                            "-i", f"/in/{pcap.name}", "-k", "/out/n.json", "-K", "json"],
                           capture_output=True, check=True)
            theirs = []
            for line in (out / "n.json").read_text().splitlines():
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                n = d.get("ndpi", {}) if isinstance(d, dict) else {}
                if isinstance(d, dict) and d.get("dst_port") == 443 and str(n.get("proto", "")).startswith("TLS"):
                    theirs.append((n.get("hostname", ""), (n.get("tls") or {}).get("ja4", "")))
            self.assertEqual(ours, sorted(theirs), pcap.name)
            self.assertTrue(all(sni and ja4 for sni, ja4 in ours))
            compared |= set(ours)
        snis = {s for s, _ in compared}
        for host in ("proxy.golang.org", "index.crates.io", "registry.npmjs.org", "api.osv.dev"):
            self.assertIn(host, snis)

    def test_observer_quiet_fetch_commits(self):
        """Proves: with the observer on, a fetch that makes no connection still commits
        (the sensor writes an empty flow file and a clean stats line with no traffic)."""
        if not self.observer_image():
            self.skipTest("no observer image (make observer)")
        cfg = Path(self.tmp.name) / "obs.toml"
        cfg.write_text("[observer]\nenabled = true\n")
        self.env["MVM_CONFIG"] = str(cfg)
        r = self.mvm("fetch", "go", "--", "true")
        self.assertEqual(r.returncode, 0, r.stderr)
        rec = json.loads(sorted((Path(self.env["MVM_STATE_DIR"]) / "runs").glob("*.json"))[-1].read_text())
        self.assertEqual(rec["observer"]["flows"], [])
        self.assertTrue(rec["observer"]["healthy"])
        self.assertEqual((rec["observer"]["capture"]["drops"], rec["observer"]["flows"]), (0, []))

    PLAIN_GO = r"""package main

import ("bufio"; "crypto/tls"; "fmt"; "net"; "net/http"; "os"; "strings")

// CONNECT proxy.golang.org:443, then either a real TLS handshake or plaintext HTTP.
func tunnel(plain bool) {
	px := strings.TrimPrefix(os.Getenv("HTTPS_PROXY"), "http://")
	c, err := net.Dial("tcp", px)
	if err != nil { fmt.Println("dial", err); return }
	defer c.Close()
	fmt.Fprintf(c, "CONNECT proxy.golang.org:443 HTTP/1.1\r\nHost: proxy.golang.org:443\r\n\r\n")
	br := bufio.NewReader(c)
	r, err := http.ReadResponse(br, nil)
	if err != nil || r.StatusCode != 200 { fmt.Println("connect", err); return }
	if !plain {
		err = tls.Client(c, &tls.Config{ServerName: "proxy.golang.org"}).Handshake()
		fmt.Println("tls", err == nil)
		return
	}
	fmt.Fprintf(c, "GET / HTTP/1.0\r\nHost: proxy.golang.org\r\n\r\n")
	line, _ := br.ReadString('\n')
	fmt.Println("plain", strings.TrimSpace(line))
}

func main() { tunnel(false); tunnel(true) }
"""

    def test_observer_holds_plaintext_on_443(self):
        """Proves: plaintext HTTP sent through a CONNECT to an allowed host:443 (the sensor sees
        proto HTTP with that Host, no TLS, so no SNI was checked) holds the run (exit 3).
        Control in the same run: real TLS to the same host is observed and not flagged."""
        lib = Path(os.environ.get("MVM_LIB_DIR", Path.home() / ".local/lib/mvm"))
        if not (lib / "smokescreen").is_file():
            self.skipTest(f"no smokescreen in {lib} (make smokescreen)")
        if not self.observer_image():
            self.skipTest("no observer image (make observer)")
        cfg = Path(self.tmp.name) / "obs.toml"
        cfg.write_text("[observer]\nenabled = true\n")
        self.env["MVM_CONFIG"] = str(cfg)
        import base64
        b64 = base64.b64encode(self.PLAIN_GO.encode()).decode()
        r = self.mvm("fetch", "go", "--", "sh", "-c",
                     f"echo {b64} | base64 -d > /tmp/p.go && cd /tmp && GOCACHE=/tmp/gc go run p.go")
        self.assertIn("tls true", r.stdout, r.stderr)                   # control: real TLS
        self.assertIn("plain", r.stdout, r.stderr)    # sent (Google closes plaintext on 443 unanswered)
        self.assertEqual(r.returncode, 3, r.stderr)
        rec = json.loads(sorted((Path(self.env["MVM_STATE_DIR"]) / "runs").glob("*.json"))[-1].read_text())
        self.assertEqual(rec["result"], "held")
        self.assertEqual(rec["egress"]["denied"], {})                    # the proxy saw nothing wrong
        self.assertTrue(rec["observer"]["healthy"])
        self.assertEqual(rec["observer"]["outside_allowlist"], ["(non-tls)"])
        self.assertEqual(sorted(f["proto"] for f in rec["observer"]["flows"]), ["TLS", "non-TLS"])

    def test_fresh_npm_repo_fetches(self):
        """Proves: a fresh `npm init` repo (lockfile with 0 packages; osv-scanner exits 128)
        passes the check before and after a plain fetch and commits (exit 0)."""
        lib = Path(os.environ.get("MVM_LIB_DIR", Path.home() / ".local/lib/mvm"))
        if not (lib / "smokescreen").is_file():
            self.skipTest(f"no smokescreen in {lib} (make smokescreen)")
        (self.proj / "go.mod").unlink()
        (self.proj / "package.json").write_text('{"name":"p","version":"1.0.0"}')
        (self.proj / "package-lock.json").write_text(json.dumps(
            {"name": "p", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
             "packages": {"": {"name": "p", "version": "1.0.0"}}}))
        r = self.mvm("fetch")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("0 package(s)", r.stdout + r.stderr)

    def test_check_blocks_malicious_lockfile(self):
        """Proves: osv-scanner in a krun VM (only api.osv.dev reachable) flags a real MAL-
        advisory; mvm check exits 6 and fetch refuses before creating any cache. Control:
        a clean lockfile passes. Needs smokescreen and internet."""
        lib = Path(os.environ.get("MVM_LIB_DIR", Path.home() / ".local/lib/mvm"))
        if not (lib / "smokescreen").is_file():
            self.skipTest(f"no smokescreen in {lib} (make smokescreen)")
        (self.proj / "go.mod").unlink()
        (self.proj / "package.json").write_text('{"name":"p","version":"1.0.0"}')
        lock = {"name": "p", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": {
            "": {"name": "p", "version": "1.0.0"},
            "node_modules/left-pad": {"version": "1.3.0"}}}
        (self.proj / "package-lock.json").write_text(json.dumps(lock))
        r = self.mvm("check")
        self.assertEqual(r.returncode, 0, r.stderr)                     # control: clean
        self.assertIn("1 package(s), no known vulnerabilities", r.stdout)
        self.assertNotIn("Scanning dir", r.stdout + r.stderr)            # scanner chatter only on failure
        lock["packages"]["node_modules/flatmap-stream"] = {"version": "0.1.1"}
        (self.proj / "package-lock.json").write_text(json.dumps(lock))
        r = self.mvm("-v", "check")
        self.assertEqual(r.returncode, 6, r.stderr)
        self.assertIn("MAL-2025-20690", r.stdout)
        self.assertIn("egress allowed: api.osv.dev", r.stderr)
        self.assertNotIn("DENIED", r.stderr)
        r = self.mvm("fetch")
        self.assertEqual(r.returncode, 6, r.stderr)
        self.assertIn("refusing to fetch", r.stderr)
        self.assertEqual(list(self.cache.glob("*.img")), [])            # nothing was downloaded

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
