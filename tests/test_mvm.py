"""Tests for bin/mvm (stdlib unittest).

Unit tests need no podman/KVM. Real tests (class RealTests) boot krun microVMs
and run only with MVM_REAL=1; each takes a few seconds.
"""

from __future__ import annotations

import fcntl
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
    names = ["core", "ecos", "cache", "project", "egress", "observer", "check", "runtime", "cli"]
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

    def test_observer_config(self):
        self.assertFalse(self.mvm.observer.enabled(self.mvm.load_config()))     # off by default
        self.mvm.CONFIG_PATH.write_text("[observer]\nenabled = true\n")
        self.assertTrue(self.mvm.observer.enabled(self.mvm.load_config()))

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


class ObserverTests(Base):
    # One flow line as real ndpiReader 6.0 wrote it in a proxy pod (trimmed), registry.npmjs.org via curl.
    REAL = ('{"src_ip":"10.5.29.71","dest_ip":"104.16.3.34","src_port":55322,"dst_port":443,"ip":4,'
            '"ndpi":{"proto":"TLS","hostname":"registry.npmjs.org","tls":{"version":"TLSv1.2",'
            '"ja4":"t13d3513h2_bfa337485184_8d7351bd871b"}},'
            '"xfer":{"src2dst_goodput_bytes":1949,"dst2src_goodput_bytes":26332}}')
    DNS = '{"dest_ip":"169.254.1.1","dst_port":53,"ndpi":{"proto":"DNS","hostname":"registry.npmjs.org"}}'

    def test_summarize_real_flow(self):
        s = self.mvm.observer.summarize([self.REAL, self.DNS, "Welcome to nDPI", "[]"], ["registry.npmjs.org"])
        self.assertEqual(s["flows"], [{"sni": "registry.npmjs.org", "ja4": "t13d3513h2_bfa337485184_8d7351bd871b",
                                       "dst": "104.16.3.34", "proto": "TLS", "bytes_out": 1949, "bytes_in": 26332}])
        self.assertEqual(s["outside_allowlist"], [])
        self.assertIn("JA4 t13d3513h2", self.mvm.observer.summary_line(s))

    def test_plaintext_on_443_is_held(self):
        """Plaintext HTTP with an allowed Host header sent through CONNECT :443 has no TLS,
        so no SNI was checked: nDPI reports proto HTTP with the Host as hostname."""
        http = ('{"dest_ip":"142.250.1.1","dst_port":443,"ndpi":{"proto":"HTTP",'
                '"hostname":"proxy.golang.org"},"xfer":{}}')
        s = self.mvm.observer.summarize([http], ["proxy.golang.org"])
        self.assertEqual(s["outside_allowlist"], ["(non-tls:HTTP)"])
        app = self.REAL.replace('"proto":"TLS"', '"proto":"TLS.Cloudflare"')
        unknown = self.REAL.replace('"proto":"TLS",', "")
        s = self.mvm.observer.summarize([app, unknown, self.REAL], ["registry.npmjs.org"])
        self.assertEqual(s["outside_allowlist"], ["(non-tls:unknown)"])   # TLS.<app> is TLS

    def test_sni_outside_allowlist_and_missing_sni(self):
        fronted = self.REAL.replace("registry.npmjs.org", "evil.example")
        no_sni = self.REAL.replace('"hostname":"registry.npmjs.org",', "")
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

    def test_stop_health_needs_clean_exit_flows_and_zero_discarded(self):
        cases = [("Discarded bytes:       0\n", "0", True, self.REAL), ("Discarded bytes:       23222\n", "0", False, self.REAL),
                 ("", "0", False, self.REAL),          # flows but no stats line: not trusted
                 ("", "0", True, ""),                  # zero packets: ndpiReader prints no stats
                 ("Discarded bytes: 0\n", "137", False, self.REAL)]
        for logs, code, healthy, flows in cases:
            ob = self.mvm.observer.Observer("RID", "pod", "eth0", ["a.org"])
            ob._dir = tempfile.TemporaryDirectory()
            (Path(ob._dir.name) / "flows.json").write_text(flows + "\n")
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
        self.assertEqual([a for a in argv if a.startswith("-v") or ":/" in a], ["-v", "/o:/out:z"])


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
        def fake(argv):
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
            def fake(argv):
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
        def fake(argv):
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
        def fake(argv):
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
        self.assertIn("DENIED: example.com", r.stderr)

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
        Needs smokescreen, localhost/mvm-observer:1 (make observer) and internet."""
        lib = Path(os.environ.get("MVM_LIB_DIR", Path.home() / ".local/lib/mvm"))
        if not (lib / "smokescreen").is_file():
            self.skipTest(f"no smokescreen in {lib} (make smokescreen)")
        if subprocess.run(["podman", "image", "exists", "localhost/mvm-observer:1"]).returncode != 0:
            self.skipTest("no localhost/mvm-observer:1 (make observer)")
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
        self.assertEqual(rec["observer"]["discarded_bytes"], 0)
        self.assertEqual(rec["observer"]["unobserved_connections"], 0)
        self.assertEqual(rec["observer"]["outside_allowlist"], ["example.com"])
        self.assertEqual(sorted({f["sni"] for f in rec["observer"]["flows"]}), ["example.com", "proxy.golang.org"])
        self.assertTrue(all(f["ja4"] for f in rec["observer"]["flows"]))
        self.assertIn("SNI OUTSIDE THE ALLOWLIST: example.com", r.stderr)

    def test_observer_quiet_fetch_commits(self):
        """Proves: with the observer on, a fetch that makes no connection still commits
        (ndpiReader writes a flow file and a clean stats line even with no traffic)."""
        if subprocess.run(["podman", "image", "exists", "localhost/mvm-observer:1"]).returncode != 0:
            self.skipTest("no localhost/mvm-observer:1 (make observer)")
        cfg = Path(self.tmp.name) / "obs.toml"
        cfg.write_text("[observer]\nenabled = true\n")
        self.env["MVM_CONFIG"] = str(cfg)
        r = self.mvm("fetch", "go", "--", "true")
        self.assertEqual(r.returncode, 0, r.stderr)
        rec = json.loads(sorted((Path(self.env["MVM_STATE_DIR"]) / "runs").glob("*.json"))[-1].read_text())
        self.assertEqual(rec["observer"]["flows"], [])
        self.assertTrue(rec["observer"]["healthy"])
        self.assertEqual(rec["observer"]["discarded_bytes"], -1)     # no packets, no stats line

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
        """Proves: plaintext HTTP sent through a CONNECT to an allowed host:443 (nDPI sees
        proto HTTP with that Host, no TLS, so no SNI was checked) holds the run (exit 3).
        Control in the same run: real TLS to the same host is observed and not flagged."""
        lib = Path(os.environ.get("MVM_LIB_DIR", Path.home() / ".local/lib/mvm"))
        if not (lib / "smokescreen").is_file():
            self.skipTest(f"no smokescreen in {lib} (make smokescreen)")
        if subprocess.run(["podman", "image", "exists", "localhost/mvm-observer:1"]).returncode != 0:
            self.skipTest("no localhost/mvm-observer:1 (make observer)")
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
        self.assertEqual(rec["observer"]["outside_allowlist"], ["(non-tls:HTTP)"])
        self.assertEqual(sorted(f["proto"] for f in rec["observer"]["flows"]), ["HTTP", "TLS"])

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
        lock["packages"]["node_modules/flatmap-stream"] = {"version": "0.1.1"}
        (self.proj / "package-lock.json").write_text(json.dumps(lock))
        r = self.mvm("check")
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
