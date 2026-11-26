"""Command-line interface."""

from __future__ import annotations

import re
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from . import check, core, egress, imagebuild, observer, pull
from .cache import cache_img, cache_meta, run_copies, try_exclusive
from .core import DEFAULT_MASK, MvmError, die, find_sbin, load_config, now_iso, pinned, pins_path, read_json, resolve_digest, say, write_json_atomic
from .ecos import ECOS, Eco, eco_caches
from .project import changed_manifests, check_writable, copy_back, detect_ecos, find_masks, manifest_tree
from .runtime import Plan, execute, reap_orphans


# podman --user values: name or uid, optionally :group or :gid
USER_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*(:[A-Za-z0-9_][A-Za-z0-9_.-]*)?")


def parse_opts(args: list[str], allow_image: bool) -> tuple[dict, list[str]]:
    opts: dict = {"writable": [], "interactive": False, "image": None, "user": "", "positional": []}
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            if not args[i + 1:]:
                break
            return opts, args[i + 1:]
        if a == "-w" and i + 1 < len(args):
            opts["writable"].append(args[i + 1])
            i += 2
        elif a == "--it":
            opts["interactive"] = True
            i += 1
        elif allow_image and a == "-i" and i + 1 < len(args):
            opts["image"] = args[i + 1]
            i += 2
        elif allow_image and a in ("-u", "--user") and i + 1 < len(args):
            if not USER_RE.fullmatch(args[i + 1]):
                die(f"bad user {args[i + 1]!r}: give NAME, UID, NAME:GROUP or UID:GID")
            opts["user"] = args[i + 1]
            i += 2
        elif a.startswith("-"):
            die(f"unknown option {a!r} (see mvm --help)")
        else:
            opts["positional"].append(a)
            i += 1
    die("missing `-- COMMAND`")
    return opts, []


def memory_for(cfg: dict, key: str, default: str) -> str:
    return str(cfg.get("memory", {}).get(key, default))


def image_for(cfg: dict, eco: Eco) -> str:
    return pinned(cfg.get("images", {}).get(eco.name, eco.image))


def cmd_fetch(args: list[str]) -> int:
    root = Path.cwd().resolve()
    custom: list[str] = []
    learn = "--learn" in args[: args.index("--") if "--" in args else len(args)]
    if learn:
        args = [a for i, a in enumerate(args) if not (a == "--learn" and ("--" not in args or i < args.index("--")))]
    if "--" in args:
        i = args.index("--")
        args, custom = args[:i], args[i + 1:]
        if not custom:
            die("missing command after --")
    if len(args) > 1 or (args and args[0] not in ECOS):
        die(f"usage: mvm fetch [{'|'.join(ECOS)}] [--learn] [-- CMD]")
    ecos = args or detect_ecos(root)
    if custom and len(ecos) != 1:
        die(f"found {', '.join(ecos) or 'no'} ecosystem(s) here; name one: mvm fetch {'|'.join(ECOS)} -- CMD")
    if not ecos:
        die("nothing to fetch: no go.mod, Cargo.toml or package.json here")
    cfg = load_config()
    if learn:
        say("learn mode: egress is allowed but logged, nothing is committed or copied back")
    checking = check.before_fetch(cfg)
    for name in ecos:
        eco = ECOS[name]
        if checking:
            rc = pre_check(root, name, cfg)
            if rc:
                return rc
        with tempfile.TemporaryDirectory(prefix=f"mvm-fetch-{name}-") as tmp:
            tree = Path(tmp)
            manifest_tree(root, eco, tree)
            cmd = custom or list(eco.fetch_cmd)
            if not custom and name == "rust" and (root / "Cargo.lock").is_file():
                cmd.append("--locked")
            if name == "node":
                (tree / "node_modules").mkdir(exist_ok=True)
            plan = Plan(kind="fetch", eco=name, image=image_for(cfg, eco),
                        memory=memory_for(cfg, name, eco.memory), cmd=cmd, src=tree, src_rw=True,
                        net=True, caches=eco_caches(eco, "fetch", root), env={**eco.env, **eco.fetch_env},
                        project=root, learn=learn, allow=egress.allowlist(cfg, name),
                        observe=observer.enabled(cfg), notify=check.notify_url(cfg))
            # Every non-learn fetch: a plain `cargo fetch` without Cargo.lock writes a new one.
            # post_check costs nothing (no VM) when no lockfile changed.
            if checking and not learn:
                plan.gate = lambda tree=tree, name=name: post_check(root, tree, name, cfg)
            rc = execute(plan)
            hosts = allowable(plan.egress_result, plan.allow) if rc == core.EXIT_EGRESS_DENIED else []
            if hosts:
                suggest_allow(name, cfg, hosts)
            if rc != 0:
                return rc
            if learn:
                report_learned(name, plan.egress_result)
                continue
            # Only dependency manifests ever flow back into the project.
            for rel in changed_manifests(root, tree, eco):
                copy_back(tree, root, rel)
                say(f"updated {rel}")
    if "node" in ecos:
        say("node: install scripts were skipped; run them offline: mvm build node -- npm rebuild")
    return 0


def allowable(egress_result: dict, allow: list[str]) -> list[str]:
    """Denied hosts an [allow] line could fix (a port refusal can't be allowed)."""
    return sorted(h for h, v in egress_result.get("denied", {}).items()
                  if h not in allow and not str(v.get("reason", "")).startswith("port "))


def suggest_allow(eco: str, cfg: dict, denied: list[str]) -> None:
    """The exact [allow] line, keeping hosts already configured."""
    have = list(cfg.get("allow", {}).get(eco, []))
    hosts = ", ".join(f'"{h}"' for h in have + [d for d in denied if d not in have])
    say(f"  if expected, allow in {core.CONFIG_PATH}:  [allow]  {eco} = [{hosts}]")
    if eco in ECOS:
        say(f"  to see every host a fetch needs first: mvm fetch {eco} --learn")


def pre_check(root: Path, eco: str, cfg: dict) -> int:
    """osv-scanner on the project's lockfile before any download; a malicious package stops it."""
    s = check.scan_project(root, eco, cfg)
    check.record(root, eco, s)
    say(f"check {eco}: {check.summary_line(s).removeprefix('check: ')}")
    if s["malicious"]:
        names = ", ".join(f"{m['package']}@{m['version']}" for m in s["malicious"])
        check.notify(check.notify_url(cfg), f"mvm fetch {eco}: malicious dependency",
                     f"{root.name}: {names}; fetch refused")
        say(f"{eco}: refusing to fetch: the lockfile pins a known malicious package ({names})")
        return core.EXIT_MALICIOUS
    return 0


def post_check(root: Path, tree: Path, eco: str, cfg: dict) -> str:
    """After a fetch whose command changed the lockfile, before its caches are committed."""
    names = set(check.LOCKFILES[eco])
    if not any(Path(rel).name in names for rel in changed_manifests(root, tree, ECOS[eco])):
        return ""
    s = check.scan_tree(tree, eco, cfg, root)
    say(f"check {eco}: new lockfile: {check.summary_line(s).removeprefix('check: ')}")
    if not s["malicious"]:
        return ""
    return "the new lockfile pins a known malicious package (" + ", ".join(
        f"{m['package']}@{m['version']}" for m in s["malicious"]) + ")"


def cmd_check(args: list[str]) -> int:
    """osv-scanner on lockfiles: this project, or with --all every project mvm knows."""
    if args not in ([], ["--all"]):
        die("usage: mvm check [--all]")
    cfg = load_config()
    roots = check.known_projects() if args else [Path.cwd().resolve()]
    if not roots:
        say("no projects known yet (mvm fetch or mvm check in a project first)")
        return 0
    worst, trips = 0, []
    for root in roots:
        for eco in detect_ecos(root):
            try:
                s = check.scan_project(root, eco, cfg)
            except MvmError as e:
                say(f"{root}: {eco}: {e}")
                trips.append(f"{root.name} {eco}: check failed")
                worst = max(worst, 1)
                continue
            check.record(root, eco, s)
            print(f"{root}  {eco}: {check.summary_line(s)}")
            if s["malicious"]:
                trips.append(f"{root.name} {eco}: malicious " + ", ".join(
                    f"{m['package']}@{m['version']}" for m in s["malicious"]))
                worst = core.EXIT_MALICIOUS
    if trips:
        check.notify(check.notify_url(cfg), "mvm check: " + ("malicious dependency" if worst == core.EXIT_MALICIOUS
                                                            else "check failed"), "\n".join(trips))
    return worst


def report_learned(eco: str, result: dict) -> None:
    """After a --learn fetch: hosts the proxy let through only because of learn mode."""
    extra = result.get("outside_allowlist", [])
    refused = sorted(result.get("denied", {}))
    if refused:
        say(f"{eco}: refused even in learn mode (Smokescreen IP rules, cannot be allowed): {', '.join(refused)}")
    sni = result.get("observer", {}).get("outside_allowlist", [])
    if sni:
        say(f"{eco}: TLS names (SNI) outside the allowlist: {', '.join(sni)}")
    if not extra:
        say(f"{eco}: no hosts outside the allowlist")
        return
    hosts = ", ".join(f'"{h}"' for h in extra)
    say(f"{eco}: hosts outside the allowlist: {', '.join(extra)}")
    say(f"to allow them, add to {core.CONFIG_PATH}:  [allow]  {eco} = [{hosts}]")


def cmd_build(args: list[str]) -> int:
    opts, cmd = parse_opts(args, allow_image=False)
    root = Path.cwd().resolve()
    pos = opts["positional"]
    if len(pos) > 1 or (pos and pos[0] not in ECOS):
        die(f"usage: mvm build [{'|'.join(ECOS)}] [-w DIR] [--it] -- CMD")
    if pos:
        name = pos[0]
    else:
        found = detect_ecos(root)
        if len(found) != 1:
            die(f"found {', '.join(found) or 'no'} ecosystem(s) here; name one: mvm build {'|'.join(ECOS)} -- CMD")
        name = found[0]
    eco = ECOS[name]
    cfg = load_config()
    if name == "node":
        (root / "node_modules").mkdir(exist_ok=True)   # mount point for the per-project cache
    plan = Plan(kind="build", eco=name, image=image_for(cfg, eco),
                memory=memory_for(cfg, name, eco.memory), cmd=cmd, src=root,
                caches=eco_caches(eco, "build", root), env={**eco.env, **eco.build_env},
                writable=check_writable(root, opts["writable"]),
                masks=find_masks(root, cfg.get("mask", DEFAULT_MASK)),
                interactive=opts["interactive"], project=root)
    return execute(plan)


def cmd_run(args: list[str]) -> int:
    opts, cmd = parse_opts(args, allow_image=True)
    if not opts["image"] or opts["positional"]:
        die("usage: mvm run -i IMAGE [-u USER] [-w DIR] [--it] -- CMD")
    root = Path.cwd().resolve()
    cfg = load_config()
    plan = Plan(kind="run", eco=None, image=pinned(opts["image"]),
                memory=memory_for(cfg, "run", "2g"), cmd=cmd, src=root,
                writable=check_writable(root, opts["writable"]),
                masks=find_masks(root, cfg.get("mask", DEFAULT_MASK)),
                interactive=opts["interactive"], project=root, user=opts["user"])
    return execute(plan)


def image_id(ref: str) -> str:
    r = subprocess.run(["podman", "image", "inspect", "--format", "{{.Id}}", ref], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def cmd_pull(args: list[str]) -> int:
    """Pull an image through the egress and pin it (a tag) or check it (a digest)."""
    if len(args) != 1 or args[0].startswith("-"):
        die("usage: mvm pull IMAGE   (registry/repo:tag or registry/repo@sha256:...)")
    ref = args[0]
    if "/" not in ref.split("@")[0].split(":")[0] or "." not in ref.split("/")[0]:
        die(f"give the full name, registry included (e.g. docker.io/library/{ref})")
    new = resolve_digest(ref, pull=True)
    if "@" not in ref:
        pins = read_json(pins_path(), {})
        old = pins.get(ref, {}).get("ref")
        if old != new:
            pins[ref] = {"ref": new, "pinned_at": now_iso(), **({"previous": old} if old else {})}
            write_json_atomic(pins_path(), pins)
    say(f"pulled {ref} -> {new}")
    return 0


def cmd_update(args: list[str]) -> int:
    if args:
        die("update takes no arguments")
    pins = read_json(pins_path(), {})
    if not pins:
        say("nothing pinned yet")
        return 0
    failed = 0
    for tag in sorted(pins):
        old = pins[tag]["ref"]
        if tag.startswith("localhost/"):
            print(f"{tag}: local build, not pulled")
            continue
        try:
            new = resolve_digest(tag, pull=True)
        except MvmError as e:
            say(str(e))
            failed += 1
            continue
        if new != old:
            # Pins made by plain podman pull name the multi-platform index; the same image
            # re-pinned by its platform manifest is not a change.
            same = image_id(new) == image_id(old) != ""
            pins[tag] = {"ref": new, "pinned_at": now_iso(), "previous": old}
            print(f"{tag}: {'unchanged (re-pinned by platform digest)' if same else ''}"
                  f"{'' if same else old.split('@')[1][:19] + ' -> ' + new.split('@')[1][:19]}")
        else:
            print(f"{tag}: unchanged")
        write_json_atomic(pins_path(), pins)
    return 1 if failed else 0


def human(n: float) -> str:
    for unit in ("B", "K", "M", "G"):
        if n < 1024 or unit == "G":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return str(n)


def cmd_status(args: list[str]) -> int:
    if args:
        die("status takes no arguments")
    cfg_state = str(core.CONFIG_PATH) if core.CONFIG_PATH.exists() else f"{core.CONFIG_PATH} (absent, defaults)"
    print(f"config   {cfg_state}")
    sb = egress.smokescreen_bin()
    if sb.is_file():
        print(f"egress   fetch only, through the allowlist proxy ({sb})")
    else:
        print(f"egress   MISSING proxy {sb}: fetch refuses to run (make smokescreen)")
    cfg = load_config()
    if not observer.enabled(cfg):
        print("observer off")
    elif observer.image_present():
        print(f"observer on: TLS ClientHello per connection (SNI, JA4, bytes) for every fetch ({observer.OBSERVER_IMAGE})")
    else:
        print(f"observer on but MISSING image {observer.OBSERVER_IMAGE}: fetch refuses to run (make observer)")
    for name in ECOS:
        print(f"  allow {name:<5} {', '.join(egress.allowlist(cfg, name))}")
    why = pull.ready()
    print(f"pull     {'MISSING: ' + why if why else 'images through the L7 policy proxy and the egress proxy (' + pull.SKOPEO_IMAGE + ')'}")
    print(f"  allow pull  {', '.join(egress.allowlist(cfg, 'pull'))}")
    print(f"image build  RUN steps in krun, egress through the proxy: {', '.join(egress.allowlist(cfg, 'image-build'))}")
    print(f"check    {'before every fetch' if check.before_fetch(cfg) else 'OFF before fetch'}"
          f" (osv-scanner {check.OSV_IMAGE.rsplit(':', 1)[1]}, MAL- advisories block)")
    print(f"notify   {'ntfy on trips' if check.notify_url(cfg) else 'off'}")
    print("\nchecks")
    recs = [read_json(x, {}) for x in sorted(check.checks_dir().glob("*.json"))]
    for r in sorted(recs, key=lambda r: r.get("checked_at", "")):
        for eco, c in sorted(r.get("ecos", {}).items()):
            mal, vul = len(c.get("malicious", [])), len(c.get("vulnerable", []))
            state = "skipped" if c.get("skipped") else f"{'MALICIOUS ' + str(mal) if mal else 'ok'}, {vul} vulnerable"
            print(f"  {c.get('checked_at', '-'):<20} {eco:<4} {state:<24} {r.get('project', '?')}")
    if not recs:
        print("  (none yet: mvm check)")
    print("\ntrips (last 24h)")
    cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 86400))
    trips = [r for r in (read_json(x, {}) for x in sorted((core.STATE_ROOT / "runs").glob("*.json")))
             if r.get("result") in check.TRIP_RESULTS and r.get("started_at", "") >= cutoff]
    for r in trips:
        print(f"  {r.get('started_at')}  {r.get('kind')} {r.get('eco') or '-'}  {r['result']}  exit {r.get('exit')}  {r.get('cwd')}")
    if not trips:
        print("  (none)")
    print("\nimages")
    pins = read_json(pins_path(), {})
    for tag in sorted(pins):
        print(f"  {tag:<42} {pins[tag]['ref'].split('@')[1][:19]}  pinned {pins[tag]['pinned_at']}")
    if not pins:
        print("  (none pinned yet)")
    print("\ncaches")
    imgs = sorted(core.CACHE_ROOT.glob("*.img"))
    for img in imgs:
        st = img.stat()
        meta = read_json(cache_meta(img.stem), {})
        extra = f"  {meta['project']}" if "project" in meta else ""
        print(f"  {img.stem:<28} {human(st.st_blocks * 512):>7} / {human(st.st_size):>6}  "
              f"gen {str(meta.get('generation', '?')):<4} {meta.get('committed_at', '-')}{extra}")
    if not imgs:
        print("  (none)")
    leftovers = sorted(core.CACHE_ROOT.glob("*.img.run-*"))
    if leftovers:
        print(f"  {len(leftovers)} leftover run copies (mvm cache gc removes them)")
    print("\nrecent runs")
    recs = [(p, r) for p in sorted((core.STATE_ROOT / "runs").glob("*.json"))
            if (r := read_json(p, {})).get("kind") != "check"][-10:]      # checks: see "checks" above
    for p, r in recs:
        cmd = " ".join(r.get("cmd", []))
        eg = r.get("egress") if isinstance(r.get("egress"), dict) else {}
        denied = eg.get("denied", {})
        flag = f" DENIED {','.join(sorted(denied))}" if denied else ""
        print(f"  {r.get('id', p.stem):<24} {r.get('kind', '?'):<5} {str(r.get('eco') or '-'):<4} "
              f"{str(r.get('result', 'running?')):<11} exit {str(r.get('exit', '-')):<4} {cmd[:50]}{flag}")
    if not recs:
        print("  (none)")
    return 0


def cmd_image(args: list[str]) -> int:
    usage = "usage: mvm image build -t localhost/NAME:TAG [-f Containerfile]"
    if not args or args[0] != "build":
        die(usage)
    tag, cf, rest = None, "Containerfile", args[1:]
    while rest:
        if rest[0] in ("-t", "-f") and len(rest) > 1:
            if rest[0] == "-t":
                tag = rest[1]
            else:
                cf = rest[1]
            rest = rest[2:]
        else:
            die(usage)
    if not tag:
        die(usage)
    cfg = load_config()
    rc, eg = imagebuild.build(tag, Path(cf).resolve(), cfg)
    hosts = allowable(eg, egress.allowlist(cfg, "image-build")) if rc == core.EXIT_EGRESS_DENIED else []
    if hosts:
        suggest_allow("image-build", cfg, hosts)
    return rc


def cmd_cache(args: list[str]) -> int:
    usage = "usage: mvm cache rm NAME | grow NAME SIZE | gc"
    if not args:
        die(usage)
    sub, rest = args[0], args[1:]
    core.CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    if sub == "rm" and len(rest) == 1:
        img = cache_img(rest[0])
        if not img.exists():
            die(f"no such cache: {rest[0]}")
        fd = try_exclusive(rest[0])
        if fd is None:
            die(f"cache {rest[0]} is in use")
        try:
            for p in [img, cache_meta(rest[0]), *run_copies(rest[0])]:
                p.unlink(missing_ok=True)
        finally:
            fd.close()
        say(f"removed {rest[0]}")
        return 0
    if sub == "grow" and len(rest) == 2:
        name, size = rest
        img = cache_img(name)
        if not img.exists():
            die(f"no such cache: {name}")
        fd = try_exclusive(name)
        if fd is None:
            die(f"cache {name} is in use")
        try:
            subprocess.run(["truncate", "-s", size, str(img)], check=True)
            r = subprocess.run([find_sbin("e2fsck"), "-f", "-p", str(img)])
            if r.returncode not in (0, 1):
                die(f"e2fsck exited with {r.returncode}")
            subprocess.run([find_sbin("resize2fs"), str(img)], check=True)
        finally:
            fd.close()
        return 0
    if sub == "gc" and not rest:
        for name in reap_orphans():
            say(f"killed orphaned container {name}")
        for copy in sorted(core.CACHE_ROOT.glob("*.img.run-*")):
            name = copy.name.split(".img.run-")[0]
            fd = try_exclusive(name)
            if fd is None:
                continue
            try:
                copy.unlink(missing_ok=True)
                say(f"removed leftover {copy.name}")
            finally:
                fd.close()
        for img in sorted(core.CACHE_ROOT.glob("nm-*.img")):
            proj = read_json(cache_meta(img.stem), {}).get("project")
            if proj and not Path(proj).is_dir():
                fd = try_exclusive(img.stem)
                if fd is None:
                    continue
                try:
                    img.unlink(missing_ok=True)
                    cache_meta(img.stem).unlink(missing_ok=True)
                    say(f"removed {img.stem} (project {proj} is gone)")
                finally:
                    fd.close()
        return 0
    die(usage)
    return 2


USAGE = """\
mvm - run dev tooling in throwaway Podman+krun microVMs

  mvm fetch [go|rust|node] [--learn] [-- CMD]
                                       download dependencies; with CMD, change them
                                       (go get, cargo add, npm install ...);
                                       --learn: allow but log every host, commit nothing
  mvm build [go|rust|node] [-w DIR] [--it] -- CMD
                                       build offline against the fetched caches
  mvm run -i IMAGE [-u USER] [-w DIR] [--it] -- CMD
                                       run any image offline
  mvm check [--all]                    osv-scanner on the lockfiles (here, or every
                                       known project); also runs before every fetch
  mvm status                           config, checks, trips, pinned images, caches, runs
  mvm pull IMAGE                       pull an image (through the egress) and pin it
  mvm update                           re-pull and re-pin images (through the egress)
  mvm image build -t localhost/NAME:TAG [-f FILE]
                                       build an image: RUN steps in krun microVMs, egress
                                       only through the proxy (OS mirrors), context = the
                                       Containerfile alone; tagged only after a clean run
  mvm cache rm NAME | grow NAME SIZE | gc

  -v       (first) verbose: per-run egress, observer and scanner details
  -w DIR   make ./DIR writable (the project is read-only otherwise)
  --it     interactive terminal

fetch downloads (check reaches only api.osv.dev; pull and update only registries), and
the way out is a per-run allowlist proxy (Smokescreen): no DNS, no direct connections. It sees only the dependency manifests
(go.mod, Cargo.toml, package.json and their lockfiles), never your sources, and
only changed manifests are copied back. npm install scripts are skipped by
default (run them offline: mvm build node -- npm rebuild).
build and run hide .git, .env* and key files (config: mask = [...]).
Cache writes are committed only when the command exits 0.

Examples:
  mvm fetch
  mvm fetch go -- go get golang.org/x/net@latest
  mvm fetch node -- npm install --ignore-scripts left-pad
  mvm build -w build -- go build -o build/app ./cmd/app
  mvm build rust -- cargo test
  mvm run -i docker.io/library/alpine:3.24 -- uname -a
"""


def _sigterm(*_):
    raise KeyboardInterrupt


def main(argv: list[str]) -> int:
    if argv and argv[0] in ("-v", "--verbose"):
        core.VERBOSE = True
        argv = argv[1:]
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE, end="")
        return 0
    signal.signal(signal.SIGTERM, _sigterm)
    core.ensure_state_dir()
    cmds = {"fetch": cmd_fetch, "build": cmd_build, "run": cmd_run, "status": cmd_status, "check": cmd_check,
            "update": cmd_update, "pull": cmd_pull, "image": cmd_image, "cache": cmd_cache}
    fn = cmds.get(argv[0])
    if fn is None:
        die(f"unknown command {argv[0]!r} (see mvm --help)")
    try:
        return fn(argv[1:])
    except KeyboardInterrupt:
        say("interrupted")
        return 130
    except (MvmError, subprocess.CalledProcessError) as e:
        hosts = allowable(getattr(e, "egress", {}), egress.allowlist(load_config(), "pull"))
        if hosts:                             # a held image pull
            say(str(e))
            suggest_allow("pull", load_config(), hosts)
            return getattr(e, "rc", 1)
        die(str(e), 1)
        return 1
