"""Command-line interface."""

from __future__ import annotations

import signal
import subprocess
import tempfile
from pathlib import Path

from . import core, egress
from .cache import cache_img, cache_meta, run_copies, try_exclusive
from .core import DEFAULT_MASK, MvmError, die, find_sbin, load_config, now_iso, pinned, pins_path, read_json, resolve_digest, say, write_json_atomic
from .ecos import ECOS, Eco, eco_caches
from .project import changed_manifests, check_writable, copy_back, detect_ecos, find_masks, manifest_tree
from .runtime import Plan, execute, reap_orphans


def parse_opts(args: list[str], allow_image: bool) -> tuple[dict, list[str]]:
    opts: dict = {"writable": [], "interactive": False, "image": None, "positional": []}
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
    for name in ecos:
        eco = ECOS[name]
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
                        project=root, learn=learn, allow=egress.allowlist(cfg, name))
            rc = execute(plan)
            if rc != 0:
                return rc
            if learn:
                report_learned(name, plan.allow)
                continue
            # Only dependency manifests ever flow back into the project.
            for rel in changed_manifests(root, tree, eco):
                copy_back(tree, root, rel)
                say(f"updated {rel}")
    if "node" in ecos:
        say("node: install scripts were skipped; run them offline: mvm build node -- npm rebuild")
    return 0


def report_learned(eco: str, allowed: list[str]) -> None:
    """After a --learn fetch: which hosts were used beyond the allowlist."""
    from .runtime import latest_record
    rec = latest_record()
    eg = rec.get("egress", {})
    seen = sorted({*eg.get("allowed", {}), *eg.get("denied", {})})
    extra = [h for h in eg.get("outside_allowlist", []) if h not in allowed]
    if not extra:
        say(f"{eco}: every host used is already allowed ({', '.join(seen) or 'none'})")
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
        die("usage: mvm run -i IMAGE [-w DIR] [--it] -- CMD")
    root = Path.cwd().resolve()
    cfg = load_config()
    plan = Plan(kind="run", eco=None, image=pinned(opts["image"]),
                memory=memory_for(cfg, "run", "2g"), cmd=cmd, src=root,
                writable=check_writable(root, opts["writable"]),
                masks=find_masks(root, cfg.get("mask", DEFAULT_MASK)),
                interactive=opts["interactive"], project=root)
    return execute(plan)


def cmd_update(args: list[str]) -> int:
    if args:
        die("update takes no arguments")
    pins = read_json(pins_path(), {})
    if not pins:
        say("nothing pinned yet")
        return 0
    for tag in sorted(pins):
        old = pins[tag]["ref"]
        new = resolve_digest(tag, pull=True)
        if new != old:
            pins[tag] = {"ref": new, "pinned_at": now_iso(), "previous": old}
            print(f"{tag}: {old.split('@')[1][:19]} -> {new.split('@')[1][:19]}")
        else:
            print(f"{tag}: unchanged")
    write_json_atomic(pins_path(), pins)
    return 0


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
    print("observer off")
    cfg = load_config()
    for name in ECOS:
        print(f"  allow {name:<5} {', '.join(egress.allowlist(cfg, name))}")
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
    recs = sorted((core.STATE_ROOT / "runs").glob("*.json"))[-10:]
    for p in recs:
        r = read_json(p, {})
        cmd = " ".join(r.get("cmd", []))
        eg = r.get("egress") if isinstance(r.get("egress"), dict) else {}
        denied = eg.get("denied", {})
        flag = f" DENIED {','.join(sorted(denied))}" if denied else ""
        print(f"  {r.get('id', p.stem):<24} {r.get('kind', '?'):<5} {str(r.get('eco') or '-'):<4} "
              f"{str(r.get('result', 'running?')):<11} exit {str(r.get('exit', '-')):<4} {cmd[:50]}{flag}")
    if not recs:
        print("  (none)")
    return 0


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
  mvm run -i IMAGE [-w DIR] [--it] -- CMD
                                       run any image offline
  mvm status                           config, pinned images, caches, recent runs
  mvm update                           re-pull and re-pin images
  mvm cache rm NAME | grow NAME SIZE | gc

  -w DIR   make ./DIR writable (the project is read-only otherwise)
  --it     interactive terminal

fetch is the only command with network, and its only way out is a per-run
allowlist proxy (Smokescreen): no DNS, no direct connections. It sees only the dependency manifests
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
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE, end="")
        return 0
    signal.signal(signal.SIGTERM, _sigterm)
    cmds = {"fetch": cmd_fetch, "build": cmd_build, "run": cmd_run, "status": cmd_status,
            "update": cmd_update, "cache": cmd_cache}
    fn = cmds.get(argv[0])
    if fn is None:
        die(f"unknown command {argv[0]!r} (see mvm --help)")
    try:
        return fn(argv[1:])
    except KeyboardInterrupt:
        say("interrupted")
        return 130
    except (MvmError, subprocess.CalledProcessError) as e:
        die(str(e), 1)
        return 1
