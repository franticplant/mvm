# mvm

[![CI](https://github.com/franticplant/mvm/actions/workflows/ci.yml/badge.svg)](https://github.com/franticplant/mvm/actions/workflows/ci.yml)

Run dev tooling (`go`, `cargo`, `npm`, or any OCI image) in throwaway KVM microVMs via **Podman + `crun-krun`**. Offline and read-only by default; dependencies are fetched in a separate, manifest-only step; caches are committed only when a command succeeds.

```bash
mvm fetch                                        # download deps (networked, allowlisted, manifests only)
mvm build -w build -- go build -o build/app ./cmd/app   # offline from here on
mvm build rust -- cargo test
mvm run -i docker.io/library/alpine:3.24 -- uname -a
mvm run -u 1000:1000 -i IMAGE -- CMD             # as a non-root user (e.g. Chromium's sandbox)
mvm run -p 8080:80 -i docker.io/library/nginx:alpine -- nginx -g 'daemon off;'   # dev server on 127.0.0.1:8080, no egress
mvm pull ghcr.io/astral-sh/ruff:0.8.4-alpine     # confined image pull, pinned by digest
mvm image build -t localhost/jq:1 -f Containerfile   # RUN steps in krun, OS mirrors only
```

The networked steps are `fetch`, `check`, `pull`/`update` and `image build`, each confined to its own allowlist through a per-run proxy and TLS observer; `build` and `run` have no network at all.

## The model

| Step | Network | Sees | Writes |
|---|---|---|---|
| `mvm fetch [go\|rust\|node] [-- CMD]` | yes | **only** `go.mod`/`go.sum`, `Cargo.toml`/`Cargo.lock`, `package.json`/`package-lock.json` (Cargo targets as empty stubs) | dependency caches; changed manifests are copied back |
| `mvm build [go\|rust\|node] -- CMD` | no | the project, read-only, with `.git`, `.env*` and key files hidden | build caches, `node_modules`, and `-w DIR` |
| `mvm run -i IMAGE [-u USER] [-p HOST:CONT] -- CMD` | no (`-p`: inbound on host 127.0.0.1 only) | same as build | `-w DIR` only |
| `mvm check [--all]` | only api.osv.dev | **only** the lockfiles | nothing (a check record) |
| `mvm pull IMAGE`, `mvm update` | only image registries | nothing | the image, loaded offline after a clean run |
| `mvm image build -t localhost/NAME:TAG [-f FILE]` | only OS package mirrors | **only** the Containerfile | the `localhost/` tag, after a clean build |

### Dependencies: fetch and build

- **No third-party code runs with network.** `go mod download` and `cargo fetch` run none; npm runs with `--ignore-scripts` (run them offline: `mvm build node -- npm rebuild`); Go may not download a newer toolchain (`GOTOOLCHAIN=local`).
- **Changing dependencies** is a fetch with a command: `mvm fetch go -- go get golang.org/x/net@latest`, `mvm fetch rust -- cargo generate-lockfile`, `mvm fetch node -- npm install --ignore-scripts left-pad`. Only manifest/lockfile changes flow back, and mvm lists them.
- **Commit-on-clean.** Every writable cache is a reflink copy for the duration of the run and replaces the cache atomically only on exit 0. A failure, Ctrl-C, crash or `kill -9` leaves the cache exactly as it was.

### Inbound-only ports: `mvm run -p`

- `-p HOST:CONT` (repeatable; `127.0.0.1:HOST:CONT` is accepted, any other bind address refused) serves a dev server (nginx, vite, `python -m http.server`) on host `127.0.0.1:HOST`, never the LAN.
- The microVM runs in a `--network=none` pod: its namespace has only `lo`, so it cannot open a connection to anything, not the internet, DNS, the LAN, the tailnet, or a host service on any of the host's addresses. No pasta, no nftables, no capabilities.
- Inbound connections cross through Unix sockets: mvm listens on `127.0.0.1:HOST` and splices each connection to a socket that a read-only, no-capability sidecar in the same pod (`mvm/portbridge.py`, stdlib Python, in the pinned observer image: `make observer`) forwards to `127.0.0.1:CONT`. Each side only ever dials its one fixed target, so the workload can answer but never initiate.
- Proven with a real krun test: HTTP 200 inbound, while connects to 1.1.1.1:443, DNS and a host listener on `0.0.0.0` (via every host address) all fail and the pod lists only `lo`. Only for `run`; the server must listen on `0.0.0.0` or `127.0.0.1` inside the guest.

### Egress: allowlist proxy, held on denial

- A fetch VM's network is pasta bound to loopback with one forwarded port, where a per-run [Smokescreen](https://github.com/stripe/smokescreen) (Stripe's egress proxy) allows only the ecosystem's registries.
- No DNS, no direct connections, no UDP, ICMP or IPv6 (each proven with real krun runs).
- Every connection is logged with bytes in/out; denials are printed and kept in the run record.
- **A denial holds the run.** If a fetch exits 0 but tried a denied host, nothing is committed or copied back and mvm exits 3; if the proxy died or its log is unreadable, exit 4.
- **Learning hosts:** `mvm fetch --learn` lets everything through the proxy but logs it, commits nothing, and prints the hosts outside the allowlist with the exact `[allow]` line to add.

### TLS observer (on by default)

- mvm's own passive TLS sensor (`mvm/tlsobs.py`, stdlib Python, in the official Python image pinned by digest) runs as a sidecar in the proxy pod. For every outbound connection it reassembles the start of the client's stream and records whether it is a TLS ClientHello, its SNI and [JA4](https://github.com/FoxIO-LLC/ja4) fingerprint, and the bytes each way.
- **Holds the run** (exit 3): a TLS name outside the allowlist, no SNI, a connection that is not TLS (e.g. plaintext HTTP through CONNECT) or conflicting retransmissions hold the run like a denial (exit 3): the proxy only sees the CONNECT host, so this catches SNI-level domain fronting.
- **Limit:** Fronting by the HTTP `Host` header inside the encrypted connection (allowed SNI, another site on the same CDN) is invisible to any passive observer; it depends on the CDN refusing mismatches.
- **Fails closed:** a missing image refuses the fetch; a dead sensor, unreadable flows, kernel packet drops, or a proxy connection with no observed flow means nothing is committed (exit 5).
- It is written clean-room from the RFCs and FoxIO's BSD-3 JA4 spec; real tests check it against nDPI 5.0 on the same packets.
- `[observer] enabled = false` turns it off; `mvm status` prints `observer off` then.
- **Telemetry.** Observe-only, for encrypted traffic analysis (nothing is enforced on these): each flow also records kernel timestamps (`ts_start`, `duration_ms`), packets each way, `data_ratio` (bytes out / total), the first ALPN, the offered TLS version, and SPLT, the first 20 data packets as `[±payload bytes, ms since the previous one]` (+ out, − in). They go into the run record (the last 200 runs; `~/.local/state/mvm` is 0700); `[observer] log = "/abs/path/flows.jsonl"` (off by default) also appends every flow with its `run_id`, `kind` and `eco`, for a long-term corpus.

### Dependency checks

- **Before every fetch.** [osv-scanner](https://github.com/google/osv-scanner) checks the lockfiles in a microVM that sees only them and reaches only `api.osv.dev` through the same proxy.
- A package with an OSV `MAL-` advisory ([OpenSSF malicious packages](https://github.com/ossf/malicious-packages)) refuses the fetch (exit 6); known vulnerabilities are printed and recorded, not blocking.
- If a fetch command changed the lockfile (`npm install x`), the new lockfile is checked before anything is committed or copied back.
- A lockfile that lists no packages (fresh `npm init`) passes; any other check that cannot complete refuses the fetch (`[check] before_fetch = false` turns it off).
- Call analysis and manifest resolution are off (`--no-call-analysis=all --no-resolve`): nothing runs and no other host is needed.
- **Daily check and notifications.** `mvm check --all` checks every project mvm has fetched or checked; `make timer` installs it as a daily systemd user timer. With `[notify] ntfy = "https://ntfy.sh/<topic>"`, trips (malicious packages, held runs, failed proxy/observer, failed checks) are posted there. `mvm status` shows the last check per project and the trips of the last 24 hours.

### Images

- **Pinned images.** The first use of an image tag pins its digest; `mvm update` re-pulls and shows what changed. Every container mvm starts uses `--pull=never`: a pinned image that is missing locally fails the run (re-pin with `mvm pull TAG`); it is never fetched outside the egress.

#### Confined pulls

- `mvm pull`, `mvm update` and an image's first use pull through the same proxy and observer as fetch: a static skopeo (`make skopeo`, pure Go, in a `FROM scratch` image) is the microVM's only process and copies the image into a `dir:` layout under `~/.cache/mvm/pulls`.
- Only after a clean run does the host load it offline (`podman pull dir:...`, which re-checks every blob digest) and pin it by the digest of its platform manifest (`dir:` keeps the registry's manifest bytes; an OCI archive would convert Docker manifests and change the digest).
- The download is removed whatever happens. A registry outside the allowlist holds the pull (exit 3) with the `[allow] pull = [...]` line to add.
- The images `make smokescreen`/`observer`/`skopeo` need are the bootstrap and come from plain `podman pull`.

#### Request-level policy for pulls (L7)

- A pull's connections first go to `l7proxy` (`egress/l7proxy`, stdlib Go, `make l7proxy`) in the same proxy pod, chained in front of Smokescreen, so the host allowlist, IP rules, byte counts and the TLS observer all still apply.
- l7proxy terminates TLS with a leaf from an ephemeral ECDSA P-256 CA made in memory for that run. The private key is never written; the CA is name-constrained to the pull allowlist, and the guest trusts only it, so nothing gets around the proxy.
- Upstream it uses Go's crypto/tls against the host CA bundle.
- For each request it checks that:
  - the method is GET or HEAD;
  - the SNI, the `Host` header and the CONNECT host are the same;
  - the path is `/v2/` or `/v2/<this repository>/...` on the registry;
  - a token is for pulling this repository only (`auth.docker.io/token`, `ghcr.io/token`);
  - a blob CDN URL is exactly the host and path a registry redirect named.
- Escaped or dot-segment paths are refused. A refusal holds the pull (exit 3).
- Other registries' token endpoints are hand rules, e.g. `[[l7.pull]] host = "quay.io"`, `exact = ["/v2/auth"]`, `scope = "repository:{repo}:pull"`.
- Fetch stays pass-through (Smokescreen + observer), so the client's own JA4 and SPLT are what the observer sees.

#### Confined image builds

- `mvm image build -t localhost/NAME:TAG -f Containerfile` runs `podman --runtime krun build`, so every RUN step (apk/apt and their install scripts) runs in a KVM microVM, on the same confined network as fetch: the per-run proxy (TCP 443 only) and the observer, allowing only OS package mirrors (`dl-cdn.alpinelinux.org`, `deb.debian.org`, `security.debian.org`; more with `[allow] image-build = [...]`; sources on `http://` fail, use the mirrors' https).
- The build context is an empty directory holding only the Containerfile, so project files and secrets are never in it (COPY of local files fails).
- Missing base images come through the confined pull first, then `--pull=never --no-cache`. Base images are used by their pinned digest (FROM is rewritten in the build's copy).
- It builds under a temporary tag and gets yours only after a clean run; a held or failed build deletes it (exit 3/4/5).
- Refused up front: `ADD` except heredocs (the context is empty, so ADD could only fetch a URL or git repository, which podman does on the host), `RUN --network=...` and `--security=...`, a `# escape=` other than backslash, and `FROM` with build variables.
- Proxy build args do not end up in the image's environment.

## State

| Path | What |
|---|---|
| `~/.cache/mvm/<name>.img` | sparse ext4 cache images, loop-mounted inside the guest (`go-mod`, `go-build`, `cargo-reg`, `cargo-git`, `cargo-target`, `npm`, `nm-<project>-<hash>`) |
| `~/.cache/mvm/<name>.meta.json` | generation number, last commit, owning project (for `node_modules`) |
| `~/.cache/mvm/<name>.lock` | `flock`: shared for read-only users, exclusive for the writer |
| `~/.local/state/mvm/pins.json` | image tag → pinned digest |
| `~/.local/state/mvm/checks/<project>.json` | last dependency check per project and ecosystem |
| `~/.local/state/mvm/runs/<id>.json` | one record per run: command, image, caches, exit, committed or discarded (last 200 kept) |
| `~/.config/mvm/config.toml` | optional host config |

`mvm status` shows all of it. `mvm cache gc` removes leftover run copies, kills microVMs orphaned by a killed `mvm`, and drops `node_modules` caches of deleted projects. `mvm cache grow NAME SIZE` and `mvm cache rm NAME` refuse while a cache is in use.

## Config (optional)

```toml
# ~/.config/mvm/config.toml
mask = [".git", ".env", ".env.*", "*.pem", "*.key"]   # hidden in build/run (default list is longer)

[images]               # override the default image per ecosystem (pinned on first use)
go = "docker.io/library/golang:1.27-alpine"

[memory]
rust = "6g"
run = "1g"

[allow]                # extra hosts for fetch, on top of the built-in registries
go = ["github.com", "codeload.github.com"]
pull = ["quay.io", "cdn01.quay.io"]   # image registries beyond Docker Hub and GHCR
image-build = ["archive.archlinux.org"] # OS mirrors for mvm image build (HTTPS only)

[[l7.pull]]            # request rules for pulls from other registries ({repo} = the image's repository)
host = "quay.io"
exact = ["/v2/auth"]
scope = "repository:{repo}:pull"

[observer]             # TLS observer for fetch (needs `make observer`); on by default
enabled = true
# log = "/home/me/mvm-flows.jsonl"   # opt-in: append every flow (ETA features) with run metadata

[check]                # osv-scanner before every fetch; on by default
before_fetch = true

[notify]               # optional: post trips to ntfy
ntfy = "https://ntfy.sh/<your-topic>"
```

Built-in allowlists: go `proxy.golang.org`, `sum.golang.org`, `storage.googleapis.com`; rust `index.crates.io`, `static.crates.io`; node `registry.npmjs.org`; pull: Docker Hub (`auth.docker.io`, `registry-1.docker.io`, blobs from `production.cloudfront.docker.com`, `production.cloudflare.docker.com` and Docker's one R2 bucket host) and GHCR (`ghcr.io`, `pkg-containers.githubusercontent.com`).

## For AI coding agents

```markdown
- Never run node, npm, go, cargo or similar dev tooling directly on the host; use `mvm` (`man mvm`):
  - Download or change dependencies: `mvm fetch`, `mvm fetch go -- go get x@v1`
  - Build/test offline: `mvm build -w build -- go build -o build/app ./...`
  - Anything else: `mvm run -i IMAGE -- CMD` (as a non-root user: `mvm run -u 1000:1000 -i IMAGE -- CMD`)
  - A local dev server, inbound only: `mvm run -p 8080:80 -i IMAGE -- CMD` (host 127.0.0.1:8080, no egress)
  - Images: `mvm pull docker.io/library/alpine:3.24`; build one with `mvm image build -t localhost/NAME:TAG -f Containerfile`
- Network exists only in `mvm fetch`, `mvm pull` and `mvm image build`, each confined to an allowlist. Do not work around it.
```

## Requirements and install

Linux with `/dev/kvm`, `podman` + `crun-krun`, `e2fsprogs`, Python 3.11+ (standard library only). Caches should live on btrfs (or another reflink-capable filesystem); elsewhere copies still work but are full copies.

```bash
sudo dnf install podman crun-krun e2fsprogs
make setup          # all of: install, smokescreen, observer, skopeo, l7proxy (what a fresh machine needs)
make install        # ~/.local/bin/mvm, ~/.local/lib/mvm (package), man page, completions
make smokescreen    # build the pinned egress proxy offline with mvm, and its port-filter image; fetch refuses without them
make l7proxy        # build the L7 pull policy proxy offline with mvm (stdlib Go); pulls refuse without it
make test-go        # its Go unit tests, offline (plain podman: loopback is refused inside krun)
make skopeo         # build skopeo offline with mvm (static, FROM scratch); image pulls refuse without it
make observer       # pull the observer's Python image (pinned by digest); on by default, fetch refuses without it
make ndpi-oracle    # optional, tests only: nDPI 5.0 (last all-LGPLv3 release) to check the observer against
make timer          # optional: daily `mvm check --all` as a systemd user timer
make test           # unit tests, no KVM needed
make test-real      # + real microVM tests, including the egress escape test
```

## Caveats

- podman's `--tmpfs` is ignored under krun; mvm hides directories with an empty read-only bind instead.
- Ports: Smokescreen's ACL is host-only, so the proxy runs in a pod whose network namespace has an nftables egress filter (loaded by a one-shot `NET_ADMIN` container; Smokescreen itself has no capabilities): only TCP 443 out, plus DNS to the pod's resolver. An allowed host on any other port is refused, recorded as denied, and holds the run. Host loopback, link-local, private and CGNAT ranges and IP literals are refused by Smokescreen (checked with real CONNECT probes).
- Observer: it captures only the pod's outbound leg (proxy to registry), which carries the VM's own ClientHello relayed through CONNECT; denied requests never reach the network, so for those the proxy log is the record. It reads frames through a 64 MiB `TPACKET_V3` ring with a BPF program that keeps whole outgoing frames but only the headers of incoming ones; with a plain socket the kernel's 208 KiB `rmem_max` dropped packets on a 38 MiB download (0 drops with the ring on 56 MiB). The firewall one-shot sets the pod's MTU to 1500 (pasta's 65520 made the earlier nDPI sensor drop ClientHello frames). Earlier sensors: Cisco mercury (rejected: needs 32 MiB locked memory, above the 8 MiB rootless default), then nDPI, dropped because from 6.0 its TLS dissector is ntop dual-licensed (free only for not-for-profit use).
- Writable caches are single-writer: concurrent builds of the same ecosystem wait on the lock.
- A failing build (non-zero exit, including failing tests) discards that run's build-cache writes; the next run rebuilds.
- Rust path dependencies outside the project directory and npm workspaces with nested `node_modules` are not handled by `fetch` yet.

## License

MIT — see [LICENSE](LICENSE).
