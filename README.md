# mvm

Run dev tooling (`go`, `cargo`, `npm`, or any OCI image) in throwaway KVM microVMs via **Podman + `crun-krun`**. Offline and read-only by default; dependencies are fetched in a separate, manifest-only step; caches are committed only when a command succeeds.

```bash
mvm fetch                                        # download deps (the only networked step)
mvm build -w build -- go build -o build/app ./cmd/app
mvm build rust -- cargo test
mvm run -i docker.io/library/alpine:3.24 -- uname -a
```

## The model

| Step | Network | Sees | Writes |
|---|---|---|---|
| `mvm fetch [go\|rust\|node] [-- CMD]` | yes | **only** `go.mod`/`go.sum`, `Cargo.toml`/`Cargo.lock`, `package.json`/`package-lock.json` (Cargo targets as empty stubs) | dependency caches; changed manifests are copied back |
| `mvm build [go\|rust\|node] -- CMD` | no | the project, read-only, with `.git`, `.env*` and key files hidden | build caches, `node_modules`, and `-w DIR` |
| `mvm run -i IMAGE -- CMD` | no | same as build | `-w DIR` only |
| `mvm check [--all]` | only api.osv.dev | **only** the lockfiles | nothing (a check record) |
| `mvm pull IMAGE`, `mvm update` | only image registries | nothing | the image, loaded offline after a clean run |

- **No third-party code runs with network.** `go mod download` and `cargo fetch` run none; npm runs with `--ignore-scripts` (run them offline: `mvm build node -- npm rebuild`); Go may not download a newer toolchain (`GOTOOLCHAIN=local`).
- **Changing dependencies** is a fetch with a command: `mvm fetch go -- go get golang.org/x/net@latest`, `mvm fetch rust -- cargo generate-lockfile`, `mvm fetch node -- npm install --ignore-scripts left-pad`. Only manifest/lockfile changes flow back, and mvm lists them.
- **Commit-on-clean.** Every writable cache is a reflink copy for the duration of the run and replaces the cache atomically only on exit 0. A failure, Ctrl-C, crash or `kill -9` leaves the cache exactly as it was.
- **Pinned images.** The first use of an image tag pins its digest; `mvm update` re-pulls and shows what changed. Every container mvm starts uses `--pull=never`: a pinned image that is missing locally fails the run (re-pin with `mvm pull TAG`); it is never fetched outside the egress.
- **Confined image pulls.** `mvm pull`, `mvm update` and an image's first use pull through the same proxy and observer as fetch: a static skopeo (`make skopeo`, pure Go, in a `FROM scratch` image) is the microVM's only process and copies the image into a `dir:` layout under `~/.cache/mvm/pulls`. Only after a clean run does the host load it offline (`podman pull dir:...`, which re-checks every blob digest) and pin it by the digest of its platform manifest (`dir:` keeps the registry's manifest bytes; an OCI archive would convert Docker manifests and change the digest). The download is removed whatever happens. A registry outside the allowlist holds the pull (exit 3) with the `[allow] pull = [...]` line to add. The images `make smokescreen`/`observer`/`skopeo` need are the bootstrap and come from plain `podman pull`.
- **Egress only through an allowlist proxy.** A fetch VM's network is pasta bound to loopback with one forwarded port, where a per-run [Smokescreen](https://github.com/stripe/smokescreen) (Stripe's egress proxy) allows only the ecosystem's registries. No DNS, no direct connections, no UDP, ICMP or IPv6 (each proven with real krun runs). Every connection is logged with bytes in/out; denials are printed and kept in the run record.
- **A denial holds the run.** If a fetch exits 0 but tried a denied host, nothing is committed or copied back and mvm exits 3; if the proxy died or its log is unreadable, exit 4.
- **Observer (on by default).** mvm's own passive TLS sensor (`mvm/tlsobs.py`, stdlib Python, in the official Python image pinned by digest) runs as a sidecar in the proxy pod. For every outbound connection it reassembles the start of the client's stream and records whether it is a TLS ClientHello, its SNI and [JA4](https://github.com/FoxIO-LLC/ja4) fingerprint, and the bytes each way. A TLS name outside the allowlist, no SNI, a connection that is not TLS (e.g. plaintext HTTP through CONNECT) or conflicting retransmissions hold the run like a denial (exit 3): the proxy only sees the CONNECT host, so this catches SNI-level domain fronting. Fronting by the HTTP `Host` header inside the encrypted connection (allowed SNI, another site on the same CDN) is invisible to any passive observer; it depends on the CDN refusing mismatches. It fails closed: a missing image refuses the fetch; a dead sensor, unreadable flows, kernel packet drops, or a proxy connection with no observed flow means nothing is committed (exit 5). It is written clean-room from the RFCs and FoxIO's BSD-3 JA4 spec; real tests check it against nDPI 5.0 on the same packets. `[observer] enabled = false` turns it off; `mvm status` prints `observer off` then.
- **Dependency check before every fetch.** [osv-scanner](https://github.com/google/osv-scanner) checks the lockfiles in a microVM that sees only them and reaches only `api.osv.dev` through the same proxy. A package with an OSV `MAL-` advisory ([OpenSSF malicious packages](https://github.com/ossf/malicious-packages)) refuses the fetch (exit 6); known vulnerabilities are printed and recorded, not blocking. If a fetch command changed the lockfile (`npm install x`), the new lockfile is checked before anything is committed or copied back. A lockfile that lists no packages (fresh `npm init`) passes; any other check that cannot complete refuses the fetch (`[check] before_fetch = false` turns it off). Call analysis and manifest resolution are off (`--no-call-analysis=all --no-resolve`): nothing runs and no other host is needed.
- **Daily check and notifications.** `mvm check --all` checks every project mvm has fetched or checked; `make timer` installs it as a daily systemd user timer. With `[notify] ntfy = "https://ntfy.sh/<topic>"`, trips (malicious packages, held runs, failed proxy/observer, failed checks) are posted there. `mvm status` shows the last check per project and the trips of the last 24 hours.
- **Learning hosts:** `mvm fetch --learn` lets everything through the proxy but logs it, commits nothing, and prints the hosts outside the allowlist with the exact `[allow]` line to add.

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

[observer]             # TLS observer for fetch (needs `make observer`); on by default
enabled = true

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
  - Anything else: `mvm run -i IMAGE -- CMD`
- Network exists only in `mvm fetch`. Do not work around it.
```

## Requirements and install

Linux with `/dev/kvm`, `podman` + `crun-krun`, `e2fsprogs`, Python 3.11+ (standard library only). Caches should live on btrfs (or another reflink-capable filesystem); elsewhere copies still work but are full copies.

```bash
sudo dnf install podman crun-krun e2fsprogs
make setup          # all of: install, smokescreen, observer, skopeo (what a fresh machine needs)
make install        # ~/.local/bin/mvm, ~/.local/lib/mvm (package), man page, completions
make smokescreen    # build the pinned egress proxy offline with mvm, and its port-filter image; fetch refuses without them
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
