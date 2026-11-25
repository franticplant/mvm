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

- **No third-party code runs with network.** `go mod download` and `cargo fetch` run none; npm runs with `--ignore-scripts` (run them offline: `mvm build node -- npm rebuild`); Go may not download a newer toolchain (`GOTOOLCHAIN=local`).
- **Changing dependencies** is a fetch with a command: `mvm fetch go -- go get golang.org/x/net@latest`, `mvm fetch rust -- cargo generate-lockfile`, `mvm fetch node -- npm install --ignore-scripts left-pad`. Only manifest/lockfile changes flow back, and mvm lists them.
- **Commit-on-clean.** Every writable cache is a reflink copy for the duration of the run and replaces the cache atomically only on exit 0. A failure, Ctrl-C, crash or `kill -9` leaves the cache exactly as it was.
- **Pinned images.** The first use of an image tag pins its digest; `mvm update` re-pulls and shows what changed.
- **Egress only through an allowlist proxy.** A fetch VM's network is pasta bound to loopback with one forwarded port, where a per-run [Smokescreen](https://github.com/stripe/smokescreen) (Stripe's egress proxy) allows only the ecosystem's registries. No DNS, no direct connections, no UDP, ICMP or IPv6 (each proven with real krun runs). Every connection is logged with bytes in/out; denials are printed and kept in the run record.
- **A denial holds the run.** If a fetch exits 0 but tried a denied host, nothing is committed or copied back and mvm exits 3; if the proxy died or its log is unreadable, exit 4.
- **Observer (optional, off by default).** With `[observer] enabled = true`, a passive [nDPI](https://github.com/ntop/nDPI) `ndpiReader` sidecar in the proxy pod records every outbound TLS flow: SNI, JA4 and bytes, in the run record and summarised. A TLS name outside the allowlist (or no SNI) holds the run like a denial (exit 3): the proxy only sees the CONNECT host, so this catches domain fronting. It fails closed: a missing image refuses the fetch, a dead observer, unreadable flows, discarded frames, or a proxy connection with no observed flow means nothing is committed (exit 5). `mvm status` prints `observer off` when it is off.
- **Learning hosts:** `mvm fetch --learn` lets everything through the proxy but logs it, commits nothing, and prints the hosts outside the allowlist with the exact `[allow]` line to add.

## State

| Path | What |
|---|---|
| `~/.cache/mvm/<name>.img` | sparse ext4 cache images, loop-mounted inside the guest (`go-mod`, `go-build`, `cargo-reg`, `cargo-git`, `cargo-target`, `npm`, `nm-<project>-<hash>`) |
| `~/.cache/mvm/<name>.meta.json` | generation number, last commit, owning project (for `node_modules`) |
| `~/.cache/mvm/<name>.lock` | `flock`: shared for read-only users, exclusive for the writer |
| `~/.local/state/mvm/pins.json` | image tag → pinned digest |
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

[observer]             # nDPI flow observer for fetch (needs `make observer`); off by default
enabled = true
```

Built-in allowlists: go `proxy.golang.org`, `sum.golang.org`, `storage.googleapis.com`; rust `index.crates.io`, `static.crates.io`; node `registry.npmjs.org`.

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
make install        # ~/.local/bin/mvm, ~/.local/lib/mvm (package), man page, completions
make smokescreen    # build the pinned egress proxy offline with mvm, and its port-filter image; fetch refuses without them
make observer       # optional: build the nDPI observer image (nDPI 6.0 tarball pinned by sha256)
make test           # unit tests, no KVM needed
make test-real      # + real microVM tests, including the egress escape test
```

## Caveats

- podman's `--tmpfs` is ignored under krun; mvm hides directories with an empty read-only bind instead.
- Ports: Smokescreen's ACL is host-only, so the proxy runs in a pod whose network namespace has an nftables egress filter (loaded by a one-shot `NET_ADMIN` container; Smokescreen itself has no capabilities): only TCP 443 out, plus DNS to the pod's resolver. An allowed host on any other port is refused, recorded as denied, and holds the run. Host loopback, link-local, private and CGNAT ranges and IP literals are refused by Smokescreen (checked with real CONNECT probes).
- Observer: it captures only the pod's outbound leg (proxy to registry), which carries the VM's own ClientHello relayed through CONNECT; denied requests never reach the network, so for those the proxy log is the record. The firewall one-shot sets the pod's MTU to 1500 because pasta's 65520 makes `ndpiReader` drop the frames that carry the ClientHello. Cisco mercury was tried first and rejected: its AF_PACKET ring needs at least 32 MiB of locked memory, above the 8 MiB rootless default.
- Writable caches are single-writer: concurrent builds of the same ecosystem wait on the lock.
- A failing build (non-zero exit, including failing tests) discards that run's build-cache writes; the next run rebuilds.
- Rust path dependencies outside the project directory and npm workspaces with nested `node_modules` are not handled by `fetch` yet.

## License

MIT — see [LICENSE](LICENSE).
