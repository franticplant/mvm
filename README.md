# mvm

Run dev tooling (`go`, `cargo`, `npm`, `python`, or any OCI image) in ephemeral KVM microVMs via **Podman + `crun-krun`** — offline and read-only by default, with `flock`-locked sparse ext4 cache images.

## Why

- **Real kernel boundary:** Untrusted build scripts (`npm postinstall`, `build.rs`, `go generate`, proc-macros) run inside their own isolated Linux guest kernel instead of sharing your host kernel.
- **No `virtio-fs` / SELinux slowdown:** Your project stays as ordinary host files (`/src:ro`), while the 30,000+ compiler scratch and dependency files live inside reusable sparse ext4 `.img` files loop-mounted inside the guest kernel. SELinux `:z` only relabels **one inode** per cache image.
- **Zero host privileges:** No `sudo`, no `--privileged`, no host namespaces. Guest `mount -o loop` and `mount -t tmpfs` run purely inside the microVM's own kernel.
- **Safe concurrency:** Host-side `flock(2)` automatically takes shared locks (`LOCK_SH`) on read-only caches and exclusive locks (`LOCK_EX`) on writable caches, preventing ext4 corruption when running parallel builds.

## Requirements

- Linux with `/dev/kvm`
- `podman` + `crun-krun` (`libkrun`)
- `e2fsprogs` (`mkfs.ext4`, `e2fsck`, `resize2fs`)
- Python 3.10+ (standard library only)

On Fedora:

```bash
sudo dnf install podman crun-krun e2fsprogs
```

## Install

```bash
git clone https://github.com/franticplant/mvm.git
cd mvm
make install
```

This installs `mvm`, `man mvm`, and bash/zsh completions into `~/.local` (no `sudo` required). Run `make uninstall` to remove them (cache images in `~/.cache/mvm` are left untouched).

- **Bash:** installed to `~/.local/share/bash-completion/completions/mvm` (auto-loaded by `bash-completion`).
- **Zsh:** installed to `~/.oh-my-zsh/custom/completions/_mvm` if Oh My Zsh is present, otherwise `~/.local/share/zsh/site-functions/_mvm` (for vanilla Zsh, add `fpath=(~/.local/share/zsh/site-functions $fpath)` before `compinit` in `~/.zshrc`, or pass `ZSH_COMPDIR=...`).

## Quickstart

Import existing host caches (optional, unprivileged via `mkfs.ext4 -d`):

```bash
mvm cache import go-mod ~/.cache/go-mod 2G
mvm cache import go-build ~/.cache/go-build 5G
mvm cache import cargo-reg ~/.cache/cargo 2G
mvm cache ls
```

Two-phase workflow (fetch with network, build offline):

```bash
# Go: fetch deps online, then build static binary offline into ./build
mvm --net --go -- go mod download
mvm --go -o build -- go build -trimpath -o /out/app ./cmd/app

# Rust: fetch crates online, then release build offline into ./build
mvm --net --rust -- cargo fetch
mvm --rust -o build -- cargo build --offline --release

# Generic OCI image with guest tmpfs scratch
mvm -i docker.io/library/alpine:latest -t /tmp/work:1g -- sh -c 'df -h /tmp/work'
```

See `man mvm` or `mvm --help` for all options, profiles (`--go`, `--rust`, `--node`), and cache commands (`ls`, `init`, `import`, `grow`, `rm`).

## Performance & Caveats

Measured on Fedora 43 (`crun-krun` 1.28, `libkrun` 1.19.8, i7-7820HQ) building a ~31 MiB static Go binary (`tailscale.com/tsnet`):

| Setup | Wall time (boot + build + exit) |
|---|---|
| Plain `podman` (`crun` container, warm host dirs) | **3.2s** |
| `mvm` (`krun` microVM + ext4 `.img` caches) | **7.7s** |
| `krun` + plain `virtio-fs` cache dir + cold `tmpfs` | **2m 17.7s** |

Caveats to know:
- **Single-writer ext4:** Writable cache images (`go-build`, `cargo-target`) are single-writer; concurrent `mvm` runs wait automatically on `flock`. Read-only caches (`go-mod`, `cargo-reg` in offline mode) are shared concurrently.
- **Loopback tests in `krun`:** Some loopback socket unit tests behave differently under `krun --network=none`. Use `mvm --crun` (without `--cache`) or plain `podman run --rm --network=none` if a unit test hits a `krun` networking quirk.

## License

MIT — see [LICENSE](LICENSE).
