PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib/mvm
# Stripe Smokescreen (egress allowlist proxy for `mvm fetch`), pinned to a main commit
# at least two weeks old; built offline by mvm itself from its vendored sources.
SMOKESCREEN_REV ?= 5b4b7aabca9bc70a8435358d648edd03294c299e
SMOKESCREEN_SRC ?= $(HOME)/.cache/mvm-src/smokescreen
# nDPI 5.0 (ntop), the last all-LGPLv3 release, only as a black-box oracle for the observer's
# real tests (`make ndpi-oracle`): from 6.0 its TLS dissector is ntop dual-licensed. Never take 6.x code.
# skopeo for confined image pulls (`make skopeo`): a release tag at least two weeks old,
# built offline by mvm from its vendored sources as a static pure-Go binary (no cgo, no gpgme,
# no storage graph drivers), into a FROM scratch image.
SKOPEO_TAG ?= v1.25.1
SKOPEO_REV ?= 1fb351f23dbde474416ba33c3786a8d04304429b
SKOPEO_SRC ?= $(HOME)/.cache/mvm-src/skopeo
SKOPEO_TAGS = containers_image_openpgp containers_image_docker_daemon_stub containers_image_ostree_stub \
	exclude_graphdriver_btrfs exclude_graphdriver_devicemapper exclude_graphdriver_overlay exclude_graphdriver_zfs
NDPI_URL ?= https://github.com/ntop/nDPI/archive/refs/tags/5.0.tar.gz
NDPI_SHA256 ?= 8b0d3dc0c8a6a68578e09a18c922021ef6458d4aca1c7a20ce04efc267aa9ea5
NDPI_SRC ?= $(HOME)/.cache/mvm-src/ndpi
MANDIR ?= $(PREFIX)/share/man/man1
SYSTEMD_USER_DIR ?= $(HOME)/.config/systemd/user
BASH_COMPDIR ?= $(PREFIX)/share/bash-completion/completions
ZSH_COMPDIR ?= $(if $(and $(filter $(HOME)/.local,$(PREFIX)),$(wildcard $(HOME)/.oh-my-zsh/custom)),$(HOME)/.oh-my-zsh/custom/completions,$(PREFIX)/share/zsh/site-functions)

.PHONY: setup install uninstall test test-real test-go lint smokescreen skopeo l7proxy observer ndpi-oracle timer

# Everything a fresh machine needs: mvm, the egress proxy, the observer, confined pulls.
setup: install
	$(MAKE) smokescreen
	$(MAKE) observer
	$(MAKE) skopeo
	$(MAKE) l7proxy

install:
	install -d "$(BINDIR)" "$(LIBDIR)/mvm" "$(MANDIR)" "$(BASH_COMPDIR)" "$(ZSH_COMPDIR)"
	rm -f "$(LIBDIR)"/mvm/*.py
	install -m 0644 mvm/*.py "$(LIBDIR)/mvm/"
	install -m 0755 bin/mvm "$(BINDIR)/mvm"
	install -m 0644 man/mvm.1 "$(MANDIR)/mvm.1"
	install -m 0644 completions/mvm.bash "$(BASH_COMPDIR)/mvm"
	install -m 0644 completions/_mvm "$(ZSH_COMPDIR)/_mvm"
	@echo "Installed mvm into $(PREFIX)"
	@echo "  binary:     $(BINDIR)/mvm"
	@echo "  package:    $(LIBDIR)/mvm"
	@echo "  man page:   $(MANDIR)/mvm.1"
	@echo "  bash comp:  $(BASH_COMPDIR)/mvm"
	@echo "  zsh comp:   $(ZSH_COMPDIR)/_mvm"

uninstall:
	-systemctl --user disable --now mvm-check.timer 2>/dev/null
	rm -f "$(SYSTEMD_USER_DIR)/mvm-check.service" "$(SYSTEMD_USER_DIR)/mvm-check.timer"
	rm -rf "$(LIBDIR)"
	rm -f "$(BINDIR)/mvm" "$(MANDIR)/mvm.1" "$(BASH_COMPDIR)/mvm" "$(ZSH_COMPDIR)/_mvm"
	@echo "Removed mvm from $(PREFIX) (cache images in ~/.cache/mvm were left untouched)"

test:
	python3 -m unittest discover -s tests -v

# Boots real krun microVMs (needs /dev/kvm, podman, crun-krun); ~10s.
test-real:
	MVM_REAL=1 python3 -m unittest discover -s tests -v

lint:
	python3 -m py_compile bin/mvm mvm/*.py tests/test_mvm.py
	bash -n completions/mvm.bash
	@if command -v zsh >/dev/null 2>&1; then zsh -n completions/_mvm; fi

smokescreen:
	@test -d "$(SMOKESCREEN_SRC)/.git" || git clone -q --filter=blob:none https://github.com/stripe/smokescreen.git "$(SMOKESCREEN_SRC)"
	git -C "$(SMOKESCREEN_SRC)" cat-file -e "$(SMOKESCREEN_REV)^{commit}" 2>/dev/null || git -C "$(SMOKESCREEN_SRC)" fetch -q origin "$(SMOKESCREEN_REV)"
	git -C "$(SMOKESCREEN_SRC)" checkout -q --detach "$(SMOKESCREEN_REV)"
	test -d "$(SMOKESCREEN_SRC)/vendor"
	cd "$(SMOKESCREEN_SRC)" && "$(BINDIR)/mvm" build go -w out -- go build -mod=vendor -trimpath -o out/smokescreen .
	install -d "$(LIBDIR)"
	install -m 0755 "$(SMOKESCREEN_SRC)/out/smokescreen" "$(LIBDIR)/smokescreen"
	podman build -q -t localhost/mvm-egress-fw:1 -f egress/Containerfile.firewall egress >/dev/null
	@echo "Installed smokescreen $(SMOKESCREEN_REV) into $(LIBDIR) and built localhost/mvm-egress-fw:1"

skopeo:
	@test -d "$(SKOPEO_SRC)/.git" || git clone -q --filter=blob:none https://github.com/containers/skopeo.git "$(SKOPEO_SRC)"
	git -C "$(SKOPEO_SRC)" cat-file -e "$(SKOPEO_REV)^{commit}" 2>/dev/null || git -C "$(SKOPEO_SRC)" fetch -q --depth 1 origin tag "$(SKOPEO_TAG)"
	git -C "$(SKOPEO_SRC)" checkout -q --detach "$(SKOPEO_REV)"
	test -d "$(SKOPEO_SRC)/vendor"
	install -d "$(SKOPEO_SRC)/out"
	@# Bootstrap: the Go image comes from plain podman pull here (later pulls need this skopeo).
	img="$$(python3 -c 'import sys; sys.path.insert(0, "."); from mvm import ecos; print(ecos.ECOS["go"].image)')"; \
		podman image exists "$$img" || podman pull -q "$$img" >/dev/null
	cd "$(SKOPEO_SRC)" && "$(BINDIR)/mvm" build go -w out -- env CGO_ENABLED=0 go build -mod=vendor -trimpath \
		-ldflags '-s -w' -tags '$(SKOPEO_TAGS)' -o out/skopeo ./cmd/skopeo
	podman build -q -t localhost/mvm-skopeo:1 -f "$(CURDIR)/egress/Containerfile.skopeo" "$(SKOPEO_SRC)/out" >/dev/null
	@echo "Built localhost/mvm-skopeo:1 (skopeo $(SKOPEO_TAG), static) for confined image pulls"

# The L7 policy proxy for image pulls (stdlib Go, no dependencies), built offline by mvm.
l7proxy:
	install -d egress/l7proxy/out
	cd egress/l7proxy && "$(BINDIR)/mvm" build go -w out -- env CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o out/l7proxy .
	install -d "$(LIBDIR)"
	install -m 0755 egress/l7proxy/out/l7proxy "$(LIBDIR)/l7proxy"
	@echo "Installed l7proxy into $(LIBDIR)"

# Go unit tests for l7proxy, offline; plain podman (crun): loopback sockets in a krun VM are refused.
test-go:
	podman run --rm --pull=never --network=none -v "$(CURDIR)/egress/l7proxy:/src:ro,z" -w /src \
		-e GOCACHE=/tmp/gc -e GOTOOLCHAIN=local docker.io/library/golang:1.27-alpine \
		sh -c 'test -z "$$(gofmt -l .)" && go vet ./... && go test -count=1 ./...'

observer:
	podman pull -q "$$(python3 -c 'import sys; sys.path.insert(0, "."); from mvm import observer; print(observer.OBSERVER_IMAGE)')" >/dev/null
	@echo "Pulled the observer's Python image (the fetch observer, on by default)"

ndpi-oracle:
	install -d "$(NDPI_SRC)"
	@test -f "$(NDPI_SRC)/nDPI-5.0.tar.gz" || curl -fsSL -o "$(NDPI_SRC)/nDPI-5.0.tar.gz" "$(NDPI_URL)"
	echo "$(NDPI_SHA256)  $(NDPI_SRC)/nDPI-5.0.tar.gz" | sha256sum -c -
	podman build -q -t localhost/mvm-ndpi-oracle:5.0 -f "$(CURDIR)/egress/Containerfile.ndpi-oracle" "$(NDPI_SRC)" >/dev/null
	@echo "Built localhost/mvm-ndpi-oracle:5.0 (nDPI 5.0, test oracle only)"

# Daily `mvm check --all` (osv-scanner on every known project's lockfiles), as a user timer.
timer:
	install -d "$(SYSTEMD_USER_DIR)"
	install -m 0644 systemd/mvm-check.service systemd/mvm-check.timer "$(SYSTEMD_USER_DIR)/"
	systemctl --user daemon-reload
	systemctl --user enable --now mvm-check.timer
	@systemctl --user list-timers mvm-check.timer --no-pager
