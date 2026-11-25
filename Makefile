PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib/mvm
# Stripe Smokescreen (egress allowlist proxy for `mvm fetch`), pinned to a main commit
# at least two weeks old; built offline by mvm itself from its vendored sources.
SMOKESCREEN_REV ?= 5b4b7aabca9bc70a8435358d648edd03294c299e
SMOKESCREEN_SRC ?= $(HOME)/.cache/mvm-src/smokescreen
MANDIR ?= $(PREFIX)/share/man/man1
BASH_COMPDIR ?= $(PREFIX)/share/bash-completion/completions
ZSH_COMPDIR ?= $(if $(and $(filter $(HOME)/.local,$(PREFIX)),$(wildcard $(HOME)/.oh-my-zsh/custom)),$(HOME)/.oh-my-zsh/custom/completions,$(PREFIX)/share/zsh/site-functions)

.PHONY: install uninstall test test-real lint smokescreen

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
	@echo "Installed smokescreen $(SMOKESCREEN_REV) into $(LIBDIR)"
