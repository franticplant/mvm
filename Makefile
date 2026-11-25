PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib/mvm
MANDIR ?= $(PREFIX)/share/man/man1
BASH_COMPDIR ?= $(PREFIX)/share/bash-completion/completions
ZSH_COMPDIR ?= $(if $(and $(filter $(HOME)/.local,$(PREFIX)),$(wildcard $(HOME)/.oh-my-zsh/custom)),$(HOME)/.oh-my-zsh/custom/completions,$(PREFIX)/share/zsh/site-functions)

.PHONY: install uninstall test test-real lint

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
