.DEFAULT_GOAL := test
SHELL := /bin/bash

## Run all tests of client-cli
test:
	cargo nextest run --features test-utils
	$(MAKE) test-shell

## Run the shell integration tests of asfaload-cli
test-shell:
	cargo build
	@for t in tests/shell/test_*.sh; do \
		printf '\n══ Running %s ══\n\n' "$$t"; \
		./$$t || exit 1; \
	done
