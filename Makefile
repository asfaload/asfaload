.DEFAULT_GOAL := help
SHELL:=/bin/bash

## Run all tests with asfaload keys (default)
test: test-asfaload

## Run tests with test-utils feature enabled (for integration tests)
# Note that if test-utils is added to other packages, they need to be added here.
test-with-test-utils:
	cargo nextest run --features test-utils  --package rest-api --package forge-url --package signatures

## Fix rust code formatting
format:
	cargo fmt --verbose

## Check rust code formatting without fixing
check-format:
	cargo fmt --check

## run clippy
clippy:
	cargo clippy

## Build non-optimised Docker image, sufficient only for alpha phase
docker-build-alpha-image:
	docker build -f docker/Dockerfile.rest-api -t asfaload_rest_api .

help:
	@echo "$$(tput bold)Available rules:$$(tput sgr0)"
	@echo
	@sed -n -e "/^## / { \
		h; \
		s/.*//; \
		:doc" \
		-e "H; \
		n; \
		s/^## //; \
		t doc" \
		-e "s/:.*//; \
		G; \
		s/\\n## /---/; \
		s/\\n/ /g; \
		p; \
	}" ${MAKEFILE_LIST} \
	| LC_ALL='C' sort --ignore-case \
	| awk -F '---' \
		-v ncol=$$(tput cols) \
		-v indent=19 \
		-v col_on="$$(tput setaf 6)" \
		-v col_off="$$(tput sgr0)" \
	'{ \
		printf "%s%*s%s ", col_on, -indent, $$1, col_off; \
		n = split($$2, words, " "); \
		line_length = ncol - indent; \
		for (i = 1; i <= n; i++) { \
			line_length -= length(words[i]) + 1; \
			if (line_length <= 0) { \
				line_length = ncol - indent - length(words[i]) - 1; \
				printf "\n%*s ", -indent, " "; \
			} \
			printf "%s ", words[i]; \
		} \
		printf "\n"; \
	}' \
	| more $(shell test $(shell uname) == Darwin && echo '--no-init --raw-control-chars')

## Run all tests with asfaload keys
test-asfaload:
	$(MAKE) check-format
	$(MAKE) clippy
	KEY_TYPE=asfaload cargo nextest run
	KEY_TYPE=asfaload $(MAKE) test-with-test-utils
	KEY_TYPE=asfaload $(MAKE) -C rest-api test-sha256
	KEY_TYPE=asfaload $(MAKE) -C rest-api test-with-test-utils-sha256
	# run separately as some tests only run when test-utils feature is NOT present.
	cargo nextest run --package forge-url
	KEY_TYPE=asfaload $(MAKE) -C tests/e2e_tests test-local

## Run mutation tests (with asfaload keys). Select packages in .cargo/mutants.toml
test-mutants:
	KEY_TYPE=asfaload cargo mutants --test-tool nextest

## Run client-server integration tests
client-server-tests:
	cargo test --package client-server-integration-tests

.PHONY: docs docs-serve docs-clean docs-copy-demos

GIF_SRC := client-cli/docs/demos/howto/out
GIF_DST := client-cli/docs/howto/demos

## Copy rendered demo GIFs into the howto tree for mdbook to embed
docs-copy-demos:
	@mkdir -p $(GIF_DST)
	@if ls $(GIF_SRC)/*.gif >/dev/null 2>&1; then \
	    cp -f $(GIF_SRC)/*.gif $(GIF_DST)/; \
	else \
	    echo "warn: no rendered demos in $(GIF_SRC) — run 'make demos' first" >&2; \
	fi

## Build documentation site
docs: docs-copy-demos
	@mkdir -p docs/site/src/client-cli docs/site/src/rest-api
	@ln -sfn ../../concepts docs/site/src/concepts
	@ln -sfn ../../../../client-cli/docs/howto docs/site/src/client-cli/howto
	@ln -sfn ../../../../client-cli/docs/manual docs/site/src/client-cli/manual
	@ln -sfn ../../../../rest-api/docs/manual docs/site/src/rest-api/manual
	mdbook build docs/site

## Serve documentation site locally for preview
docs-serve: docs-copy-demos
	@mkdir -p docs/site/src/client-cli docs/site/src/rest-api
	@ln -sfn ../../concepts docs/site/src/concepts
	@ln -sfn ../../../../client-cli/docs/howto docs/site/src/client-cli/howto
	@ln -sfn ../../../../client-cli/docs/manual docs/site/src/client-cli/manual
	@ln -sfn ../../../../rest-api/docs/manual docs/site/src/rest-api/manual
	mdbook serve docs/site

## Remove generated documentation files
docs-clean:
	rm -rf docs/site/src/concepts docs/site/src/client-cli docs/site/src/rest-api docs/site/book
	rm -rf $(GIF_DST)


RCLONE_CONFIG := private/rclone.conf
## Configure rclone for deployment.
## If the configuration file at private/rclone.conf already exists if stops.
docs-setup-rclone:
	[[ ! -f $(RCLONE_CONFIG) ]]  || { echo "Config file already exists at $(RCLONE_CONFIG)"; exit 1; }
	mkdir -p private
	rclone --config $(RCLONE_CONFIG) config

## Deploy generated static site
docs-deploy: docs-clean docs
	rclone --config $(RCLONE_CONFIG) sync --verbose ./docs/site/book/ ovh:/home/asfaloc/www/docs/

## Render VHS demos for the client-cli how-tos. DEMO_PROFILE is production by default, set to fast for dev
demos:
	./client-cli/docs/demos/run-demos.sh
