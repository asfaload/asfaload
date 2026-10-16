.DEFAULT_GOAL := help
SHELL := /bin/bash

TESTS := basic_flow.sh signers_update_by_master.sh basic_flow_local.sh ssh_keys_flow_local.sh metadata_signatures_check_local.sh register_assets_invalid_client_data.sh
KEY_TYPES ?= asfaload

## Run all e2e tests
test: test-sha256

## Run all e2e tests with sha256 oids (all key types)
test-sha256:
	@for kt in $(KEY_TYPES); do \
		for t in $(TESTS); do \
			printf '\n══ Running %s (sha256, %s) ══\n\n' "$$t" "$$kt"; \
			ASFALOAD_GIT_BACKEND=sha256 KEY_TYPE=$$kt ./$$t || exit 1; \
		done; \
	done

## Run local tests in fast config. Run by default by CI too.
test-local:
	@for t in $(TESTS); do \
		if [[ $$t == *_local.sh ]]; then \
			ASFALOAD_GIT_BACKEND=$${ASFALOAD_GIT_BACKEND:-sha256} KEY_TYPE=$${KEY_TYPE:-asfaload} ./$$t || exit 1; \
		fi; \
	done

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
	}'
