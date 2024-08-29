.DEFAULT_GOAL := help
SHELL:=/bin/bash
DEV_NODE_NAME = moonbeam_development
## Compile all contracts
compile:
	npx hardhat compile

## Report contracts sizes
size:
	npx hardhat size-contracts


## Deploy contract to local node
deploy-dev: export NETWORK=dev
deploy-dev: deploy-upgradeable

.PHONY: deploy-upgradeable
## Deploy contract to $NETWORK (e.g. dev)
deploy-upgradeable:
	npx hardhat run --network $${NETWORK:-dev} scripts/deploy-upgradable.js

.PHONY: upgrade
## Upgrade contract on chain ${NETWORK} at address found in .asfaload_address_${NETWORK}
upgrade:
	npx hardhat run --network $${NETWORK:-dev} scripts/upgrade-asfaload.js

.PHONY: start-local-node
## Start a local moonbeam node with docker
start-local-node:
	if [[ -z $$(docker ps --filter "name=$(DEV_NODE_NAME)" -q) ]] ; then \
		echo "starting container $${DEV_NODE_NAME}"; \
		docker run -d --rm --name $(DEV_NODE_NAME) -p 9944:9944 moonbeamfoundation/moonbeam:v0.39.1 --dev --rpc-external --tmp --sealing 6000; \
	fi

.PHONY: stop-local-node
## Stop the local moonbeam node container
stop-local-node:
	if [[ -n $$(docker ps --filter "name=$(DEV_NODE_NAME)" -q) ]] ; then \
		docker stop $(DEV_NODE_NAME); \
	fi

.PHONY: wait-local-node
## Sending a request to the node before it's ready makes it crash. This target lets you wait until the node is ready
wait-local-node:
	while ! docker logs $(DEV_NODE_NAME) 2>&1 | grep -q "Idle ([[:digit:]] peers)" ; \
	do \
			sleep 1; \
			echo "Waiting for local node to be up..."; \
	done; \

.PHONY: test
## Run contract tests on local node, which is started if needed (but it is not stopped)
## Select which tests to run by passing your selection in the GREP variable: make test GREP="regex"
# Sending a request to the node before it's ready makes it crash, so we first detect when it's ready
# by depending on wait-local-node
test: start-local-node wait-local-node
	GREP="$(GREP)" && \
			 npx hardhat test --network dev $${GREP:+--grep "$$GREP"} tests/Asfaload.js

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
