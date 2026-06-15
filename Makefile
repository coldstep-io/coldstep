# coldstep developer convenience targets.
#
# The authoritative build is scripts/build-agent-linux.sh (Linux only). These
# targets wrap the common loops. `make devshell` drops you into a reproducible
# Ubuntu 24.04 container (.devcontainer/Dockerfile) with the full BPF toolchain
# and a Go matching go.mod — the same bones as scripts/docker-linux-test.sh.

DOCKER ?= docker
DEVIMAGE ?= coldstep-dev
ROOT := $(CURDIR)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help.
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build bin/coldstep via scripts/build-agent-linux.sh (Linux host).
	bash scripts/build-agent-linux.sh "$(ROOT)"

.PHONY: test
test: ## Run the Go unit tests (Linux host).
	go test ./... -count=1

.PHONY: devimage
devimage: ## Build the .devcontainer dev image.
	$(DOCKER) build -t $(DEVIMAGE) -f .devcontainer/Dockerfile .

.PHONY: devshell
devshell: devimage ## Open an interactive dev shell in the container (repo mounted at /work, CAP_BPF).
	$(DOCKER) run --rm -it \
		--cap-add BPF \
		--cap-add PERFMON \
		-v "$(ROOT):/work" \
		-w /work \
		-e GOTOOLCHAIN=auto \
		$(DEVIMAGE) \
		bash

.PHONY: linux-test
linux-test: ## Run the full Linux build + tests in a throwaway container.
	bash scripts/docker-linux-test.sh "$(ROOT)"
