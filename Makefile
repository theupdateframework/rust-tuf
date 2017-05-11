.PHONY: help travis
.DEFAULT_GOAL := help

clean: ## Remove junk
	@find . -name '*.rs.bk' -delete

help: ## Print this message and exit
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%16s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST)

travis: ## Run the TravisCI tests
	@cargo build --verbose --features=cli && \
		cargo test --verbose --features=cli || \
		{ cat Cargo.lock; exit 1; }
