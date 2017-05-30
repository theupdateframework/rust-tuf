.PHONY: clean help test travis
.DEFAULT_GOAL := help

clean: ## Remove junk
	@find . -name '*.rs.bk' -delete

help: ## Print this message and exit
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%16s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: ## Run the tests with logging enabled
	@cargo test --features=cli --no-run && \
		RUST_LOG=debug cargo test --features=cli

travis: ## Run the TravisCI tests
	@RUST_BACKTRACE=full cargo build --verbose --features=cli && \
		RUST_BACKTRACE=full cargo test --verbose --features=cli || \
		{ cat Cargo.lock; exit 1; }
