.PHONY: help clean dev-docs
.DEFAULT_GOAL := help

clean: ## Remove temp/useless files
	@find . -name '*.rs.bk' -type f -delete

dev-docs: ## Generate the documentation for all modules (dev friendly)
	@cargo rustdoc --all-features --open -- --no-defaults --passes "collapse-docs" --passes "unindent-comments"

help: ## Print this message
	@awk 'BEGIN {FS = ":.*?## "} /^[0-9a-zA-Z_-]+:.*?## / {printf "\033[36m%16s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST)
