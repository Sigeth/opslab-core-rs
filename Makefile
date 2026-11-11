.PHONY: all generate generate-local test lint deny verify-generated

all: lint test deny

## generate: regenerate opslab-types from the core-go tag in CORE_GO_VERSION
generate:
	scripts/generate.sh

## generate-local: regenerate opslab-types from a local core-go checkout
generate-local:
	CORE_GO_DIR=$(or $(CORE_GO_DIR),../core-go) scripts/generate.sh

test:
	cargo test --workspace --all-features

lint:
	cargo fmt --all --check
	cargo clippy --workspace --all-features --all-targets -- -D warnings

deny:
	cargo deny check

## verify-generated: fail if generated types differ from the pinned core-go tag (CI)
verify-generated: generate
	git diff --exit-code -- crates/opslab-types/src/generated
