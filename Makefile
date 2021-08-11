BDUP_VERSION = $(shell git describe --always --tags --dirty)

.PHONY: all test Cargo.toml

all: Cargo.toml
	cargo build

test: Cargo.toml
	CARGO_TARGET_DIR=/tmp/bdup_test cargo tarpaulin --frozen --verbose

Cargo.toml: Cargo.toml.in
	sed 's/$$BDUP_VERSION/$(BDUP_VERSION)/g' $< > $@

