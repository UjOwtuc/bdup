BDUP_VERSION = $(shell git describe --always --tags --dirty)

.PHONY: all

all: Cargo.toml
	cargo build

Cargo.toml: Cargo.toml.in .git/index
	sed 's/$$BDUP_VERSION/$(BDUP_VERSION)/g' $< > $@

