.PHONY: build test fmt lint deploy clean

build:
	cargo build --target wasm32-unknown-unknown --release

test:
	cargo test

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace -- -D warnings

clean:
	cargo clean

deploy:
	@echo "Run scripts/deploy.sh to deploy to testnet"
	@bash scripts/deploy.sh

check: fmt lint test
	@echo "All checks passed"
