.PHONY: ci setup-ubuntu run

ci:
	cargo check --all-targets
	cargo check --all-targets --features apdu-dispatch,ctaphid
	cargo test --verbose

run:
	env RUST_LOG=debug cargo run $(FLAGS)

setup-ubuntu:
	sudo apt install llvm libclang-dev make
