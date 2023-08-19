.PHONY: ci setup-ubuntu run

FLAGS=--example usbip --features "ctaphid devel"

ci:
	cargo test --verbose
	cargo build $(FLAGS)

run:
	env RUST_LOG=debug cargo run $(FLAGS)

setup-ubuntu:
	sudo apt install llvm libclang-dev make