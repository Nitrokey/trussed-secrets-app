.PHONY: ci setup-ubuntu

ci:
	cargo test --verbose
	cargo build --example usbip --features "ctaphid devel"

setup-ubuntu:
	sudo apt install llvm libclang-dev make