.PHONY: ci setup-ubuntu

ci:
	cargo test --verbose

setup-ubuntu:
	sudo apt install llvm libclang-dev make