# Copyright (C) 2022 Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

FUZZ_DURATION?="0"
FUZZ_JOBS?=$(shell nproc)
.NOTPARALLEL:

.PHONY: check
check:
	reuse lint

corpus: corpus.tar.gz
	tar xf $<

.PHONY: fuzz
fuzz: corpus
	nice cargo +nightly fuzz run --jobs ${FUZZ_JOBS} fuzz_target_1 corpus -- -max_total_time=${FUZZ_DURATION}

.PHONY: fuzz-cov
fuzz-cov:
	mkdir -p /tmp/coverage
	-rm ./coverage
	ln -s /tmp/coverage
	cargo +nightly fuzz coverage fuzz_target_1 corpus
	$(MAKE) fuzz-cov-show

LLVMCOV=~/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov
.PHONY: fuzz-cov-show
fuzz-cov-show:
	$(LLVMCOV) show --format=html \
		--instr-profile=coverage/fuzz_target_1/coverage.profdata \
		 ${CARGO_TARGET_DIR}/x86_64-unknown-linux-gnu/release/fuzz_target_1 \
		> fuzz_coverage.html

.PHONY: ci
ci:
	$(MAKE) fuzz FUZZ_DURATION=10 FUZZ_JOBS=1

.PHONY: setup
setup:
	rustup component add clippy rustfmt && rustup toolchain install nightly
	rustup +nightly component add llvm-tools-preview
	cargo +nightly install cargo-fuzz --profile release
	cargo +nightly install cargo-tarpaulin cargo-binutils --profile release  # for coverage
	# python3 -m pip install reuse
	# Fedora 37
	# sudo ln -s libclang.so.15 libclang.so

.PHONY: setup-ubuntu
setup-ubuntu:
	sudo apt install llvm libclang-dev make curl clang pkg-config libssl-dev python3-pip git
	# rust
	# curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
	# source "$HOME/.cargo/env"
