.PHONY: build test format install update uninstall

PREFIX := $(HOME)/.local/bin

build:
	cargo build --release

test:
	cargo test

format:
	cargo fmt

install: build
	mkdir -p $(PREFIX)
	cp target/release/lord-kali $(PREFIX)/lord-kali

update: build install

uninstall:
	rm -f $(PREFIX)/lord-kali
