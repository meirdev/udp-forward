.PHONY: fmt

fmt:
	cargo +nightly fmt

fix:
	__CARGO_FIX_YOLO=1 cargo +nightly fix

tests:
	cargo test -- --include-ignored --test-threads=1

release:
	cargo build --release

release-musl:
	rustup target add x86_64-unknown-linux-musl
	cargo build --release --target x86_64-unknown-linux-musl
