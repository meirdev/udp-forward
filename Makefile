.PHONY: fmt

fmt:
	cargo +nightly fmt

fix:
	__CARGO_FIX_YOLO=1 cargo +nightly fix

tests:
	cargo test -- --include-ignored --test-threads=1
