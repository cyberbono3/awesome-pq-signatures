<<<<<<< HEAD
.PHONY: format build test 
=======
.PHONY: format build test
>>>>>>> master

format:
	cargo fmt --all

build:
	cargo build --release --workspace

test:
	cargo test --workspace