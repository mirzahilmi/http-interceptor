COLOR=\033[0;33m
RESET=\033[0m

.PHONY: ebpf
ebpf:
	@printf "$(COLOR)%s$(RESET)\n" "Building, and executing eBPF program"
	RUST_LOG=info cargo run --release
