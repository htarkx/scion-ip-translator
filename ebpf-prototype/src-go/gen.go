package srcgo

// Package srcgo provides Go skeletons for the SCION eBPF translator programs.

//go:generate go tool github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -strip $LLVM_STRIP Egress ../bpf/egress.bpf.c -- $BPF_CFLAGS -I../vmlinux
//go:generate go tool github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -strip $LLVM_STRIP Ingress ../bpf/ingress.bpf.c -- $BPF_CFLAGS -I../vmlinux
