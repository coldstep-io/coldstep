package traceenforce

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.21.0 -cc clang -no-strip -target bpfel,bpfeb -cflags "-O2 -g -Wall -Werror -I../../../bpf -I/usr/include/bpf" Traceenforce ../../../bpf/trace_enforce.bpf.c -- -I../../../bpf -I/usr/include/bpf
