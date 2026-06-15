# Reproducible Linux dev environment for coldstep.
#
# Mirrors the toolchain that scripts/build-agent-linux.sh expects on a GitHub
# ubuntu-latest runner: clang/llvm + libbpf-dev for the BPF compile path,
# bpftool (via linux-tools-generic) for the vmlinux.h dump, kernel headers, and
# a Go toolchain matching go.mod.
#
# BPF load/integration tests need a kernel with BTF (/sys/kernel/btf/vmlinux)
# and CAP_BPF inside the container — see .devcontainer/devcontainer.json
# (runArgs) and the `make devshell` target, both of which add --cap-add BPF.

FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
# Keep in lockstep with the `go` directive in go.mod.
ARG GO_VERSION=1.25.11

RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      ca-certificates \
      curl \
      git \
      make \
      clang \
      llvm \
      libbpf-dev \
      linux-tools-generic \
      linux-headers-generic \
      build-essential \
      pkg-config \
      python3 \
 && rm -rf /var/lib/apt/lists/*

# Install the Go toolchain that matches go.mod (apt's golang-go lags behind).
RUN arch="$(dpkg --print-architecture)" \
 && case "$arch" in \
      amd64) goarch=amd64 ;; \
      arm64) goarch=arm64 ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac \
 && curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz" -o /tmp/go.tgz \
 && tar -C /usr/local -xzf /tmp/go.tgz \
 && rm /tmp/go.tgz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOTOOLCHAIN=auto

WORKDIR /work

CMD ["bash"]
