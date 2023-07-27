# bachelor-bpf-xdp

This project is part of my bachelor's thesis and is not intended for production.
The goal of this part of the project was to write a XDP program that could
forward traffic arriving at a specific port to a specified container (via the
veth interface). It consists of two parts: `ba-ebpf-main` and `ba-ebpf-veth`.
Both parts are reflected by branches in this repository. However, for this to
work, the container needs a XDP program attached to it's side of the veth pair
as well. I used the basic xdp pass programm from the
[xdp-tutorial](https://github.com/xdp-project/xdp-tutorial/tree/master/basic01-xdp-pass)
for this.

## Usage

**For MAIN:**
```bash
cargo xtask run --release -- -i <input_interface_name> -o <veth_iface_id>
# e.g.: cargo xtask run --release -- -i ens1 -o $(ip link | grep veth | cut -d: -f1 | head -n1)
```

**For VETH:**
```bash
cargo xtask run --release -- -i <veth_iface_name>
# e.g.: cargo xtask run --release -- -i $(ip -br a | grep veth | cut -d@ -f1)
```

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain with the rust-src component: `rustup toolchain install nightly --component rust-src`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```

Note: Logs are disabled
