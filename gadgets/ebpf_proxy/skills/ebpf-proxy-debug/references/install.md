# Installing eBPF Proxy + `ig` (no MCP server needed)

eBPF Proxy runs as an OCI gadget through the `ig` CLI. You need: a BTF-enabled Linux
kernel, `ig`, and the `ebpf_proxy:latest` image in the local `ig` store.

## 1. Prereqs
- Kernel with BTF: `test -r /sys/kernel/btf/vmlinux` (Ubuntu 22.04+/24.04, Azure
  Linux 3, most 5.10+ distro kernels).
- Root or `CAP_BPF`+`CAP_PERFMON` (tracing). `NET_ADMIN` only for TC/XDP.
- `clang/llvm`, `libbpf-dev`, Go (only to BUILD ig/the image).

## 2. Get `ig` (Inspektor Gadget)
Prebuilt: download the `ig` binary from the Inspektor Gadget releases and put it
on `PATH`. From source:
```bash
git clone https://github.com/inspektor-gadget/inspektor-gadget
cd inspektor-gadget && make ig            # -> ./ig
sudo install ./ig /usr/local/bin/ig
ig version
```

## 3. Build the eBPF Proxy image into the local ig store
From the branch that carries the gadget (`ebpf_proxy`):
```bash
cd gadgets/ebpf_proxy
sudo ig image build -t ebpf_proxy:latest --local .   # needs clang/libbpf
sudo ig image list | grep ebpf_proxy              # confirm
```
`--local` builds with the local toolchain (no builder container).

## 4. Smoke test
```bash
sudo ig run ebpf_proxy:latest --verify-image=false \
  --capability=list_attachable --filter=do_sys_open --max=3 -o columns
```
You should see `do_sys_openat2` etc. Or run `scripts/ebpf-proxy-doctor.sh`.

## 5. Kubernetes / AKS
For in-cluster use, deploy Inspektor Gadget (`kubectl gadget deploy`) and
`kubectl gadget run ebpf_proxy:latest ...`, OR use a node debug session
(`kubectl debug node/<n>` + `nsenter`) and run `ig` directly on the node.
See the `ebpf-proxy-aks-azure-debug` skill.
