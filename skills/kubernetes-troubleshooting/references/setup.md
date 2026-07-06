# Setup — Inspektor Gadget in a Kubernetes cluster

You need the `kubectl gadget` plugin locally and the Inspektor Gadget DaemonSet
running in the cluster. Everything here is standard upstream; confirm the exact
current commands with `kubectl gadget --help`.

## 1. Install the `kubectl gadget` plugin

Install via `krew` (the kubectl plugin manager) or download the release binary:

```bash
kubectl krew install gadget          # or: download kubectl-gadget from the upstream release
kubectl gadget version               # prints client version (and server, once deployed)
```

## 2. Deploy Inspektor Gadget into the cluster

```bash
kubectl gadget deploy                # installs the IG DaemonSet (namespace: gadget)
kubectl get pods -n gadget           # confirm one Running gadget pod per node
```

`kubectl gadget deploy` starts a privileged DaemonSet that loads the eBPF
programs on each node and streams enriched events back to your `kubectl gadget
run` client. To remove it:

```bash
kubectl gadget undeploy
```

## 3. Requirements

- **Kernel with BTF** — most modern distros ship it; verify a node has
  `/sys/kernel/btf/vmlinux`. IG uses CO-RE (Compile Once, Run Everywhere) and
  needs BTF to relocate against the running kernel.
- **Privileges** — the DaemonSet runs privileged (CAP_BPF / CAP_SYS_ADMIN) to
  load eBPF. Deploy it in clusters where you have troubleshooting rights.
- **Version matching** — keep the `kubectl gadget` client and the deployed
  DaemonSet on the same IG version. A "built with vX, running vY" message is a
  **warning**, not a failure; the run still produces data, but match versions
  when you can to avoid field/flag skew.
- **"Server version: not available" is not a blocker.** `kubectl gadget version`
  printing `Server version: not available` only means the version probe didn't
  answer — **try `kubectl gadget run …` anyway**; it usually still works. Only if
  the run itself errors on connectivity, check `kubectl get pods -n gadget`; and
  only if the DaemonSet pod isn't `Running` do you fall back to `sudo ig run` on a
  single node.

## 4. Sanity check

```bash
kubectl gadget run trace_exec:latest -A --timeout 5 -o json   # should stream a few exec events
```

If this hangs or errors on connectivity, re-check `kubectl get pods -n gadget`
and your kubeconfig context. If it errors on image signature, you likely have a
locally-built image shadowing the upstream one — pull the upstream image (see
`common-flags.md` → gotchas).
