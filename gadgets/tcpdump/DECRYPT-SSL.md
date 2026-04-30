# tcpdump --decrypt-ssl

## Overview

The `--decrypt-ssl` flag enables in-gadget SSL/TLS/SSH decryption by
attaching uprobes to userspace cryptographic libraries. Plaintext is
injected into the pcap as synthetic Ethernet/IPv4/TCP frames marked
with `eth.src=02:49:47:00:00:01` and TCP option `0xFD "IGDC"`.

## Usage

```bash
# Host mode (required for --host uprobe attachment):
sudo ig run ghcr.io/inspektor-gadget/gadget/tcpdump:latest \
  --decrypt-ssl --host --iface lo -o pcap-ng > capture.pcap

# Verify plaintext:
strings capture.pcap | grep "$PAYLOAD"

# Filter synth frames in Wireshark:
# Display filter: eth.src == 02:49:47:00:00:01
```

## Supported libraries

| Library   | Symbols hooked                      |
|-----------|-------------------------------------|
| OpenSSL   | SSL_read, SSL_write, SSL_read_ex, SSL_write_ex, SSL_set_fd |
| BoringSSL | SSL_read, SSL_write                 |
| GnuTLS    | gnutls_record_send, gnutls_record_recv |
| NSS       | PR_Read, PR_Write, PR_Send, PR_Recv |
| OpenSSH   | sshbuf_put_string, sshbuf_get_string |

## OpenSSH notes

OpenSSH binaries are typically stripped. Install debug symbols:

```bash
# Ubuntu/Debian:
sudo apt install openssh-server-dbgsym
```

The uprobe tracer will gracefully skip attachment if symbols are not
found in the binary.

## Regression

When `--decrypt-ssl` is not set (default), no uprobes are attached and
the verifier dead-code-eliminates all synth-frame emission paths. The
pcap output is byte-identical to the upstream tcpdump gadget.
