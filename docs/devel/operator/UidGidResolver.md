---
title: UidGidResolver
sidebar_position: 100
description: >
  Resolving UID and GID to username and groupname
---

# UidGidResolver

The `UidGidResolver` resolves user ids and group ids to their corresponding names.

This is done by reading `/etc/passwd` and `/etc/group` on the host.
Therefore any `UID` inside a container might not properly match the username inside the container.
Since the path is hardcoded usernames provided through `ldap`, `nss-systemd`, systemd units with `DynamicUser=yes`, ... will not be resolved correctly.

## Usage

### Classic gadgets

1. Implement the UidResolverInterface for the `event struct` to resolve a UID.
   The `UID` which is returned by `GetUid()` will be resolved to the corresponding username and is passed into `SetUserName(...)`
    ```go
    type UidResolverInterface interface {
      GetUid() uint32
      SetUserName(string)
    }
    ```
2. Implement the GidResolverInterface for the `event struct` to a resolve GID.
   The `GID` which is returned by `GetGid()` will be resolved to the corresponding groupname and is passed into `SetGroupName(...)`
    ```go
    type GidResolverInterface interface {
      GetGid() uint32
      SetGroupName(string)
    }
    ```

### Image based gadgets

For image-based gadgets no interface has to be implemented: resolution happens
automatically. The operator inspects every data source and enriches any field
that carries the well-known UID/GID types. Declare the relevant eBPF fields with
the enriched types `gadget_uid` and `gadget_gid` (see
[Enriched types](../../gadget-devel/gadget-ebpf-api.md#enriched-types)); the
resolver then adds a companion string field holding the resolved name. By
default these added fields are named `user` and `group`. The name of the added
field can be overridden through the field's annotations understood by the
operator (`uidgidresolver.uid` / `uidgidresolver.gid`, with `uidgidresolver.target`
naming the target field).
