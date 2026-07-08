---
title: 'Gadget gRPC API'
sidebar_position: 30
description: 'Reference documentation for the gRPC API'
---

Inspektor Gadget exposes a gRPC API that lets clients run gadgets, manage
long-running gadget instances, and query information about a running Inspektor
Gadget deployment. This is the same API used internally by `kubectl gadget` and
by `ig` when it runs as a daemon (`ig daemon`). A client connects to the gadget
service (over a Unix socket, TCP, or the Kubernetes API server for
`kubectl gadget`) and drives gadgets through the services described below.

## api.proto

The API is defined in the following protobuf file:

[pkg/gadget-service/api/api.proto](https://github.com/inspektor-gadget/inspektor-gadget/blob/%IG_BRANCH%/pkg/gadget-service/api/api.proto)

It provides the following gRPC services:

- `GadgetManager`: run gadgets and query gadget metadata. `RunGadget` is a
  bidirectional streaming RPC that streams control requests from the client to
  the server and streams gadget events back to the client; `GetGadgetInfo`
  returns a gadget's data sources, fields and parameters without running it.
- `GadgetInstanceManager`: create, list, get and remove persistent *gadget
  instances* — gadgets that keep running in the background and can be attached
  to later.
- `BuiltInGadgetManager`: `GetInfo` returns information about the Inspektor
  Gadget deployment itself.

Refer to the `.proto` file for the full list of request and response messages.
