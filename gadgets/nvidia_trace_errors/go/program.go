// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main is the WASM enricher for the nvidia_trace_errors gadget.
// Subsequent patches populate the error catalog, argument heuristics and the
// subscription callback; this skeleton only wires the datasource handles so
// that the gadget is buildable and `git bisect` remains clean.
package main

import (
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

var (
	dsErrors api.DataSource

	fSourceRaw    api.Field
	fErrorCodeRaw api.Field
	fAPIIDRaw     api.Field
	fXidCode      api.Field
	fPCIDomain    api.Field
	fPCIBus       api.Field
	fPCISlot      api.Field
	fPCIFunc      api.Field
	fArg1         api.Field
	fArg2         api.Field
	fArg3         api.Field
	fArg4         api.Field
	fArg5         api.Field
	fArg6         api.Field

	// Derived string fields added by the enricher.
	fErrorName  api.Field
	fAPIName    api.Field
	fSourceName api.Field
	fSeverity   api.Field
	fCategory   api.Field
	fDesc       api.Field
	fWhy        api.Field
	fSuggestion api.Field
	fContext    api.Field
	fGPUAddr    api.Field
)

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	var err error

	dsErrors, err = api.GetDataSource("nvidia_errors")
	if err != nil {
		api.Warnf("nvidia_trace_errors: datasource: %v", err)
		return 1
	}

	if err = bindRawFields(); err != nil {
		api.Warnf("nvidia_trace_errors: bind raw: %v", err)
		return 1
	}
	if err = addDerivedFields(); err != nil {
		api.Warnf("nvidia_trace_errors: add derived: %v", err)
		return 1
	}

	dsErrors.Subscribe(enrich, 0)
	return 0
}

func bindRawFields() error {
	var err error
	for _, b := range []struct {
		f    *api.Field
		name string
	}{
		{&fSourceRaw, "source_raw"},
		{&fErrorCodeRaw, "error_code_raw"},
		{&fAPIIDRaw, "api_id_raw"},
		{&fXidCode, "xid_code"},
		{&fPCIDomain, "pci_domain"},
		{&fPCIBus, "pci_bus"},
		{&fPCISlot, "pci_slot"},
		{&fPCIFunc, "pci_func"},
		{&fArg1, "arg1"}, {&fArg2, "arg2"}, {&fArg3, "arg3"},
		{&fArg4, "arg4"}, {&fArg5, "arg5"}, {&fArg6, "arg6"},
	} {
		*b.f, err = dsErrors.GetField(b.name)
		if err != nil {
			return err
		}
	}
	return nil
}

func addDerivedFields() error {
	var err error
	for _, b := range []struct {
		f    *api.Field
		name string
	}{
		{&fErrorName, "error_code"},
		{&fAPIName, "api_id"},
		{&fSourceName, "source"},
		{&fSeverity, "severity"},
		{&fCategory, "category"},
		{&fDesc, "description"},
		{&fWhy, "why"},
		{&fSuggestion, "suggestion"},
		{&fContext, "context_info"},
		{&fGPUAddr, "gpu_pci_addr"},
	} {
		*b.f, err = dsErrors.AddField(b.name, api.Kind_String)
		if err != nil {
			return err
		}
	}
	return nil
}

// enrich is replaced with the real catalog lookup in patch 0005 and argument
// heuristics in patch 0006. In this skeleton it only sets the source label so
// the gadget produces usable output from the first commit of the series.
func enrich(source api.DataSource, data api.Data) {
	src, _ := fSourceRaw.Uint32(data)
	switch src {
	case 1:
		fSourceName.SetString(data, "SOURCE_CUDA_API")
	case 2:
		fSourceName.SetString(data, "SOURCE_XID")
	default:
		fSourceName.SetString(data, "SOURCE_UNKNOWN")
	}
}

func main() {}
