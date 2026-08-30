// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 The Inspektor Gadget authors

package main

import "testing"

func TestValidateUprobeRateParameters(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		sample     string
		rollup     string
		wantSample uint64
		wantRollup uint64
		wantError  bool
	}{
		{name: "ordinary paired", mode: "uprobe_uretprobe", sample: "1", rollup: "1", wantSample: 1, wantRollup: 1},
		{name: "single-sided sampling", mode: "uprobe", sample: "100", rollup: "1", wantSample: 100, wantRollup: 1},
		{name: "paired rollup", mode: "uprobe_uretprobe", sample: "1", rollup: "1000", wantSample: 1, wantRollup: 1000},
		{name: "zero sample", mode: "uprobe", sample: "0", rollup: "1", wantError: true},
		{name: "non-integer rollup", mode: "uprobe_uretprobe", sample: "1", rollup: "many", wantError: true},
		{name: "paired sampling", mode: "uprobe_uretprobe", sample: "10", rollup: "1", wantError: true},
		{name: "single-sided rollup", mode: "uretprobe", sample: "1", rollup: "10", wantError: true},
		{name: "sampling and rollup", mode: "uprobe_uretprobe", sample: "10", rollup: "10", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sample, rollup, err := validateUprobeRateParameters(tt.mode, tt.sample, tt.rollup)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected validation error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if sample != tt.wantSample || rollup != tt.wantRollup {
				t.Fatalf("got sample=%d rollup=%d, want sample=%d rollup=%d",
					sample, rollup, tt.wantSample, tt.wantRollup)
			}
		})
	}
}
