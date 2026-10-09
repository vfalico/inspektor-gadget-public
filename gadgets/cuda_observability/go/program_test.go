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

package main

import "testing"

func TestParseHeuristicsStrict(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
		err  bool
	}{{"", false, false}, {"false", false, false}, {"TRUE", true, false}, {"yes", false, true}, {"0", false, true}} {
		got, err := parseHeuristics(tc.in)
		if got != tc.want || (err != nil) != tc.err {
			t.Fatalf("parseHeuristics(%q)=(%v,%v), want (%v,error=%v)", tc.in, got, err, tc.want, tc.err)
		}
	}
}

func TestEmitRoutingCoversAllRecordKinds(t *testing.T) {
	// Keep the datasource-routing contract explicit: summaries and health events
	// must not be delivered through the activity datasource.
	for _, tc := range []struct{ typ, want string }{
		{"activity_summary", "summary"},
		{"analyzer_health", "health"},
		{"decode_candidate", "activity"},
	} {
		got := recordRoute(tc.typ)
		if got != tc.want {
			t.Fatalf("route(%s)=%s want %s", tc.typ, got, tc.want)
		}
	}
}
