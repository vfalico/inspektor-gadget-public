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

package tests

import (
	"testing"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
)

// TestNvidiaTraceErrorsUnit is a lightweight unit smoke-test that starts the
// gadget in a short-lived runner and verifies it loads without errors — no
// GPU required. Matches the pattern used by profile_cuda / trace_dns.
func TestNvidiaTraceErrorsUnit(t *testing.T) {
	gadgettesting.DummyGadgetTest(t, "nvidia_trace_errors")
}
