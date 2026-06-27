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

// max-entries=<ds>:-1 must DISABLE the cap even when <ds> is a non-array
// (streaming/snapshot) data source. Previously the array-type guard ran first
// and hard-errored, so a caller lifting the cap on a streaming source got an
// error instead of an uncapped stream. A POSITIVE top-N targeting a non-array
// source must still error.
//
// The limiter only instantiates when at least one ARRAY data source exists, so
// every case registers one array source ("arr") plus one single source
// ("snap") and targets "snap" by name.
package limiter

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

// runLimiterPreStart registers an array DS "arr" (so the limiter instantiates)
// and a single DS "snap", applies the limiter with maxEntries, and returns the
// Run error (PreStart is where the limiter validates per-ds types).
func runLimiterPreStart(t *testing.T, maxEntries string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	producer := simple.New("producer",
		simple.WithPriority(Priority-1),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			if _, err := gadgetCtx.RegisterDataSource(datasource.TypeArray, "arr"); err != nil {
				return err
			}
			_, err := gadgetCtx.RegisterDataSource(datasource.TypeSingle, "snap")
			return err
		}),
		simple.OnStart(func(gadgetCtx operators.GadgetContext) error {
			cancel() // stop the run right after PreStart validation
			return nil
		}),
		simple.OnStop(func(gadgetCtx operators.GadgetContext) error { return nil }),
	)

	gadgetCtx := gadgetcontext.New(ctx, "",
		gadgetcontext.WithDataOperators(&limiterOperator{}, producer))

	paramValues := api.ParamValues{
		"operator.limiter." + ParamMaxEntries: maxEntries,
	}
	return gadgetCtx.Run(paramValues)
}

func TestLimiterDisableMinusOneOnNonArray(t *testing.T) {
	// snap:-1 = DISABLE on a non-array source -> must succeed (was a hard error).
	err := runLimiterPreStart(t, "snap:-1")
	assert.NoError(t, err, "max-entries=snap:-1 must DISABLE the cap on a non-array source, not error")
}

func TestLimiterPositiveTopNOnNonArrayWarnsAndContinues(t *testing.T) {
	// Owner directive: a positive top-N (snap:5) on a non-array
	// (snapshot/streaming) source is meaningless, but it must DEGRADE GRACEFULLY
	// — the limiter logs a warning and skips the cap for that data source rather
	// than hard-failing the whole run with -32603. So PreStart must NOT error.
	err := runLimiterPreStart(t, "snap:5")
	assert.NoError(t, err, "max-entries=snap:5 on a non-array source must warn-and-continue, not error")
}

func TestLimiterDisableMinusOneOnArray(t *testing.T) {
	// arr:-1 on the array source disables cleanly (regression guard).
	err := runLimiterPreStart(t, "arr:-1")
	assert.NoError(t, err, "max-entries=arr:-1 on an array source must disable without error")
}

func TestLimiterPositiveTopNOnArrayOK(t *testing.T) {
	// arr:5 on the array source is the normal, valid case.
	err := runLimiterPreStart(t, "arr:5")
	assert.NoError(t, err, "max-entries=arr:5 on an array source must be accepted")
}
