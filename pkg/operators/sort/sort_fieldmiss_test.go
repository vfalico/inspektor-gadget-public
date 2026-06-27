package sort

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

// TestSortGlobalKeyMissingFromArrayWarnsAndContinues reproduces the missing-key case
// id=5: a GLOBAL (non-ds-specific) sort rule like "-runq_ns" is applied to
// EVERY data source. The key exists in mep_runq but NOT in some other ARRAY
// source — previously the field-resolution loop hard-returned
// `field runq_ns not found`, aborting the WHOLE gadget run (wire -32603). It
// must instead WARN and leave that one source unsorted while every other
// source is still returned.
func TestSortGlobalKeyMissingFromArrayWarnsAndContinues(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	producer := simple.New("producer",
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			// ARRAY source that does NOT carry the global sort key "runq_ns".
			ds, err := gadgetCtx.RegisterDataSource(datasource.TypeArray, "other")
			require.NoError(t, err)
			_, err = ds.AddField("cpu", api.Kind_Uint32)
			require.NoError(t, err)
			return nil
		}),
		simple.OnStop(func(gadgetCtx operators.GadgetContext) error { return nil }),
	)

	gadgetCtx := gadgetcontext.New(ctx, "",
		gadgetcontext.WithDataOperators(&sortOperator{}, producer))

	// GLOBAL sort rule (no ds: prefix) on a field absent from "other".
	paramValues := api.ParamValues{
		"operator.sort." + ParamSortBy: "-runq_ns",
	}
	err := gadgetCtx.Run(paramValues)
	assert.NoError(t, err, "a global sort key missing from one array source must warn-and-skip that source, not abort the run with -32603")
}
