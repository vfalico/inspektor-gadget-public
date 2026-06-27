package filter

import (
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// Prove that a bare leaf filter key written as
// `comm==X` transparently resolves to the nested `proc.comm` field that the
// streaming gadgets actually expose, instead of aborting with the -32603
// "field not found" the live case hit. Also prove the
// enumerated-fields diagnostic lists the real dotted name when the key is
// genuinely absent.

// buildProcDS registers a datasource that nests comm/pid under a "proc" parent
// (proc.comm, proc.pid) plus a top-level "bytes" field — mirroring the shape of
// mep_net / mep_lock / trace_syscall, where the failure occurred.
func buildProcDS(t *testing.T, ds *datasource.DataSource, commVal string, bytesVal int64) (
	prepare func(operators.GadgetContext) error,
	produce func(operators.GadgetContext) error,
) {
	var commField, bytesField datasource.FieldAccessor
	prepare = func(gadgetCtx operators.GadgetContext) error {
		var err error
		*ds, err = gadgetCtx.RegisterDataSource(datasource.TypeSingle, "mep_net")
		require.NoError(t, err)
		proc, err := (*ds).AddField("proc", api.Kind_Invalid)
		require.NoError(t, err)
		commField, err = proc.AddSubField("comm", api.Kind_String)
		require.NoError(t, err)
		_, err = proc.AddSubField("pid", api.Kind_Uint32)
		require.NoError(t, err)
		bytesField, err = (*ds).AddField("bytes", api.Kind_Int64)
		require.NoError(t, err)
		return nil
	}
	produce = func(gadgetCtx operators.GadgetContext) error {
		data, err := (*ds).NewPacketSingle()
		require.NoError(t, err)
		require.NoError(t, commField.PutString(data, commVal))
		require.NoError(t, bytesField.PutInt64(data, bytesVal))
		require.NoError(t, (*ds).EmitAndRelease(data))
		return nil
	}
	return prepare, produce
}

// Bare `comm==target` must KEEP a matching row (alias -> proc.comm) and DROP a
// non-matching one. If alias resolution regressed, addFilter would error out
// (field not found) and the test would fail at the Tester() error check.
func TestFilter_BareCommAliasResolvesToProcComm(t *testing.T) {
	for _, tc := range []struct {
		name    string
		comm    string
		wantRow bool
	}{
		{"match", "DIAG_case04", true},
		{"nomatch", "kworker/3:1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ds datasource.DataSource
			var rows int
			var mu sync.Mutex
			prepare, produce := buildProcDS(t, &ds, tc.comm, 4096)
			err := Tester(
				t, &filterOperator{},
				api.ParamValues{"operator.filter.filter": "comm==DIAG_case04"},
				prepare, produce,
				func(gadgetCtx operators.GadgetContext) error {
					return ds.Subscribe(func(datasource.DataSource, datasource.Data) error {
						mu.Lock()
						rows++
						mu.Unlock()
						return nil
					}, Priority+1)
				},
			)
			require.NoError(t, err, "bare comm filter must NOT error (alias must resolve to proc.comm)")
			if tc.wantRow {
				assert.Equal(t, 1, rows, "matching comm row must survive bare-comm alias filter")
			} else {
				assert.Equal(t, 0, rows, "non-matching comm row must be dropped by bare-comm alias filter")
			}
		})
	}
}

// A genuinely-absent field must produce the enumerated-fields diagnostic that
// lists the real dotted names, so the agent self-corrects in one retry.
func TestFilter_UnknownFieldEnumeratesAvailable(t *testing.T) {
	var ds datasource.DataSource
	prepare, produce := buildProcDS(t, &ds, "x", 1)
	err := Tester(
		t, &filterOperator{},
		api.ParamValues{"operator.filter.filter": "nosuchfield==1"},
		prepare, produce,
		func(gadgetCtx operators.GadgetContext) error { return nil },
	)
	require.Error(t, err, "unknown field must still error")
	msg := err.Error()
	assert.Contains(t, msg, "available filterable fields:", "error must enumerate available fields")
	assert.True(t, strings.Contains(msg, "proc.comm"),
		"enumerated fields must include the real dotted name proc.comm; got: "+msg)
}
