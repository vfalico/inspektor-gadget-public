// Copyright 2024-2025 The Inspektor Gadget authors
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

package sort

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	name        = "sort"
	ParamSortBy = "sort"
	Priority    = 9500
)

type sortOperator struct{}

type arrSort struct {
	datasource.DataArray
	fn func(i, j datasource.Data) bool
}

func (s *arrSort) Less(i, j int) bool {
	return s.fn(s.Get(i), s.Get(j))
}

func (s *sortOperator) Name() string {
	return name
}

func (s *sortOperator) Init(params *params.Params) error {
	return nil
}

func (s *sortOperator) GlobalParams() api.Params {
	return nil
}

func (s *sortOperator) InstanceParams() api.Params {
	return api.Params{
		{
			Key:   ParamSortBy,
			Title: "Sort By",
			Description: "Sort by fields. Join multiple fields with ','. Prefix a field with '-' to sort in descending order. " +
				"If using multiple data sources, prefix fields with 'datasourcename:' and separate with ';'",
			Tags: []string{api.TagGroupDataFiltering},
		},
	}
}

func (s *sortOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	logger := gadgetCtx.Logger()
	logger.Debugf("instantiating %s operator: client=%v, remote_call=%v", name, gadgetCtx.IsClient(), gadgetCtx.IsRemoteCall())

	activate := false

	sortBy := instanceParamValues[ParamSortBy]

	for _, ds := range gadgetCtx.GetDataSources() {
		if ds.Type() == datasource.TypeArray {
			activate = true
			break
		}
	}

	if !activate {
		return nil, nil
	}

	return &sortOperatorInstance{
		sortBy: sortBy,
	}, nil
}

func (s *sortOperator) Priority() int {
	return Priority
}

type sortOperatorInstance struct {
	sortBy  string
	sorters map[datasource.DataSource][]func(i, j datasource.Data) bool
}

func getCompareFunc(f datasource.FieldAccessor, negate bool) func(i, j datasource.Data) bool {
	switch f.Type() {
	case api.Kind_Int8:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Int8(i)
			v2, _ := f.Int8(j)
			return (v1 < v2) != negate
		}
	case api.Kind_Int16:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Int16(i)
			v2, _ := f.Int16(j)
			return (v1 < v2) != negate
		}
	case api.Kind_Int32:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Int32(i)
			v2, _ := f.Int32(j)
			return (v1 < v2) != negate
		}
	case api.Kind_Int64:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Int64(i)
			v2, _ := f.Int64(j)
			return (v1 < v2) != negate
		}
	case api.Kind_Uint8:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Uint8(i)
			v2, _ := f.Uint8(j)
			return (v1 < v2) != negate
		}
	case api.Kind_Uint16:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Uint16(i)
			v2, _ := f.Uint16(j)
			return (v1 < v2) != negate
		}
	case api.Kind_Uint32:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Uint32(i)
			v2, _ := f.Uint32(j)
			return (v1 < v2) != negate
		}
	case api.Kind_Uint64:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Uint64(i)
			v2, _ := f.Uint64(j)
			return (v1 < v2) != negate
		}
	case api.Kind_Float32:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Float32(i)
			v2, _ := f.Float32(j)
			return (v1 < v2) != negate
		}
	case api.Kind_Float64:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Float64(i)
			v2, _ := f.Float64(j)
			return (v1 < v2) != negate
		}
	case api.Kind_String, api.Kind_CString:
		return func(i, j datasource.Data) bool {
			v1, _ := f.String(i)
			v2, _ := f.String(j)
			if strings.Compare(v1, v2) < 0 {
				return !negate
			}
			return negate
		}
	default:
		return nil
	}
}

func (s *sortOperatorInstance) getFieldsByDs() map[string][]string {
	dsSorts := make(map[string][]string)
	for _, srt := range strings.Split(s.sortBy, ";") {
		dsFields := strings.Split(srt, ":")
		dsName := ""
		fieldList := dsFields[0]
		if len(dsFields) == 2 {
			dsName = dsFields[0]
			fieldList = dsFields[1]
		}
		fields := strings.Split(fieldList, ",")
		if len(fields) > 2 || fields[0] != "" {
			dsSorts[dsName] = append(dsSorts[dsName], fields...)
		}
	}
	return dsSorts
}

func (s *sortOperatorInstance) init(gadgetCtx operators.GadgetContext) error {
	s.sorters = make(map[datasource.DataSource][]func(i datasource.Data, j datasource.Data) bool)
	dsSorts := s.getFieldsByDs()

	// Check edge cases
	dsSpecific := true
	if _, ok := dsSorts[""]; ok {
		if len(dsSorts) > 1 {
			return fmt.Errorf("mixing sorting rules with and without specifying data source")
		}
		dsSpecific = false
	}

	for _, ds := range gadgetCtx.GetDataSources() {
		sortFields := dsSorts[ds.Name()]
		if !dsSpecific {
			sortFields = dsSorts[""]
		}

		if len(sortFields) == 0 {
			continue
		}

		if ds.Type() != datasource.TypeArray {
			// sort is meaningless on a non-array data source. Degrade
			// gracefully: WARN and skip ordering this data source instead of
			// hard-failing the whole gadget run. The message distinguishes the
			// two non-array cases and points streaming callers at the
			// server-side ranking they already have.
			gadgetCtx.Logger().Warnf("sort ignored for data source %q: applies "+
				"only to array (rankable) sources, and %q is not one. If %q is a "+
				"high-volume STREAMING source, the server already emits a "+
				"<topGroups key=...> block with the dominant keys over the full "+
				"pre-truncation set — read that instead. If it is a single-row "+
				"snapshot there is nothing to order.", ds.Name(), ds.Name(), ds.Name())
			continue
		}

		var sortFuncs []func(i, j datasource.Data) bool
		skipDS := false
		for _, fieldName := range sortFields {
			rawField := fieldName
			fieldName, negate := strings.CutPrefix(fieldName, "-")

			field := ds.GetField(fieldName)
			if field == nil {
				// A GLOBAL (non-ds-specific) sort rule is applied to EVERY data
				// source, so a key that lives in one capability's source (e.g.
				// runq_ns in mep_runq) naturally will not exist in the others.
				// Missing field is therefore NOT fatal: WARN and leave THIS data
				// source unsorted instead of hard-failing the whole gadget run —
				// the caller still gets every source's rows (just unordered where
				// the key is absent). A ds-specific rule that names a real ds but
				// a missing field is the caller's targeting mistake, yet killing
				// all OTHER sources' output over it is still the wrong trade, so
				// we warn and skip there too (the warning still names the typo).
				gadgetCtx.Logger().Warnf("sort key %q not found in data source "+
					"%q; leaving %q unsorted (the field belongs to a different "+
					"capability's data source). Other data sources are "+
					"unaffected and still returned.", rawField, ds.Name(), ds.Name())
				skipDS = true
				break
			}

			cmp := getCompareFunc(field, negate)
			if cmp == nil {
				// Field exists but is not an orderable scalar. Same trade: warn
				// and leave this source unsorted rather than abort the run.
				gadgetCtx.Logger().Warnf("sort key %q in data source %q is not an "+
					"orderable type; leaving %q unsorted.", rawField, ds.Name(), ds.Name())
				skipDS = true
				break
			}
			sortFuncs = append(sortFuncs, cmp)
		}
		if skipDS {
			continue
		}

		slices.Reverse(sortFuncs)
		s.sorters[ds] = sortFuncs
	}
	return nil
}

func (s *sortOperatorInstance) Name() string {
	return name
}

func (s *sortOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	err := s.init(gadgetCtx)
	if err != nil {
		return err
	}
	for ds, fns := range s.sorters {
		ds.SubscribeArray(func(ds datasource.DataSource, data datasource.DataArray) error {
			for _, s := range fns {
				sort.Stable(&arrSort{DataArray: data, fn: s})
			}
			return nil
		}, Priority)
	}
	return nil
}

func (s *sortOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (s *sortOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (s *sortOperatorInstance) Close(gadgetCtx operators.GadgetContext) error {
	return nil
}

var Operator = &sortOperator{}

func init() {
	operators.RegisterDataOperator(Operator)
}
