// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// IG-AUDIT-2026-13: constrain GadgetInstance paramValues.

package validation

import (
	"fmt"
	"strings"
)

// ForbiddenGadgetInstanceParams returns an error if a GadgetInstance sets a
// security-sensitive param via its paramValues map.
func ValidateGadgetInstanceParamValues(pv map[string]string) error {
	for k := range pv {
		lk := strings.ToLower(k)
		if lk == "operator.oci.verify-image" ||
			lk == "operator.oci.public-keys" ||
			lk == "operator.oci.insecure-registries" ||
			strings.Contains(lk, "verify-image") {
			return fmt.Errorf("paramValue %q forbidden in GadgetInstance CR", k)
		}
	}
	return nil
}
