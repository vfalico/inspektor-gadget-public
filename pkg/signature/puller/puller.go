// Copyright 2025 The Inspektor Gadget authors
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

package puller

import (
	"context"
	"errors"
	"fmt"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/puller/bundle"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/puller/cosign"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/puller/oci11"
)

type Puller interface {
	PullSigningInformation(ctx context.Context, repo *remote.Repository, imageStore oras.Target, digest string) error
	Name() string
}

// ErrSignatureNotFound indicates that all supported signature formats were
// checked and none was present. It never represents authentication, transport,
// registry, malformed-artifact, or cryptographic verification failures.
var ErrSignatureNotFound = errors.New("signature not found")

type SignaturePuller struct {
	pullers []Puller
}

var DefaultSignaturePuller = SignaturePuller{
	pullers: []Puller{
		&cosign.Puller{},
		&oci11.Puller{},
		&bundle.Puller{},
	},
}

func (p *SignaturePuller) PullSigningInformation(ctx context.Context, repo *remote.Repository, imageStore oras.Target, digest string) error {
	if len(p.pullers) == 0 {
		return errors.New("no pulling method available")
	}

	errs := make([]error, 0)
	for _, puller := range p.pullers {
		err := puller.PullSigningInformation(ctx, repo, imageStore, digest)
		if err == nil {
			return nil
		}

		wrappedErr := fmt.Errorf("pulling signing information with %s: %w", puller.Name(), err)
		if !isSignatureAbsent(err) {
			return wrappedErr
		}
		errs = append(errs, wrappedErr)
	}

	return &signatureNotFoundError{causes: errs}
}

type signatureNotFoundError struct {
	causes []error
}

func (e *signatureNotFoundError) Error() string {
	return ErrSignatureNotFound.Error()
}

func (e *signatureNotFoundError) Is(target error) bool {
	return target == ErrSignatureNotFound
}

// Details returns per-format lookup failures for verbose diagnostics.
func (e *signatureNotFoundError) Details() []error {
	return append([]error(nil), e.causes...)
}

func isSignatureAbsent(err error) bool {
	return errors.Is(err, errdef.ErrNotFound) || errors.Is(err, helpers.ErrReferrerNotFound)
}
