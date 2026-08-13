// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package helpers

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/content/oci"
)

func TestFindReferrerTagClassifiesAbsence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := oci.New(t.TempDir())
	require.NoError(t, err)
	blob := []byte(`{"schemaVersion":2}`)
	desc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(blob), Size: int64(len(blob))}
	require.NoError(t, store.Push(ctx, desc, bytes.NewReader(blob)))
	require.NoError(t, store.Tag(ctx, desc, "image:latest"))

	_, err = FindBundleTag(ctx, store, desc.Digest.String())
	require.ErrorIs(t, err, ErrReferrerNotFound)
}

func TestFindOCI11SignatureTagPreservesResolveFailure(t *testing.T) {
	t.Parallel()
	store, err := oci.New(t.TempDir())
	require.NoError(t, err)

	_, err = FindOCI11SignatureTag(context.Background(), store, digest.FromString("missing").String())
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrReferrerNotFound)
	require.Contains(t, err.Error(), "finding cosign referrer")
}

func TestFindReferrerTagPreservesCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store, err := oci.New(t.TempDir())
	require.NoError(t, err)

	_, err = FindBundleTag(ctx, store, digest.FromString("missing").String())
	require.Error(t, err)
	require.True(t, errors.Is(err, context.Canceled) || !errors.Is(err, ErrReferrerNotFound))
}
