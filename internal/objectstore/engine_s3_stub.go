// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"context"
	"io"
)

// s3StubEngine is the compile-refusing second engine kind (ADR-0010): the
// seam names local-volume AND s3 from day one, and this stub proves the
// Engine interface is satisfiable by the network kind while v0.1 ships
// local-volume only. Every verb refuses with ErrNotImplemented. It is never
// registered or constructed as a usable engine — the full s3 engine (STS
// credential, storage-lane egress per ADR-0011) replaces it on the full
// shelf.
type s3StubEngine struct{}

var _ Engine = (*s3StubEngine)(nil)

func (*s3StubEngine) Kind() EngineKind { return S3 }

func (*s3StubEngine) ProvisionScope(_ context.Context, _ ScopeID) error {
	return ErrNotImplemented
}

func (*s3StubEngine) TeardownScope(_ context.Context, _ ScopeID) error {
	return ErrNotImplemented
}

func (*s3StubEngine) List(_ context.Context, _ ScopeID, _ string) ([]FileInfo, error) {
	return nil, ErrNotImplemented
}

func (*s3StubEngine) Stat(_ context.Context, _ ScopeID, _ string) (FileInfo, error) {
	return FileInfo{}, ErrNotImplemented
}

func (*s3StubEngine) MakeDir(_ context.Context, _ ScopeID, _ string) error {
	return ErrNotImplemented
}

func (*s3StubEngine) MoveDir(_ context.Context, _ ScopeID, _, _ string, _ bool) error {
	return ErrNotImplemented
}

func (*s3StubEngine) RemoveDir(_ context.Context, _ ScopeID, _ string) error {
	return ErrNotImplemented
}

func (*s3StubEngine) CopyFile(_ context.Context, _ ScopeID, _, _ string, _ bool) error {
	return ErrNotImplemented
}

func (*s3StubEngine) MoveFile(_ context.Context, _ ScopeID, _, _ string, _ bool) error {
	return ErrNotImplemented
}

func (*s3StubEngine) RemoveFile(_ context.Context, _ ScopeID, _ string) error {
	return ErrNotImplemented
}

func (*s3StubEngine) ReadRange(_ context.Context, _ ScopeID, _ string, _, _ int64, _ io.Writer) error {
	return ErrNotImplemented
}

func (*s3StubEngine) WriteStream(_ context.Context, _ ScopeID, _ string, _ io.Reader, _ bool) error {
	return ErrNotImplemented
}
