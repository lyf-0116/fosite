// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"

	"github.com/ory/fosite"
)

type PKCERequestStorage interface {
	GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error)
	CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error
	DeletePKCERequestSession(ctx context.Context, signature string) error
}

// AtomicPKCERequestStorage is an optional storage implementation that can
// atomically consume a PKCE request session. ConsumePKCERequestSession must
// delete the session only when it exists and return fosite.ErrNotFound when it
// has already been consumed. This prevents concurrent token requests from both
// passing verification and consuming the same PKCE session.
type AtomicPKCERequestStorage interface {
	PKCERequestStorage
	ConsumePKCERequestSession(ctx context.Context, signature string) error
}
