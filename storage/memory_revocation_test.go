// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
)

func newRevocationRequest(id string) fosite.Requester {
	return &fosite.Request{
		ID:     id,
		Client: &fosite.DefaultClient{ID: "my-client"},
	}
}

func TestMemoryStoreOneToManyAccessTokens(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	const requestID = "request-id"
	const firstSignature = "access-signature-1"
	const secondSignature = "access-signature-2"

	require.NoError(t, store.CreateAccessTokenSession(ctx, firstSignature, newRevocationRequest(requestID)))
	require.NoError(t, store.CreateAccessTokenSession(ctx, secondSignature, newRevocationRequest(requestID)))

	// Both access tokens of the same authorization must be stored and addressable by signature.
	_, err := store.GetAccessTokenSession(ctx, firstSignature, nil)
	require.NoError(t, err)
	_, err = store.GetAccessTokenSession(ctx, secondSignature, nil)
	require.NoError(t, err)

	// Deleting one token by its signature must not touch the other token.
	require.NoError(t, store.DeleteAccessTokenSession(ctx, firstSignature))
	_, err = store.GetAccessTokenSession(ctx, firstSignature, nil)
	require.ErrorIs(t, err, fosite.ErrNotFound)
	_, err = store.GetAccessTokenSession(ctx, secondSignature, nil)
	require.NoError(t, err)

	// The index must be cleaned up only once the last signature of the grant is gone.
	assert.Contains(t, store.AccessTokenRequestIDs, requestID)
	require.NoError(t, store.DeleteAccessTokenSession(ctx, secondSignature))
	assert.NotContains(t, store.AccessTokenRequestIDs, requestID)
}

func TestMemoryStoreRevokeAccessTokenCascadesOverWholeGrant(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	const requestID = "request-id"
	signatures := []string{"access-signature-1", "access-signature-2"}
	for _, signature := range signatures {
		require.NoError(t, store.CreateAccessTokenSession(ctx, signature, newRevocationRequest(requestID)))
	}

	require.NoError(t, store.RevokeAccessToken(ctx, requestID))

	for _, signature := range signatures {
		_, err := store.GetAccessTokenSession(ctx, signature, nil)
		require.ErrorIs(t, err, fosite.ErrNotFound)
	}
	assert.NotContains(t, store.AccessTokenRequestIDs, requestID)
}

func TestMemoryStoreOneToManyRefreshTokens(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	const requestID = "request-id"
	const firstSignature = "refresh-signature-1"
	const secondSignature = "refresh-signature-2"

	require.NoError(t, store.CreateRefreshTokenSession(ctx, firstSignature, "access-signature-1", newRevocationRequest(requestID)))
	require.NoError(t, store.CreateRefreshTokenSession(ctx, secondSignature, "access-signature-2", newRevocationRequest(requestID)))

	// Both refresh tokens of the same authorization must be stored and addressable by signature.
	_, err := store.GetRefreshTokenSession(ctx, firstSignature, nil)
	require.NoError(t, err)
	_, err = store.GetRefreshTokenSession(ctx, secondSignature, nil)
	require.NoError(t, err)

	// Deleting one token by its signature must not touch the other token.
	require.NoError(t, store.DeleteRefreshTokenSession(ctx, firstSignature))
	_, err = store.GetRefreshTokenSession(ctx, firstSignature, nil)
	require.ErrorIs(t, err, fosite.ErrNotFound)
	_, err = store.GetRefreshTokenSession(ctx, secondSignature, nil)
	require.NoError(t, err)

	// The index must be cleaned up only once the last signature of the grant is gone.
	assert.Contains(t, store.RefreshTokenRequestIDs, requestID)
	require.NoError(t, store.DeleteRefreshTokenSession(ctx, secondSignature))
	assert.NotContains(t, store.RefreshTokenRequestIDs, requestID)
}

func TestMemoryStoreRevokeRefreshTokenCascadesOverWholeGrant(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	const requestID = "request-id"
	signatures := []string{"refresh-signature-1", "refresh-signature-2"}
	for _, signature := range signatures {
		require.NoError(t, store.CreateRefreshTokenSession(ctx, signature, "access-signature", newRevocationRequest(requestID)))
	}

	require.NoError(t, store.RevokeRefreshToken(ctx, requestID))

	// Every refresh token of the grant is inactive, the sessions themselves are kept.
	for _, signature := range signatures {
		_, err := store.GetRefreshTokenSession(ctx, signature, nil)
		require.ErrorIs(t, err, fosite.ErrInactiveToken)
		assert.Contains(t, store.RefreshTokens, signature)
	}
}

func TestMemoryStoreRevocationOfUnknownGrantIsANoOp(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	assert.NoError(t, store.RevokeAccessToken(ctx, "unknown-request-id"))
	assert.NoError(t, store.RevokeRefreshToken(ctx, "unknown-request-id"))
	assert.NoError(t, store.DeleteAccessTokenSession(ctx, "unknown-signature"))
	assert.NoError(t, store.DeleteRefreshTokenSession(ctx, "unknown-signature"))
}
