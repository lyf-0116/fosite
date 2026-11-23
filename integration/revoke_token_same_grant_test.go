// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/parnurzeal/gorequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/hmac"
)

// TestRevokeAccessTokenOfGrantWithMultipleAccessTokens reproduces the scenario where a single
// authorization grant owns more than one access token. The named token must always be revoked
// (rather than some other token that happened to overwrite its index entry) and the revocation
// cascades over every access token of the same grant through the request ID index.
func TestRevokeAccessTokenOfGrantWithMultipleAccessTokens(t *testing.T) {
	config := &fosite.Config{GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows")}
	strategy := oauth2.NewHMACSHAStrategy(
		&hmac.HMACStrategy{Config: config},
		config,
	)

	f := compose.Compose(config, fositeStore, strategy,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory)
	ts := mockServer(t, f, &fosite.DefaultSession{})
	defer ts.Close()

	oauthClient := newOAuth2AppClient(ts)

	// Issue two access tokens that share the same authorization request ID.
	firstToken, err := oauthClient.Token(context.Background())
	require.NoError(t, err)

	firstSignature := strategy.AccessTokenSignature(context.Background(), firstToken.AccessToken)
	firstRequest, err := fositeStore.GetAccessTokenSession(context.Background(), firstSignature, nil)
	require.NoError(t, err)

	// A second access token issued for the very same authorization grant. It reuses the request
	// ID and session of the first token, exactly as the refresh and authorization-code flows do.
	secondRequest := &fosite.Request{
		ID:           firstRequest.GetID(),
		RequestedAt:  firstRequest.GetRequestedAt(),
		Client:       firstRequest.GetClient(),
		GrantedScope: firstRequest.GetGrantedScopes(),
		Session:      firstRequest.GetSession().Clone(),
	}
	secondAccessToken, secondSignature, err := strategy.GenerateAccessToken(context.Background(), secondRequest)
	require.NoError(t, err)
	require.NoError(t, fositeStore.CreateAccessTokenSession(context.Background(), secondSignature, secondRequest))

	introspect := func(token string) int {
		hres, _, errs := gorequest.New().Get(ts.URL+"/info").
			Set("Authorization", "bearer "+token).
			End()
		require.Len(t, errs, 0)
		return hres.StatusCode
	}
	revoke := func(token string) int {
		resp, _, errs := gorequest.New().Post(ts.URL+"/revoke").
			SetBasicAuth(oauthClient.ClientID, oauthClient.ClientSecret).
			Type("form").
			SendStruct(map[string]string{"token": token}).End()
		require.Len(t, errs, 0)
		return resp.StatusCode
	}

	// Both tokens work before any revocation happens.
	require.Equal(t, http.StatusOK, introspect(firstToken.AccessToken))
	require.Equal(t, http.StatusOK, introspect(secondAccessToken))

	// Revoking the second token by its own value returns 200. The named token is invalidated
	// (with the old 1:1 index it stayed valid forever and the first token was revoked instead)
	// and the cascade through the request ID removes every access token of the grant.
	assert.Equal(t, http.StatusOK, revoke(secondAccessToken))
	assert.Equal(t, http.StatusUnauthorized, introspect(secondAccessToken))
	assert.Equal(t, http.StatusUnauthorized, introspect(firstToken.AccessToken))

	// The revoked token can no longer be found in the signature-keyed store or the request ID index.
	_, err = fositeStore.GetAccessTokenSession(context.Background(), secondSignature, nil)
	assert.ErrorIs(t, err, fosite.ErrNotFound)
	_, err = fositeStore.GetAccessTokenSession(context.Background(), firstSignature, nil)
	assert.ErrorIs(t, err, fosite.ErrNotFound)
	assert.NotContains(t, fositeStore.AccessTokenRequestIDs, firstRequest.GetID())

	// Revoking an already revoked token still returns 200, as required by RFC 7009.
	assert.Equal(t, http.StatusOK, revoke(secondAccessToken))
}

// TestRevokeRefreshTokenCascadesToAllAccessTokensOfGrant ensures that revoking a refresh token
// invalidates the refresh token itself together with every access token issued for the same grant.
func TestRevokeRefreshTokenCascadesToAllAccessTokensOfGrant(t *testing.T) {
	config := &fosite.Config{GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows")}
	strategy := oauth2.NewHMACSHAStrategy(
		&hmac.HMACStrategy{Config: config},
		config,
	)

	f := compose.Compose(config, fositeStore, strategy,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory)
	ts := mockServer(t, f, &fosite.DefaultSession{})
	defer ts.Close()

	oauthClient := newOAuth2AppClient(ts)

	accessToken, err := oauthClient.Token(context.Background())
	require.NoError(t, err)

	accessSignature := strategy.AccessTokenSignature(context.Background(), accessToken.AccessToken)
	accessRequest, err := fositeStore.GetAccessTokenSession(context.Background(), accessSignature, nil)
	require.NoError(t, err)
	requestID := accessRequest.GetID()

	// A refresh token was issued together with the access token of this grant.
	refreshToken, refreshSignature, err := strategy.GenerateRefreshToken(context.Background(), accessRequest)
	require.NoError(t, err)
	require.NoError(t, fositeStore.CreateRefreshTokenSession(context.Background(), refreshSignature, accessSignature,
		&fosite.Request{
			ID:           requestID,
			RequestedAt:  accessRequest.GetRequestedAt(),
			Client:       accessRequest.GetClient(),
			GrantedScope: accessRequest.GetGrantedScopes(),
			Session:      accessRequest.GetSession().Clone(),
		}))

	introspect := func(token string) int {
		hres, _, errs := gorequest.New().Get(ts.URL+"/info").
			Set("Authorization", "bearer "+token).
			End()
		require.Len(t, errs, 0)
		return hres.StatusCode
	}

	require.Equal(t, http.StatusOK, introspect(accessToken.AccessToken))

	resp, _, errs := gorequest.New().Post(ts.URL+"/revoke").
		SetBasicAuth(oauthClient.ClientID, oauthClient.ClientSecret).
		Type("form").
		SendStruct(map[string]string{"token": refreshToken}).End()
	require.Len(t, errs, 0)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// The refresh token is inactive and its access token was cascade revoked as well.
	_, err = fositeStore.GetRefreshTokenSession(context.Background(), refreshSignature, nil)
	assert.ErrorIs(t, err, fosite.ErrInactiveToken)
	_, err = fositeStore.GetAccessTokenSession(context.Background(), accessSignature, nil)
	assert.ErrorIs(t, err, fosite.ErrNotFound)
	assert.Equal(t, http.StatusUnauthorized, introspect(accessToken.AccessToken))
}
