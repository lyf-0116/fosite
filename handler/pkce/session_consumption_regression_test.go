// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

func TestPKCEFailedVerificationLeavesSessionForRetry(t *testing.T) {
	store := storage.NewMemoryStore()
	codeStrategy := &mockCodeStrategy{signature: "retry-code"}
	handler := &Handler{
		Storage:               store,
		AuthorizeCodeStrategy: codeStrategy,
		Config:                &fosite.Config{},
	}

	verifier := "KGCt4m8AmjUvIR5ArTByrmehjtbxn1A49YpTZhsH8N7fhDr7LQayn9xx6mck"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])

	authorizeRequest := fosite.NewAuthorizeRequest()
	authorizeRequest.Client = &fosite.DefaultClient{}
	authorizeRequest.Form.Set("code_challenge", challenge)
	authorizeRequest.Form.Set("code_challenge_method", "S256")
	require.NoError(t, store.CreatePKCERequestSession(context.Background(), codeStrategy.signature, authorizeRequest))

	failedRequest := fosite.NewAccessRequest(nil)
	failedRequest.Client = authorizeRequest.Client
	failedRequest.GrantTypes = fosite.Arguments{"authorization_code"}
	failedRequest.Form.Set("code_verifier", "wrong-verifier-wrong-verifier-wrong-verifier")
	require.ErrorIs(t, handler.HandleTokenEndpointRequest(context.Background(), failedRequest), fosite.ErrInvalidGrant)

	validRequest := fosite.NewAccessRequest(nil)
	validRequest.Client = authorizeRequest.Client
	validRequest.GrantTypes = fosite.Arguments{"authorization_code"}
	validRequest.Form.Set("code_verifier", verifier)
	require.NoError(t, handler.HandleTokenEndpointRequest(context.Background(), validRequest))

	_, err := store.GetPKCERequestSession(context.Background(), codeStrategy.signature, nil)
	require.ErrorIs(t, err, fosite.ErrNotFound)
}

func TestPKCEConcurrentValidVerificationConsumesSessionOnce(t *testing.T) {
	store := storage.NewMemoryStore()
	codeStrategy := &mockCodeStrategy{signature: "race-code"}
	handler := &Handler{
		Storage:               store,
		AuthorizeCodeStrategy: codeStrategy,
		Config:                &fosite.Config{},
	}

	verifier := "KGCt4m8AmjUvIR5ArTByrmehjtbxn1A49YpTZhsH8N7fhDr7LQayn9xx6mck"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])

	authorizeRequest := fosite.NewAuthorizeRequest()
	authorizeRequest.Client = &fosite.DefaultClient{}
	authorizeRequest.Form.Set("code_challenge", challenge)
	authorizeRequest.Form.Set("code_challenge_method", "S256")
	require.NoError(t, store.CreatePKCERequestSession(context.Background(), codeStrategy.signature, authorizeRequest))

	const requestCount = 32
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	var successMu sync.Mutex
	successCount := 0

	waitGroup.Add(requestCount)
	for range requestCount {
		go func() {
			defer waitGroup.Done()

			accessRequest := fosite.NewAccessRequest(nil)
			accessRequest.Client = authorizeRequest.Client
			accessRequest.GrantTypes = fosite.Arguments{"authorization_code"}
			accessRequest.Form.Set("code_verifier", verifier)

			<-start
			if err := handler.HandleTokenEndpointRequest(context.Background(), accessRequest); err == nil {
				successMu.Lock()
				successCount++
				successMu.Unlock()
			}
		}()
	}

	close(start)
	waitGroup.Wait()

	require.Equal(t, 1, successCount)
}
