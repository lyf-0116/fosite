// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"log"
	"strings"
	"sync"

	"github.com/ory/x/errorsx"
)

// ScopeStrategy is a strategy for matching scopes.
type ScopeStrategy func(haystack []string, needle string) bool

func HierarchicScopeStrategy(haystack []string, needle string) bool {
	for _, this := range haystack {
		// foo == foo -> true
		if this == needle {
			return true
		}

		// picture.read > picture -> false (scope picture includes read, write, ...)
		if len(this) > len(needle) {
			continue
		}

		needles := strings.Split(needle, ".")
		haystack := strings.Split(this, ".")
		haystackLen := len(haystack) - 1
		for k, needle := range needles {
			if haystackLen < k {
				return true
			}

			current := haystack[k]
			if current != needle {
				break
			}
		}
	}

	return false
}

func ExactScopeStrategy(haystack []string, needle string) bool {
	for _, this := range haystack {
		if needle == this {
			return true
		}
	}

	return false
}

var warnAllowAnyRequestedScopeOnce sync.Once

// ValidateRequestedScopes ensures that every requested scope is covered by the OAuth 2.0 Client's
// registered scopes, using the scope strategy resolved from the config. It is shared by all
// authorization request entry points (the authorize endpoint and the pushed authorization request
// endpoint) so that they can not diverge.
//
// If the config does not provide a scope strategy, a safe built-in default is used which rejects
// scopes that exceed the client's registered scopes. Validation can therefore never silently
// degrade to allowing everything when no strategy was configured.
//
// Deployments that intentionally allow clients to request scopes beyond their registered scopes
// (dynamic scope escalation) must explicitly opt in via Config.AllowAnyRequestedScope. Because
// this weakens a security relevant check, a warning is logged when the opt-in is in effect.
func ValidateRequestedScopes(ctx context.Context, config Configurator, clientScopes, requestedScopes []string) error {
	if config.GetAllowAnyRequestedScope(ctx) {
		warnAllowAnyRequestedScopeOnce.Do(func() {
			log.Println("fosite: security warning: Config.AllowAnyRequestedScope is enabled, requested scopes are not validated against the OAuth 2.0 Client's registered scopes and any requested scope is allowed. Only enable this if your deployment intentionally allows dynamic scope escalation.")
		})
		return nil
	}

	strategy := config.GetScopeStrategy(ctx)
	if strategy == nil {
		strategy = WildcardScopeStrategy
	}

	for _, scope := range requestedScopes {
		if !strategy(clientScopes, scope) {
			return errorsx.WithStack(ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	return nil
}

func WildcardScopeStrategy(matchers []string, needle string) bool {
	needleParts := strings.Split(needle, ".")
	for _, matcher := range matchers {
		matcherParts := strings.Split(matcher, ".")
		if len(matcherParts) > len(needleParts) {
			continue
		}

		var noteq bool
		for k, c := range matcherParts {
			// this is the last item and the lengths are different
			if k == len(matcherParts)-1 && len(matcherParts) != len(needleParts) {
				if c != "*" {
					noteq = true
					break
				}
			}

			if c == "*" && len(needleParts[k]) > 0 {
				// pass because this satisfies the requirements
				continue
			} else if c != needleParts[k] {
				noteq = true
				break
			}
		}

		if !noteq {
			return true
		}
	}

	return false
}
