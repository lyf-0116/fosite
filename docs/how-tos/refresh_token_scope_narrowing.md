# Refresh Token Scope Narrowing

The refresh token grant supports requesting a subset of the scopes that were
originally granted. This follows
[RFC 6749, section 6](https://datatracker.ietf.org/doc/html/rfc6749#section-6).

## Behavior

When a client sends a refresh request with a `scope` parameter:

1. Each requested scope must still be allowed by the client's registered
   scopes.
2. Each requested scope must be covered by the scopes granted to the original
   refresh token. Requesting any scope that was not originally granted fails
   with `invalid_scope`.
3. The new access token and the rotated refresh token are bound to the
   requested subset only. The token response and introspection response report
   that same subset.

If the `scope` parameter is omitted, the new tokens keep the full set of
scopes granted to the original refresh token.

## Narrowing is irreversible

The rotated refresh token is persisted with the narrowed scope. It cannot be
used to request a broader scope later. To regain a scope that was dropped, the
client must start a new authorization flow and obtain a new grant.

Clients that currently request a broad scope once and rely on refresh to keep
that broad scope will observe the change in the token response. In particular,
if a refresh request narrows away `offline`, the rotated token no longer
contains a scope configured in `RefreshTokenScopes` and cannot be refreshed
again with that configuration. Likewise, dropping `openid` means the refresh
response no longer contains an ID token. Include these scopes explicitly in the
`scope` parameter when they are still needed.

## Migration

Audit refresh requests that send a `scope` parameter. Before this change they
continued to receive the original full grant; after this change they receive
only the requested subset, and subsequent refreshes inherit that subset. If a
client needs the original scope for later requests, either omit `scope` on the
refresh request or request the required scopes explicitly.
