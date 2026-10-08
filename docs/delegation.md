# Delegation — tokens, actors, budgets

SPEC §6. An identity provider says who the person is. The gate turns that into
a **narrower, budgeted, short-lived token** that names both the person and the
agent acting for them, and every action taken with it is charged against the
budget written into it.

## Why a second token at all

An IdP access token says "this is Ali". It does not say "this is Ali's coding
agent, allowed to read one repository, for the next fifteen minutes, for at
most three actions". Handing an agent the IdP token directly gives it
everything Ali can do, for as long as Ali's session lasts, with no record of
which agent did what.

The exchange is where that narrowing happens, and it never grants what it was
asked for: every field is the minimum of the request and what the caller's
group may hold. An exchange that honoured requests would be an escalation path
that works by asking politely.

## The two halves

| | |
|---|---|
| `gate/core/delegation/` | Pure. Decides whether claims are acceptable and what they grant. No key fetch, no clock of its own. |
| `gate/infra/tokens.py`, `gate/infra/jwks.py` | Resolves `kid` to a key, checks the signature, fetches and caches JWKS. |

The split is enforced by `tests/core/test_no_network.py`, which AST-scans
`gate.core` for anything that can reach a socket. A token layer that behaves
differently when the network is down is a token layer an air-gapped install
cannot rely on.

## Signing in

```bash
gate login --issuer https://keycloak.example/realms/gate --client-id gate-cli
```

RFC 8628 device flow: the CLI prints a URL and a short code, you approve in a
browser *anywhere* — it does not have to be the machine you are logged into —
and the refresh token lands in the OS keychain. On a box with no keychain it
goes to a 0600 file and says so.

The device flow is used rather than the authorization-code flow because the
thing logging in is a terminal. A code flow needs a loopback listener and a
browser that can reach it; over SSH or inside a container that is a series of
workarounds.

```bash
gate token --issuer https://keycloak.example/realms/gate --adapter adp_laptop
```

Adapters call this transparently when their cached token is close to expiry.

## The exchange

`POST /v1/token`, RFC 8693. **Adapter-authenticated like every other `/v1`
route**: the subject token proves who the *user* is, not which deployment is
asking on their behalf, and a stolen IdP token should not be exchangeable from
anywhere on the internet.

```http
POST /v1/token
x-gate-adapter-id: adp_laptop
x-gate-signature: ...

{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token": "<IdP access token>",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "requested_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "scope": "read write admin"
}
```

```json
{
  "access_token": "<the minted gate token, a compact JWS>",
  "token_type": "Bearer",
  "expires_in": 899,
  "scope": "read write",
  "refused_scope": "admin"
}
```

`refused_scope` is returned so a misconfigured agent fails loudly here rather
than silently at the first action it cannot take.

### What bounds what

| Field | Bounded by |
|---|---|
| scope | the union of the scopes the subject's IdP groups may hold |
| budget | per axis, the minimum of the request and the group ceiling |
| lifetime | the smallest of: the request, one hour, the parent's remaining life, the mandate's remaining life |

A cap of **0 means uncapped**, which makes the budget arithmetic less obvious
than it looks: an uncapped ceiling grants the request, an uncapped *request*
under a capped ceiling takes the ceiling, and two caps take the smaller.

## Configuration

```yaml
delegation:
  self_issuer: https://gate.internal      # the `iss` of tokens this gate mints
  token_ttl_default_seconds: 900
  offline: false                          # true: never fetch JWKS, cache only
  issuers:
    - issuer: https://keycloak.example/realms/gate
      jwks_uri: ...                       # optional; discovered when absent
      algorithms: [RS256]                 # never read from the token
      scopes_by_group:
        platform: [read, write]
  budget_caps:
    platform: { steps: 20, money_cents: 500 }
```

With no `issuers`, `/v1/token` answers **501** rather than minting tokens
nobody asked for. A deployment that never exchanges tokens should not be made
to hold a token key.

## Verifying a token the gate issued

```bash
curl -s http://gate:8710/.well-known/jwks.json
```

Unauthenticated, and deliberately **outside `/v1`**: every `/v1` route refuses
an unsigned request and the test that asserts it has no exemption list.

Gate tokens are signed `alg: Ed25519` — not `EdDSA`, which RFC 9864
deprecates. The evidence chain is unaffected; that is raw Ed25519, not JOSE.

## Keys

The **token key** (`token-key.json`, created on first use) is not the
**evidence key**. An evidence key signs history and must outlive every token;
a token key is online, used constantly, and has to be rotatable without
invalidating a single past record.

## When the identity provider is down

The network is an optimisation, not a dependency. Every JWKS fetch is written
to disk whole and moved into place; a failed fetch falls back to the loaded
set, then to that file. An install that has run once keeps verifying through
an outage. An air-gapped install sets `offline: true` and is seeded by copying
the cache file in.

An unknown `kid` forces **one** refetch — that is what a key rotation looks
like from this side, and waiting out the TTL would refuse every token signed
with the new key until it expired. It is rate limited separately from the TTL
refresh, so junk tokens cannot turn the gate into a request amplifier pointed
at the identity provider.

## Trying it

`deploy/keycloak/` brings up a real Keycloak with the realm, client, user and
groups already imported:

```bash
docker compose -f deploy/keycloak/docker-compose.yml up -d
./deploy/keycloak/demo.sh
```

The script signs in, exchanges, verifies the minted token against the
published JWKS, spends a three-step budget, and shows the chain:

```
seq  2  budget_update        token issued
seq  3  proposal   seq  4  verdict      ALLOW
seq  5  proposal   seq  6  verdict      ALLOW
seq  7  proposal   seq  8  verdict      ALLOW
seq  9  budget_exhausted
seq 10  proposal   seq 11  verdict      BLOCK
result : OK -- chain is contiguous, unmodified and signed
```

Only the person at the keyboard is faked: the script drives the password grant
so it can run unattended. The tokens, signatures, JWKS fetch, budget and chain
are the production paths.

### What running it against a real provider found

Three things that fixtures had hidden, all now covered by
`tests/delegation/test_real_idp_shapes.py`:

1. **`scope` is a space-delimited string** (RFC 6749 §3.3), not a list. Every
   real provider sends the string; the synthetic tests had always built a list.
2. **Keycloak 26 omits `sub`** from the access token unless the client carries
   the `basic` client scope. A token with no subject cannot name anybody, so it
   is refused — but the realm in `deploy/keycloak/` now requests that scope.
3. **A token must not declare its own kind.** `TokenClaims` had a `token_type`
   field defaulting to `"gate"`, so an IdP token — which carries no such claim
   — arrived looking gate-issued and was handed to the narrowing check as its
   own parent. Whether a token is gate-issued is now decided by *which key
   verified it*, which is the same rule as never reading `alg` from the token.
