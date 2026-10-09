# The HTTP forward proxy

SPEC §12.3. One sentence: **point the agent's `HTTPS_PROXY` at QED and
every outbound call gets a verdict.**

```
$ qed proxy --human you@acme.com --env prod
qed: forward proxy on 127.0.0.1:8888 in shadow mode, env prod
qed: point your agent at it with  HTTPS_PROXY=http://127.0.0.1:8888 HTTP_PROXY=http://127.0.0.1:8888
qed: every CONNECT tunnel is ADVISORY -- QED decides whether the
      connection may be opened, but the request inside it is encrypted, so it
      cannot replace the credential and the agent is using its own.
```

The MCP proxy governs the tools an agent was given. This governs everything
else: the `curl` in a shell step, the SDK call in a script, the HTTP request an
agent makes because something in its context told it to.

## What it can see, and what it cannot

This is the first thing to understand about it, because the two halves of the
same port are not equally governable.

| | Plain HTTP | CONNECT (HTTPS) |
|---|---|---|
| What arrives | `GET http://api.test/v1/orders` | `CONNECT api.test:443` |
| Decided on | method, path, query, headers | host and port |
| Credential | QED's, with the agent's stripped | the agent's, inside TLS |
| `enforcement` | `enforcing` when the broker holds it | **always `advisory`** |

**Every tunnel is advisory.** QED decides whether the connection may be
opened at all, which is a real control and the refusal is real — but once the
tunnel is open it carries ciphertext. There is no method, no path, no body, and
no way to replace the credential inside it. An adapter that recorded
`enforcing` there would be putting a control in the evidence that the transport
does not allow, so it records `advisory` with the reason attached whatever the
command line asked for.

The `execution_result` for a tunnel says so in the record itself:

```json
{
  "proposal_id": "01JB…",
  "status": "ok",
  "duration_ms": 1840.2,
  "tunnel": true,
  "bytes_to_upstream": 5312,
  "bytes_to_client": 41980,
  "visibility": "host only; the request inside the tunnel is encrypted"
}
```

Byte counts and a duration are thin evidence and they are labelled as such.
They are still the difference between *"an agent opened a connection to
pastebin.example at 02:14 and moved 41 MB"* and no record at all.

SPEC §12.3's optional `mitm` mode, with a CA the customer installs, is what
changes this. It is not in v1.

## The proposal

```
action.kind    http
action.name    "POST /v1/charges"   |  "CONNECT api.stripe.com"
action.method  POST                 |  CONNECT
action.target  https://api.stripe.com/v1/charges
```

The target is a **URL**, not a cloud resource id. That is deliberate and load
bearing in two places: `match_upstream` finds a host glob by splitting the
target on `://`, and the shipped `AG-DAT-003` egress rule matches
`action.target` against `*://*`. A target in some other shape would leave both
of them matching nothing, and an egress rule that never fires is invisible.

The **query is not in the target**. It carries tokens, and its order varies
between calls that mean the same thing; either would make a policy glob leaky
or useless. It goes into the parameters, where `AG-DAT-001` can still see it
and the masking pass cleans it on the way into the chain.

The **body is not read at all** in `host_path` mode. `params_hash` covers the
request line and the headers that describe the body, not the body itself, and
the parameters record its declared type and length:

```json
{
  "host": "api.stripe.com",
  "path": "/v1/charges",
  "query": "",
  "content_type": "application/json",
  "content_length": 61
}
```

A rule that needs the body needs `mitm` mode.

### Blast hints

Derived from the method, with the path as the only clue to width:

| Method | `writes` | `deletes` | `scope` |
|---|---|---|---|
| `GET` `HEAD` `OPTIONS` `TRACE` | no | no | single |
| `POST` `PATCH` | yes | no | single |
| `PUT` `DELETE` on `/v1/orders/8812` | yes | `DELETE` only | single |
| `PUT` `DELETE` on `/v1/orders` | yes | `DELETE` only | **multi** |
| `CONNECT` | — | — | — |

A trailing segment that is all digits, a ULID, a UUID or anything with a dot in
it reads as one resource; anything else reads as the collection. Best effort,
and wrong either way it only moves a hint that a rule can override.

`CONNECT` claims nothing. Guessing `writes=True` would route every TLS
connection to an approver; guessing `writes=False` would tell the blast-radius
scorer the connection is harmless. Neither is known, so neither is asserted,
and the summary says in words what QED cannot see.

### Declaring intent

An agent can say what it is doing with a header, the HTTP counterpart of MCP's
`_meta.intent`:

```
X-QED-Intent: refund order 123
```

It lands in `context.intent`, and it is stripped before the request is
forwarded — it is for QED, not for the upstream.

## Enforcing: the credential

An `http` upstream in `upstreams.yaml` is what makes QED enforcing:

```yaml
upstreams:
  - id: stripe
    kind: http
    match: { host_globs: ["api.stripe.com"], environments: [prod] }
    credential:
      source: vault
      ref: "secret/data/qed/stripe#SECRET_KEY"
      inject: { type: header, name: Authorization, format: "Bearer {value}" }
```

Then, on an ALLOW:

1. Everything the agent supplied that looks like a credential is **removed** —
   nine header names, matched case-insensitively.
2. The broker's header is attached.
3. The request goes out in origin form with a rewritten `Host`, a `Via` and
   `Connection: close`.

Stripping matters more than attaching. An adapter that added the broker's
header while leaving the agent's in place would be an adapter where the agent
still chooses which credential gets used.

If the agent keeps supplying one, the closing summary says so:

```
qed: removed 4 agent-supplied credential header(s): Authorization, X-Api-Key.
      Something is wiring a token into the agent; it is being ignored.
```

That is worth noticing in both directions: it usually means somebody wired a
token into the agent and is wondering why it is ignored, and it can mean the
agent is trying to reach past QED.

**With no `http` upstream configured, the session is advisory** and says so at
startup. The MCP proxy keeps the operator's flag in that situation because
deployments existed before the broker did; this adapter has no such history, so
it has no reason to inherit the dishonesty. `--enforcement` is a ceiling: it
can ask for less than the broker can give, never for more.

`inject: {type: env, ...}` is refused at startup. An environment variable is
how a credential reaches a stdio child process; an HTTP request does not have
one, and an upstream configured that way would match, resolve, and have its
credential silently dropped.

`sigv4` cannot be planned ahead, because the signature covers the request body.
The request is decided, recorded, and answered with a `501` rather than
forwarded unsigned — forwarding unsigned would mean the agent's own credentials
get used after all.

## What the agent sees

A refusal is a `403` whose body is the explanation, because the body is the one
place it reliably survives: an agent that only logs `403` still logs the rule
ids with it.

```
HTTP/1.1 403 Forbidden

[qed BLOCK] AG-DAT-013: This request targets the cloud instance metadata
service, which hands out the instance's own credentials. Fix: An agent does
not need instance credentials. Give it a scoped credential through QED's
broker instead.
```

| Status | Means |
|---|---|
| `403` | BLOCK, or approval required. The body has the rule ids. |
| `502` | The upstream could not be reached. Not a policy decision. |
| `503` | The kernel itself failed and `fail_mode` is `closed`. |
| `501` | Something this build does not forward: a chunked request body, `sigv4`, a non-HTTP scheme. |
| `400` `414` `431` `505` | The request could not be read one way only. See below. |

## Strict framing, on purpose

A proxy that resolves an ambiguity in request framing can be made to disagree
with the server behind it about where one request ends and the next begins.
That is request smuggling, and here it has a sharper edge than usual: the
smuggled half is the half QED never decided, so it would execute with no
verdict and leave no record.

So anything ambiguous is refused:

- both `Content-Length` and `Transfer-Encoding` (RFC 9112 §6.1);
- two `Content-Length` headers that disagree;
- an obs-fold continuation line;
- a header name that is not a token, or a value carrying CR, LF or NUL;
- a `CONNECT` with no port — it does not default to 443;
- userinfo in a proxied URL, which is a credential in a place nothing masks;
- more than 100 headers, or a head over 64 KB.

**One request per client connection.** v1 answers with `Connection: close` and
forwards with `Connection: close`. Keep-alive and pipelining are where that
disagreement lives, so the cost is a TCP handshake per plain-HTTP call and
nothing at all on the tunnel path.

A connection that opens and closes with nothing on it is a health check or a
port scan, not an error, and is not answered or counted.

## Loopback is the access control

`qed proxy` binds `127.0.0.1`. Binding anything else needs
`--allow-non-loopback`, because a forward proxy on a reachable interface is an
open relay: anything that can see the port gets to make requests, and the chain
would attribute every one of them to this session's `--human`.

If you need it reachable, put your own authentication in front of it.

## Related

- `docs/credential-broker.md` — where the credential comes from, and why
  `advisory` is the honest answer when there is none.
- `docs/mcp-proxy.md` — the same kernel, for tools rather than for HTTP.
- `AG-DAT-003` (egress allow list) and `AG-DAT-013` (instance metadata) are the
  two shipped rules this adapter exists to make reachable.
