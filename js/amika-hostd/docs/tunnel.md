# Outbound tunnel

A host behind a home router has no way to be reached. Today an operator
solves that themselves: ngrok, a port forward, cloudflared, and then
`amika-hostd register-url` to tell Amika where the tunnel came out. That is
a second service to run, a second thing to pay for, and a URL that changes.

Tunnel mode removes it. The daemon binds nothing and **dials out** to an
Amika-run gateway over WSS. The gateway holds one yamux session per host and
opens one stream for each public request it forwards. hostd serves each of
those streams with the same Hono app, the same authentication and the same
upgrade handler a listening daemon serves, so no route exists twice.

This document covers the client half, which lives in this repo. The gateway
is in amika-mono (`js/gateway`), and the design both ends implement is spec
025, `specs/025-hostd-outbound-tunnel.md` there.

## The pieces

`src/internal/` is flat, so the tunnel is a set of files rather than a
directory:

| File                    | What it owns                                                |
| ----------------------- | ----------------------------------------------------------- |
| `tunnel-dial.ts`        | The WSS handshake, and what the gateway's answer means      |
| `tunnel-byte-stream.ts` | The WebSocket, read by the multiplexer as ordered bytes     |
| `tunnel-frame-guard.ts` | A length check on an inbound DATA frame, before the decoder |
| `tunnel-attachment.ts`  | One live session: the yamux muxer, liveness, draining       |
| `tunnel-socket.ts`      | One yamux stream, shaped like a socket for `node:http`      |
| `tunnel-serving.ts`     | An `http.Server` with no listener, fed those sockets        |
| `tunnel-backoff.ts`     | How long to wait before dialling again                      |
| `tunnel-client.ts`      | The loop: dial, serve, decide what a disconnect meant       |
| `tunnel-target.ts`      | Where to attach, and what to prove it with                  |

## Decisions

### The credential is a host-scoped bearer token

hostd already keeps two secrets, and the tunnel uses neither.

- The **Amika API key** acts as the user across their whole organization.
  Spec 025 forbids reusing it, and `setup` already keeps it out of the
  daemon's environment.
- The **secret key** authorizes Amika's requests _into_ this daemon and
  signs service links. Attaching a host is the opposite direction and a
  different permission.

So the tunnel adds a third secret, `attachment-credential`, in the same
store as the other two (`credentials.ts`): a keychain item, or a file beside
`api-key` with the file store. It is minted by the control plane at
enrolment, in exchange for the user's API key, and it is worth only this
host's inbound traffic.

**Why a bearer token and not a signed assertion over a keypair**, which spec
025 prefers for the long term: the gateway re-presents the same credential
string on every lease renewal, for the whole life of the attachment. Its
`attachHost` captures the string at attach time and passes it unchanged to
`renewHost` hours later. A proof bound to a timestamp or a challenge would
be valid for the first call and rejected for every renewal after it, and the
gateway has no way to ask the host for a fresh one. A keypair model
therefore needs a change on the gateway side first; the credential is opaque
to the gateway, so making it later changes nothing in this repo but the
enrolment call.

It travels in the `x-amika-host-credential` header of the handshake, beside
`x-amika-host-id`, never in the URL, because a query string reaches the
access log of every proxy on the path and an attachment credential lives
until it is rotated. It is not `Authorization: Bearer`: the gateway does not
know the credential's scheme and hands the whole value to the control plane
unread. These are the names the gateway reads; any other spelling is
refused at the handshake.

### The gateway address comes from the control plane

The control plane records it at enrolment, in
`<state>/tunnel-enrolment.json` beside the host id and the credential
generation. A gateway is deployment configuration Amika owns: hosts move
between staging and production, and a gateway moves between zones. Making
that an operator setting means editing a file on every laptop when it moves.

`tunnel_gateway_url` in `config.toml`, or
`AMIKA_HOSTD_TUNNEL_GATEWAY_URL`, overrides it. That exists for a gateway
running on a developer's own machine, and for pinning one host while an
incident is on.

`wss://` is required. Plain `ws://` is accepted on loopback only, because a
developer's own gateway has no certificate and nothing leaves the machine.
The loopback test is anchored at both ends: `127.0.0.1.evil.example` is a
name anyone can register.

### A ping, not a WebSocket ping, and not the library's keep-alive

The normal way a tunnel dies is a closed laptop lid. The socket stays in
`ESTABLISHED`, the kernel accepts writes, and no WebSocket or TCP event
reports anything. Only an unanswered round trip finds it.

- A **WebSocket ping** is answered by the peer's `ws` library, below the
  multiplexer and below the event loop that serves requests. A pong proves
  bytes move and nothing else.
- **`@libp2p/yamux`'s own keep-alive** sends pings and swallows the error
  when one goes unanswered. Its source carries a `TODO: should abort here?`
  where the abort would be. It cannot report a dead peer, which is the only
  thing this daemon needs it for.

So `TunnelAttachment` disables the library's keep-alive and runs its own:
a yamux ping every `keepAliveIntervalMs`, with a `pingTimeoutMs` deadline,
ending the attachment when one is not answered. A yamux ping is answered by
the peer's multiplexer, so it proves the whole stack a request travels
through.

It pings on a fixed interval rather than only when the tunnel is idle.
Inbound traffic proves the gateway can reach this host; it proves nothing
about the other direction, and a response that cannot be written is the
failure that matters. The cost of being wrong is one 12-byte frame per
interval. The same interval doubles as the idle keep-alive an edge that
closes quiet WebSockets needs.

### Backoff is full jitter with a floor

A gateway deploy drops every host at the same instant. Hosts that all wait
the same growing interval arrive together and knock it over again. So the
wait is drawn uniformly across the whole window rather than nudged a few
percent around it, with a floor under it: full jitter can draw one
millisecond, and the failure that most often repeats immediately is a
gateway that completes the handshake and then drops the connection.

A session that stayed up for `resetAfterMs` resets the schedule. A laptop
that sleeps nightly would otherwise bring last night's cap to this
morning's first reconnect.

### Shutdown closes the WebSocket, and that is the point

`TunnelAttachment.close()` stops accepting streams, lets the requests in
flight finish up to `drainMs`, sends GO_AWAY, and then closes the WebSocket
with 1001 "going away". The close is what releases the attachment at the
gateway: its close handler gives up the route, so a daemon that has gone
does not leave the gateway forwarding into a socket nobody reads. Dropping
the connection instead loses every request sent before the gateway's own
liveness check notices.

A caller with upgraded connections -- SSH, the web terminal, a rig's service
WebSocket -- destroys those first. They are long-lived by design, so waiting
for them always runs the drain out to its bound. Listener-mode shutdown
makes the same distinction (`server.ts`).

Disconnecting is **not** shutdown. A dropped tunnel leaves the daemon and
every rig on this host running while it reconnects, and it never falls back
to opening a port.

## What the gateway does

The gateway in amika-mono does both things this client was written to use.

**It authorizes before the `101`.** A refusal arrives as an HTTP status,
not an aborted socket, so a daemon whose credential was revoked can tell
its operator why it is offline instead of retrying for ever. The gateway
answers `401` for a host the control plane rejects and `503` when it could
not ask. `tunnel-dial.ts` reads the status: 401, 403, 404, 410 and 426 stop
the loop and produce an actionable message, and everything else is an
outage to wait out. As a fallback, the client still counts consecutive
sessions that connected, served nothing and died, and raises
`suspect-credential` after five of them.

**It names the connection on the `101`.** Spec 025's readiness result is
host id, connection id and public address. The connection id is minted by
the gateway's attachment directory, and the only channel the host has for
it is the handshake response, since the tunnel carries binary frames only
and a text control message is exactly what the gateway refuses.
`dialTunnel` reads `x-amika-connection-id` and `x-amika-host-url` when they
are there, and reports the attachment without them when they are not. The
gateway sends the connection id; it does not send a public URL.

## Limits, and the one rule nothing enforces

`DEFAULT_LIMITS` mirrors the gateway's. The guard's limit at each end must
be at least the other end's initial stream window, and **nothing negotiates
this**: a host with a larger window trips the gateway's guard on its first
full-size frame and loses its tunnel. Amika owns both ends, so it is a
deployment rule. Keep `maxFrameBytes` here equal to the gateway's
`maxFrameBytes`, and check it when either moves.

`maxPayload` on the WebSocket is the only bound on an inbound WebSocket
message: `ws` assembles a whole message before the frame guard sees a byte
of it. `dialTunnel` sets it.

## Bundling

`ws` is CommonJS and calls `require("events")` as it loads. esbuild rewrites
that to a helper that throws `Dynamic require of "events" is not supported`
in ESM output, unless a real `require` is in scope, which the helper then
uses instead. `scripts/bundle.mjs` therefore carries a `createRequire`
banner, and `src/bundle.test.ts` bundles the tunnel on its own and runs it
with no `node_modules` to pin that. The daemon's own entry point does not
import the tunnel yet, so without that test the release bundle would break
on the day it does.

## Enrolment

`amika-hostd up` enrols a host whose transport is `tunnel`, every time,
right after it registers. One call to the control plane returns the
credential, the generation the gateway fences on, and the gateway's
address; the credential goes into the secret store and the rest into
`tunnel-enrolment.json` beside the config the daemon loaded. The record
deliberately does not hold the credential, so a copied state directory
does not carry one.

Every `up`, not only when setup rotates the secret key: a host set up
fresh, or one whose operator kept its key, would otherwise never be
enrolled. Repeating it is harmless, because the control plane answers
with the credential it already holds. It is apart from setup's key
rotation for a second reason: a failed enrolment must never roll back a
secret key Amika has already taken.

The control plane enrols only for a person, so the API key must be a
user-scoped one; an organization-scoped key is refused with `403`.

## Serving

`serve` and `up` start a tunnel instead of a listener when the transport
says so. `startTunnel` is the counterpart of `startServer`, and both
build the app and the upgrade handler through one `buildHandlers`, so a
rig reached down a tunnel answers the same routes under the same
authorization as one reached on a port.

A tunnel host binds nothing, so the readiness the daemon reports over IPC
carries no port. It carries the connection id the gateway named on the
`101`, where the gateway sends one, which is what matches this daemon
against the gateway's logs.

### A rig named by its hostname

A browser reaches a rig's service at `<service>--<rig>.r.<org>.o.<zone>`.
That hostname never reaches this daemon on its own: the request goes to
the gateway's address, and on Cloudflare the gateway's container renames
it again. So the reverse proxy reads the rig and the service out of it and
signs them, and the gateway, having checked the signature, writes them
onto the tunnel stream as `x-amika-rig` and `x-amika-service`. It writes
them after removing every `x-amika-` header the request arrived with, so
on a tunnel stream they can only be the gateway's. It also sends the
caller's own authority as `Host`.

The tunnel's server (`tunnel-rig-route.ts`) reads the two headers, removes
them, and records the rig and service beside the request in a `WeakMap`.
The app and the upgrade handler ask `namedRoute` for it and hand it to the
service-auth gateway as `GatewayRequest.named`. A header can be forged on a
listening socket; a `WeakMap` entry only the tunnel's server writes
cannot, so a listening daemon never names a request.

A named request is that service's whatever its path. `/v0beta1/rigs` on
`web--rig.r.org.o.<zone>` is the rig's own page, never this daemon's
machine list, so the app sends it to the service before any of its own
routes can match. The exceptions are `/__amika/login` and
`/__amika/callback`, which are how a browser logs in to that origin.

Who may have it is the gateway's to decide. At a name, that is a browser
session for that origin and nothing else:

- A page load without a session is sent to log in at the same origin and
  comes back to the same path. Amika checks the origin names a rig of the
  user's organization on this host, and posts the pass to that origin's
  callback.
- The host key and service tokens travel in `x-amika-` headers, which the
  reverse proxy and the gateway both drop from what a caller sends, so
  neither reaches a name. A scripted caller uses the service route.
- `amikad` is never reachable at its name.

Each service is its own origin, so each logs in once, and no cookie has to
say which service the root belongs to. Every rig shares the zone, so a
sibling's page is the same site and the session goes with what it loads:
only the origin's own requests and page loads are let through, and a frame
or script another site loads is refused even with a session.

A request with neither header is the control plane calling this daemon's
API, and is left alone. One with only one of them, or a name that is not a
DNS label, is refused with `400`.
