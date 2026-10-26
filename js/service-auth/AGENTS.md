# @amika/service-auth

Who may reach a rig's service, and the credentials that say so. Kept apart
from amika-hostd so the auth proxy can become its own package, or a service
in front of hosts, without untangling it from the daemon.

| Entry point                       | What it holds                                                                                |
| --------------------------------- | -------------------------------------------------------------------------------------------- |
| `@amika/service-auth/credentials` | Signing and verifying service tokens, browser login passes and sessions (`src/credentials/`) |
| `@amika/service-auth/gateway`     | Deciding each request: forward, refuse, or not ours (`src/gateway/`)                         |

The control plane (amika-mono, through `@amika/sandbox`) signs credentials;
a gateway verifies them with the same host secret key, so neither calls the
other.

## The gateway

`createGateway({ secretKey, isOwnPath, amikaUrl })` returns a gateway whose
`authorize(request)` answers one of:

- `forward`: the rig, service and guest path to send the request to, the
  cookies to set on the answer, the surface it came in on (a preview's
  answers `finish` / `harden` lock down), and whether it is
  amikad's keyless SSH upgrade (which the server must pin to amikad's port).
- `refuse`: the status, and for a `401` a hint; `refusal` renders it. A
  `403` is a preview request that is neither the origin's own nor a page
  load.
- `login`: a page load on a preview with no session; `login` renders the
  redirect to the server's `/__amika/login`.
- `not-mine`: no service request at all, for the server's own rules.

With `amikaUrl`, the gateway also serves previews behind a browser login
through Amika (`src/gateway/browser-login.ts`), and the server mounts its two
endpoints: `GET /__amika/login` (`startLogin`) and `POST /__amika/callback`
(`finishLogin`). `servesPreviews` says whether it does.

The server does everything else: resolving the rig's port, forwarding the
request or piping the upgrade, its own API and its own key check. It must not
forward a credential header or cookie of the gateway's
(`isCredentialHeader`, `guestCookies`).

## Boundaries

- No imports from amika-hostd or `@amika/sandbox`; they depend on this, never
  the other way round.
- Requests and responses are Fetch API types (`GatewayRequest`, `Response`).
  Converting a server's own request type (a Node upgrade, say) is the
  server's job. `node:crypto` and `node:net` are fine; HTTP servers are not.
- Credentials use only Web Crypto, so they run wherever the control plane
  does.

## Checks

```bash
pnpm run formatcheck && pnpm run typecheck && pnpm run lint && pnpm run test
```
