# @amika/service-auth

Who may reach a rig's service, and the credentials that say so. Kept apart
from amika-hostd so the auth proxy can become its own package, or a service
in front of hosts, without untangling it from the daemon.

| Entry point                       | What it holds                                                                                               |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `@amika/service-auth/credentials` | Signing and verifying service links, service tokens, browser login passes and sessions (`src/credentials/`) |
| `@amika/service-auth/gateway`     | Deciding each request: forward, refuse, or not ours (`src/gateway/`)                                        |

The control plane (amika-mono, through `@amika/sandbox`) signs credentials;
a gateway verifies them with the same host secret key, so neither calls the
other.

## The gateway

`createGateway({ secretKey, isOwnPath })` returns a gateway whose
`authorize(request)` answers one of:

- `forward`: the rig, service and guest path to send the request to, any
  cookie to set on the answer, and whether it came in through a link (whose
  answers `finish` / `harden` lock down) or is amikad's keyless SSH upgrade
  (which the server must pin to amikad's port).
- `refuse`: the status, and for a `401` a hint; `refusal` renders it.
- `not-mine`: no service request at all, for the server's own rules.

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
