/**
 * Who may reach a rig's service, decided per request: the host key, service
 * tokens, signed links and the link cookie. See `./gateway.ts`.
 */
export {
  createGateway,
  type ForwardDecision,
  type Gateway,
  type GatewayDecision,
  type GatewayOptions,
  type GatewaySurface,
  type RefuseDecision,
} from "./gateway";
export {
  SERVICE_KEY_HEADER,
  SERVICE_TOKEN_HEADER_NAME,
  authorizeServiceLinkRequest,
  authorizeServiceRequest,
  authorizeServiceRouteRequest,
  bearerToken,
  secretMatches,
} from "./keys";
export {
  LINK_COOKIE,
  isLoopbackHost,
  linkCookie,
  linkFromCookie,
  withoutLinkCookie,
  type LinkCookieClaim,
} from "./link-cookie";
export { hardenServiceLinkResponse, tokenHint } from "./responses";
export {
  AMIKAD_SERVICE,
  fromRequest,
  isAmikadSshUpgrade,
  parseServiceLinkPath,
  parseServicePath,
  type GatewayRequest,
  type ServiceLinkRoute,
  type ServiceRoute,
} from "./routes";
