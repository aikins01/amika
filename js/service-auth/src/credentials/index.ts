/**
 * The credentials Amika and amika-hostd exchange, signed with keys derived
 * from a host's secret key: the control plane signs, the host verifies, and
 * neither calls the other. See `./service-links.ts`.
 */
export * from "./service-links";
