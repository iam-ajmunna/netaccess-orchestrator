export type ProbeLayer =
  | "captive"
  | "dns"
  | "address"
  | "tcp"
  | "path"
  | "tls"
  | "http"
  | "route";

export type FailureClass =
  | "healthy"
  | "captive_portal"
  | "dns_nxdomain"
  | "dns_servfail"
  | "dns_timeout"
  | "dns_inconsistency"
  | "address_resolution"
  | "ipv4_failure"
  | "ipv6_failure"
  | "tcp_refused"
  | "tcp_reset"
  | "tcp_timeout"
  | "routing_failure"
  | "path_mtu"
  | "tls_handshake_timeout"
  | "tls_cert_invalid"
  | "tls_sni_blocked"
  | "http_failure"
  | "destination_restriction"
  | "geographic_restriction"
  | "timeout"
  | "unknown";

export type TransportType =
  | "direct"
  | "http_proxy"
  | "https_connect"
  | "socks5"
  | "wireguard"
  | "ssh_dynamic"
  | "tailscale"
  | "plugin";

export type CircuitState = "closed" | "open" | "half_open";

export type Finding = {
  id: string;
  layer: ProbeLayer;
  ok: boolean;
  classHint: FailureClass;
  weight: number;
  evidence: string;
  latencyMs?: number;
  detail?: { a?: string[]; aaaa?: string[]; status?: number };
  supports?: FailureClass[];
  startedAt: number;
  endedAt: number;
};

export type Classification = {
  class: FailureClass;
  label: string;
  confidence: number;
  likelyCause: string;
  evidence: string[];
  scores: { class: FailureClass; weight: number }[];
};

export type HappyEyeballs = {
  v4?: { ip: string; connectMs?: number; ok: boolean; error?: string };
  v6?: { ip: string; connectMs?: number; ok: boolean; error?: string };
  winner?: "v4" | "v6" | "none";
};

export type Hop = {
  ttl: number;
  label: string;
  asn?: string;
  rttMs?: number;
  kind: "local" | "isp" | "transit" | "edge" | "origin";
};

export type AsnInfo = {
  ip: string;
  asn?: string;
  org?: string;
  prefix?: string;
  country?: string;
};

export type Diagnosis = {
  id: string;
  target: string;
  host: string;
  port: number;
  scheme: "http" | "https";
  mode: "live" | "scenario";
  scenarioId?: string;
  startedAt: number;
  finishedAt: number;
  findings: Finding[];
  classification: Classification;
  happyEyeballs: HappyEyeballs;
  hops: Hop[];
  asn?: AsnInfo;
  altResolver?: { url: string; a: string[]; aaaa: string[]; diverged: boolean };
  redactedTarget: string;
};

export type PolicyMatch = {
  destinationTag?: string;
  hostSuffix?: string;
};

export type PolicyRule =
  | { id: string; kind: "forbid"; match?: PolicyMatch; forbidTransportTag: string[] }
  | { id: string; kind: "require"; match?: PolicyMatch; requireTransportTag: string[] }
  | { id: string; kind: "prefer_latency"; withinMs: number }
  | { id: string; kind: "prefer_tag"; tag: string }
  | { id: string; kind: "fallback"; transportId: string };

export type PolicyDoc = { rules: PolicyRule[] };

export type TransportConfig = {
  id: string;
  name: string;
  type: TransportType;
  host?: string;
  port?: number;
  tags: string[];
  trusted: boolean;
  enabled: boolean;
  secretRef?: string;
  notes?: string;
};

export type TransportRuntime = {
  id: string;
  score: number;
  latencyMs: number;
  jitterMs: number;
  successRate: number;
  history: number[];
  latencyHistory: number[];
  circuit: CircuitState;
  failures: number;
  lastCheckAt: number;
  lastError?: string;
  cooldownUntil?: number;
};

export type DecisionStep = {
  step: string;
  detail: string;
  dropped?: string[];
  kept?: string[];
  scores?: Record<string, number>;
};

export type Selection = {
  transportId: string;
  reason: string;
  trail: DecisionStep[];
  policyHits: string[];
};

export type ScenarioDef = {
  id: string;
  name: string;
  summary: string;
  expected: FailureClass;
  layer: ProbeLayer;
  target: string;
};

export const LAYER_ORDER: ProbeLayer[] = [
  "captive", "dns", "address", "tcp", "path", "tls", "http", "route",
];

export const LAYER_LABEL: Record<ProbeLayer, string> = {
  captive: "Captive portal",
  dns: "DNS resolution",
  address: "Address selection",
  tcp: "TCP connect",
  path: "Path / MTU",
  tls: "TLS handshake",
  http: "HTTP application",
  route: "Route / ASN",
};

export const CLASS_LABEL: Record<FailureClass, string> = {
  healthy: "Healthy path",
  captive_portal: "Captive portal",
  dns_nxdomain: "DNS NXDOMAIN",
  dns_servfail: "DNS SERVFAIL",
  dns_timeout: "Resolver timeout",
  dns_inconsistency: "Resolver inconsistency",
  address_resolution: "Address resolution failure",
  ipv4_failure: "IPv4 failure",
  ipv6_failure: "IPv6 failure",
  tcp_refused: "TCP connection refused",
  tcp_reset: "TCP connection reset",
  tcp_timeout: "TCP connection timeout",
  routing_failure: "Routing / peering failure",
  path_mtu: "Path MTU black hole",
  tls_handshake_timeout: "TLS handshake timeout",
  tls_cert_invalid: "Certificate invalid",
  tls_sni_blocked: "SNI blocked",
  http_failure: "HTTP failure",
  destination_restriction: "Destination restriction",
  geographic_restriction: "Geographic restriction",
  timeout: "Timeout",
  unknown: "Unknown",
};

export const TRANSPORT_LABEL: Record<TransportType, string> = {
  direct: "Direct",
  http_proxy: "HTTP proxy",
  https_connect: "HTTPS CONNECT",
  socks5: "SOCKS5",
  wireguard: "WireGuard",
  ssh_dynamic: "SSH dynamic forward",
  tailscale: "Tailscale",
  plugin: "Plugin transport",
};
