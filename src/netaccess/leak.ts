/** Zero-leak verification: packets must appear on selected transport only. */

export type PacketEvent = {
  id: string;
  t: number;
  from: string;
  to: string;
  bytes: number;
  leaked: boolean;
  transportId: string;
  sessionId: string;
  policyRuleId?: string;
};

export function simulatePackets(args: {
  sessionId: string;
  transportId: string;
  injectLeak?: boolean;
  n?: number;
}): PacketEvent[] {
  const n = args.n ?? 18;
  const packets: PacketEvent[] = [];
  for (let i = 0; i < n; i++) {
    const leaked = Boolean(args.injectLeak && i === n - 3);
    packets.push({
      id: Math.random().toString(36).slice(2, 7),
      t: i * 90,
      from: "app.pid",
      to: leaked ? "direct.en0" : `${args.transportId}.tun`,
      bytes: 40 + ((i * 97) % 1200),
      leaked,
      transportId: leaked ? "direct" : args.transportId,
      sessionId: args.sessionId,
      policyRuleId: "prefer-home",
    });
  }
  return packets;
}

export function leakVerdict(packets: PacketEvent[]) {
  const leaked = packets.filter((p) => p.leaked);
  return {
    pass: leaked.length === 0,
    leaked: leaked.length,
    observed: packets.length,
    onSelected: packets.filter((p) => !p.leaked).length,
  };
}
