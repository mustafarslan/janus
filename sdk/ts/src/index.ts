/**
 * Janus TypeScript SDK — stub.
 *
 * Phase 4 implements this. The placeholder throws rather
 * than returning a client that quietly does nothing: an SDK that appears to
 * work while recording nothing would let an agent act unevidenced while looking
 * compliant, which is the failure mode Janus exists to prevent.
 */

export const VERSION = "0.0.0";

export function createClient(): never {
  throw new Error(
    "@janus/sdk is not implemented yet. The TypeScript SDK lands in Phase 4; " +
      "until then use janus-mcpd to intercept MCP tool calls.",
  );
}
