/**
 * server.ts - Preflight A2MCP service.
 *
 * Exposes an MCP streamable-HTTP endpoint at POST /mcp.
 * Stateless: one server + transport per request, so it scales horizontally
 * behind any load balancer with no sticky sessions.
 */

import express, { type Request, type Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

import {
  CHAINS,
  fetchAddressIntel,
  fetchApprovalIntel,
  fetchTokenIntel,
  isAddress,
  resolveChain,
} from "./intel.js";
import { decide, type RiskTolerance } from "./policy.js";

const CHAIN_LIST = Object.keys(CHAINS).join(", ");

const toleranceSchema = z
  .enum(["strict", "balanced", "degen"])
  .default("balanced")
  .describe(
    "Risk policy. strict = block on any material risk (use for treasury / user funds). balanced = default. degen = only block on critical findings."
  );

const chainSchema = z
  .string()
  .default("ethereum")
  .describe(`Chain name (${CHAIN_LIST}) or numeric chain id.`);

function ok(payload: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
  };
}

/**
 * An infrastructure failure is NOT a risk verdict.
 *
 * Returning BLOCK when the upstream feed is rate-limited says "this token is
 * dangerous" when the truth is "I never looked at it". That defames clean
 * tokens and, worse, teaches the calling agent to distrust real BLOCKs.
 *
 * So failure gets its own verdict. UNAVAILABLE never fails open (the agent is
 * told not to proceed on an unchecked transaction) but it never pretends to be
 * a finding about the token either. `retryable` lets a caller back off and try
 * again instead of abandoning a legitimate trade.
 */
function fail(message: string, retryable = false) {
  return {
    isError: true,
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(
          {
            schema: "preflight.error.v1",
            verdict: "UNAVAILABLE",
            retryable,
            error: message,
            summary:
              `UNAVAILABLE. Preflight could not complete the check: ${message} ` +
              `This is NOT a finding about the target - no assessment was made. ` +
              (retryable
                ? "Upstream data is temporarily unreachable; retry shortly. "
                : "") +
              `Do not proceed on an unchecked transaction.`,
          },
          null,
          2
        ),
      },
    ],
  };
}

/** Upstream throttling and timeouts are transient - flag them as retryable. */
const isTransient = (msg: string) =>
  /too many requests|rate.?limit|429|timeout|abort|upstream 5\d\d|fetch failed|ECONNRESET/i.test(
    msg
  );

const failFrom = (e: any) => {
  const msg = String(e?.message ?? e);
  return fail(msg, isTransient(msg));
};

function buildServer(): McpServer {
  const server = new McpServer({
    name: "preflight",
    version: "1.0.0",
  });

  server.registerTool(
    "check_token",
    {
      title: "Check token safety",
      description:
        "Run a safety check on an ERC-20 token before buying, swapping, or accepting it as payment. " +
        "Returns a machine-actionable verdict (ALLOW / WARN / BLOCK), a 0-100 risk score, and specific findings " +
        "(honeypot, mintable supply, mutable tax, unlocked liquidity, holder concentration, unverified source, and more). " +
        "Call this BEFORE signing any transaction that acquires or approves a token.",
      inputSchema: {
        token_address: z
          .string()
          .describe("The 0x token contract address to check."),
        chain: chainSchema,
        risk_tolerance: toleranceSchema,
      },
    },
    async ({ token_address, chain, risk_tolerance }) => {
      const addr = token_address.trim();
      if (!isAddress(addr)) return fail(`"${addr}" is not a valid 0x address.`);
      try {
        const chainId = resolveChain(chain);
        const intel = await fetchTokenIntel(chainId, addr);
        const decision = decide(intel, "token", risk_tolerance as RiskTolerance);
        return ok({
          ...decision,
          target: { type: "token", address: addr, chain, chain_id: chainId },
          token: {
            name: intel.token_name ?? null,
            symbol: intel.token_symbol ?? null,
            total_supply: intel.total_supply ?? null,
            holder_count: intel.holder_count ?? null,
            buy_tax: intel.buy_tax ?? null,
            sell_tax: intel.sell_tax ?? null,
          },
        });
      } catch (e: any) {
        return failFrom(e);
      }
    }
  );

  server.registerTool(
    "check_address",
    {
      title: "Check counterparty address",
      description:
        "Screen a wallet or contract address before sending funds to it or accepting funds from it. " +
        "Detects sanctions, phishing, theft, laundering, mixers, and known honeypot deployers. " +
        "Returns a verdict (ALLOW / WARN / BLOCK) with reasons. Call this before any outbound transfer or payout.",
      inputSchema: {
        address: z.string().describe("The 0x address to screen."),
        chain: chainSchema,
        risk_tolerance: toleranceSchema,
      },
    },
    async ({ address, chain, risk_tolerance }) => {
      const addr = address.trim();
      if (!isAddress(addr)) return fail(`"${addr}" is not a valid 0x address.`);
      try {
        const chainId = resolveChain(chain);
        const intel = await fetchAddressIntel(chainId, addr);
        const decision = decide(intel, "address", risk_tolerance as RiskTolerance);
        return ok({
          ...decision,
          target: { type: "address", address: addr, chain, chain_id: chainId },
        });
      } catch (e: any) {
        return failFrom(e);
      }
    }
  );

  server.registerTool(
    "check_approval",
    {
      title: "Check spender before approving",
      description:
        "Screen a spender contract before granting a token approval or allowance. " +
        "Unlimited approvals to a malicious spender are the single most common way agents and wallets are drained. " +
        "Returns a verdict (ALLOW / WARN / BLOCK). Call this before every approve() / permit().",
      inputSchema: {
        spender_address: z
          .string()
          .describe("The 0x spender contract that will receive the allowance."),
        chain: chainSchema,
        risk_tolerance: toleranceSchema,
      },
    },
    async ({ spender_address, chain, risk_tolerance }) => {
      const addr = spender_address.trim();
      if (!isAddress(addr)) return fail(`"${addr}" is not a valid 0x address.`);
      try {
        const chainId = resolveChain(chain);
        const [approval, address] = await Promise.all([
          fetchApprovalIntel(chainId, addr).catch(() => ({ _found: false })),
          fetchAddressIntel(chainId, addr).catch(() => ({ _found: false })),
        ]);
        const merged = { ...approval, ...address, _found: (approval as any)._found || (address as any)._found };
        const decision = decide(merged, "address", risk_tolerance as RiskTolerance);
        return ok({
          ...decision,
          target: { type: "spender", address: addr, chain, chain_id: chainId },
          advice:
            decision.verdict === "ALLOW"
              ? "Approve only the exact amount required. Never grant an unlimited allowance, even to a clean spender."
              : "Do not approve. Revoke any existing allowance to this spender.",
        });
      } catch (e: any) {
        return failFrom(e);
      }
    }
  );

  return server;
}

const app = express();
app.use(express.json({ limit: "1mb" }));

app.get("/", (_req, res) => {
  res.json({
    service: "preflight",
    version: "1.0.0",
    description: "Agent-native onchain safety gate. Check before you sign.",
    mcp_endpoint: "/mcp",
    tools: ["check_token", "check_address", "check_approval"],
    chains: Object.keys(CHAINS),
  });
});

app.get("/health", (_req, res) => res.json({ status: "ok" }));

app.post("/mcp", async (req: Request, res: Response) => {
  const server = buildServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined, // stateless
  });
  res.on("close", () => {
    transport.close();
    server.close();
  });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal server error" },
        id: null,
      });
    }
  }
});

// MCP is POST-only in stateless mode. The spec expects a JSON-RPC 405 for
// GET (SSE stream) and DELETE (session teardown), not an HTML 404 - some
// clients and validators probe these before they trust the endpoint.
const methodNotAllowed = (_req: Request, res: Response) => {
  res.status(405).json({
    jsonrpc: "2.0",
    error: {
      code: -32000,
      message:
        "Method not allowed. This is a stateless MCP endpoint - send JSON-RPC via POST /mcp.",
    },
    id: null,
  });
};

app.get("/mcp", methodNotAllowed);
app.delete("/mcp", methodNotAllowed);

const PORT = Number(process.env.PORT ?? 3000);
app.listen(PORT, () => {
  console.log(`preflight ASP listening on :${PORT}  (MCP at POST /mcp)`);
});
