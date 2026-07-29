import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

import type { AccountContext } from "./context.js";

export function createMcpServer(_context: AccountContext): McpServer {
  const server = new McpServer({ name: "mailcow-mcp", version: "0.1.0" });

  // The endpoint advertises tools/list now so clients can initialize safely;
  // mailbox tools are intentionally introduced in a later phase.
  server.server.registerCapabilities({ tools: {} });
  server.server.setRequestHandler(ListToolsRequestSchema, () => ({ tools: [] }));

  return server;
}
