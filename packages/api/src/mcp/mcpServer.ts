import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import { CODE_VERSION } from '@/config';

import dashboardPrompts from './prompts/dashboards/index';
import alertsTools from './tools/alerts/index';
import dashboardsTools from './tools/dashboards/index';
import queryTools from './tools/query/index';
import savedSearchesTools from './tools/savedSearches/index';
import sourcesTools from './tools/sources/index';
import traceTools from './tools/trace/index';
import { McpContext } from './tools/types';
import { assertMcpCoverage } from './utils/coverage';
import {
  createRegisterPrompt,
  type DeclaredPrompts,
} from './utils/registerPrompt';
import {
  createRegisterTool,
  type DeclaredPermissions,
} from './utils/registerTool';

export function createServer(context: McpContext) {
  const server = new McpServer({
    name: 'clickstack',
    version: `${CODE_VERSION}-beta`,
  });

  const declaredTools: DeclaredPermissions = new Map();
  const declaredPrompts: DeclaredPrompts = new Map();
  const registerTool = createRegisterTool(server, context, declaredTools);
  const registerPrompt = createRegisterPrompt(server, context, declaredPrompts);
  const registrar = { server, context, registerTool };

  sourcesTools(registrar);
  alertsTools(registrar);
  dashboardsTools(registrar);
  queryTools(registrar);
  savedSearchesTools(registrar);
  traceTools(registrar);
  dashboardPrompts({ server, context, registerPrompt });

  // Every tool AND prompt must declare a permission. A new one that forgets
  // fails here rather than shipping ungated — the runtime half of the
  // guarantee. Prompts are included because SEC-1 was exactly a prompt
  // surface that this assertion could not see.
  assertMcpCoverage(server, declaredTools, declaredPrompts);

  return server;
}
