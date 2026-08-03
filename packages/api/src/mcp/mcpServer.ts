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
import {
  assertToolCoverage,
  createRegisterTool,
  type DeclaredPermissions,
} from './utils/registerTool';

export function createServer(context: McpContext) {
  const server = new McpServer({
    name: 'clickstack',
    version: `${CODE_VERSION}-beta`,
  });

  const declared: DeclaredPermissions = new Map();
  const registerTool = createRegisterTool(server, context, declared);
  const registrar = { server, context, registerTool };

  sourcesTools(registrar);
  alertsTools(registrar);
  dashboardsTools(registrar);
  queryTools(registrar);
  savedSearchesTools(registrar);
  traceTools(registrar);
  dashboardPrompts(server, context);

  // Every tool must declare a permission. A new tool that forgets one fails
  // here rather than shipping ungated — the runtime half of the guarantee.
  assertToolCoverage(server, declared);

  return server;
}
