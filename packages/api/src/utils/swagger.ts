import { Application } from 'express';
import fs from 'fs';
import path from 'path';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';

import { noPermissionRequired } from '@/middleware/rbac';

export const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'HyperDX External API',
      description: 'API for managing HyperDX alerts and dashboards',
      version: '2.0.0',
    },
    servers: [
      {
        url: '/',
        description: 'Your HyperDX instance (http://<host>:<port>)',
      },
    ],
    tags: [
      {
        name: 'Dashboards',
        description:
          'Endpoints for managing dashboards and their visualizations',
      },
      {
        name: 'Alerts',
        description: 'Endpoints for managing monitoring alerts',
      },
      {
        name: 'Charts',
        description: 'Endpoints for querying chart data',
      },
      {
        name: 'Connections',
        description: 'Endpoints for managing ClickHouse connections',
      },
      {
        name: 'Sources',
        description: 'Endpoints for managing data sources',
      },
      {
        name: 'Webhooks',
        description: 'Endpoints for managing webhooks',
      },
      {
        name: 'Search',
        description:
          'Endpoints for querying raw data from log and trace sources',
      },
    ],
    components: {
      securitySchemes: {
        BearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'API Key',
        },
      },
    },
    security: [
      {
        BearerAuth: [],
      },
    ],
  },
  apis: ['./src/routers/external-api/**/*.ts'], // Path to the API routes files
};

export function setupSwagger(app: Application) {
  const specs = swaggerJsdoc(swaggerOptions);

  // Serve swagger docs
  app.use('/api/v2/docs', swaggerUi.serve, swaggerUi.setup(specs));

  // Serve OpenAPI spec as JSON (needed for ReDoc).
  //
  // Declared public: the spec is static API documentation carrying no team
  // data, and this route is not behind validateUserAccessKey. The declaration
  // is required because slice C brought /api/v2 under the RBAC coverage
  // assertion — without it the server refuses to boot wherever
  // ENABLE_SWAGGER is set, which is the default in .env.development.
  app.get('/api/v2/docs.json', noPermissionRequired('public'), (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(specs);
  });

  // Optionally save the spec to a file
  const outputPath = path.resolve(__dirname, '../../openapi.json');
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(specs, null, 2));
}
