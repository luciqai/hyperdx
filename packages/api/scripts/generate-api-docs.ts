import fs from 'fs';
import path from 'path';
import swaggerJsdoc from 'swagger-jsdoc';

// Relative rather than `@/` for this entry import, but the script is now run
// with `-r tsconfig-paths/register`: `swagger.ts` pulls in the RBAC middleware
// (for `noPermissionRequired` on the docs route), and that transitively imports
// `@/config` and `@/utils/*`, which cannot resolve without the hook.
// eslint-disable-next-line no-restricted-imports
import { swaggerOptions } from '../src/utils/swagger';

const specs = swaggerJsdoc(swaggerOptions);
const outputPath = path.resolve(__dirname, '../openapi.json');
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, JSON.stringify(specs, null, 2));

console.log(`OpenAPI specification written to ${outputPath}`);
