import { guardedSeriesSchema } from '@/routers/external-api/v2/charts';
import {
  searchRequestSchema,
  validateColumnsExpression,
} from '@/routers/external-api/v2/search';

// Valid ObjectId strings used across schema-level cases below.
const SOURCE_ID = '69b46cb0d964ce2d0b9506a8';

describe('validateColumnsExpression', () => {
  it('accepts ordinary column expressions', () => {
    expect(validateColumnsExpression('Timestamp, ServiceName')).toBe(true);
    expect(validateColumnsExpression('count()')).toBe(true);
    expect(validateColumnsExpression('')).toBe(true);
  });

  it('accepts identifiers that merely contain the keyword', () => {
    expect(validateColumnsExpression('selectId')).toBe(true);
  });

  it('rejects semicolons and bare subqueries', () => {
    expect(validateColumnsExpression('a; DROP TABLE x')).toBe(false);
    expect(validateColumnsExpression('(SELECT 1)')).toBe(false);
  });

  // BUG-9, demonstrated live: /**/ defeated the bare SELECT\s anchor and
  // returned 200 on (SELECT/**/groupArray(name) FROM system.users).
  it('rejects a subquery hidden behind a block comment', () => {
    expect(
      validateColumnsExpression(
        '(SELECT/**/groupArray(name) FROM system.users)',
      ),
    ).toBe(false);
  });

  it('rejects a subquery hidden behind a line comment', () => {
    expect(validateColumnsExpression('(SELECT--x\ngroupArray(name))')).toBe(
      false,
    );
  });

  it('rejects a comment-split semicolon', () => {
    expect(validateColumnsExpression('a/**/;/**/b')).toBe(false);
  });
});

describe('searchRequestSchema (schema-level wiring for /search)', () => {
  it('accepts a literal "SELECT foo" in `where` when whereLanguage is omitted (defaults to lucene)', () => {
    const result = searchRequestSchema.safeParse({
      sourceId: SOURCE_ID,
      where: 'SELECT foo',
      // whereLanguage intentionally omitted — must default to 'lucene' and
      // the where guard (SQL-only) must not fire.
    });
    expect(result.success).toBe(true);
  });

  it('accepts a `where` with a semicolon or subquery when whereLanguage is explicitly "lucene"', () => {
    const result = searchRequestSchema.safeParse({
      sourceId: SOURCE_ID,
      whereLanguage: 'lucene',
      where: 'a; (SELECT 1)',
    });
    expect(result.success).toBe(true);
  });

  it('rejects a comment-obfuscated subquery in `where` when whereLanguage is "sql"', () => {
    const result = searchRequestSchema.safeParse({
      sourceId: SOURCE_ID,
      whereLanguage: 'sql',
      where: '(SELECT/**/groupArray(name) FROM system.users)',
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues).toContainEqual(
        expect.objectContaining({ path: ['where'] }),
      );
    }
  });

  it('accepts a clean `where` when whereLanguage is "sql"', () => {
    const result = searchRequestSchema.safeParse({
      sourceId: SOURCE_ID,
      whereLanguage: 'sql',
      where: "SeverityText = 'ERROR'",
    });
    expect(result.success).toBe(true);
  });
});

describe('guardedSeriesSchema (schema-level wiring for /charts/series)', () => {
  const baseSeries = {
    sourceId: SOURCE_ID,
    aggFn: 'count' as const,
    groupBy: [] as string[],
  };

  it('rejects a comment-obfuscated subquery in a series `where` when whereLanguage is "sql"', () => {
    const result = guardedSeriesSchema.safeParse({
      ...baseSeries,
      whereLanguage: 'sql',
      where: '(SELECT/**/groupArray(name) FROM system.users)',
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues).toContainEqual(
        expect.objectContaining({ path: ['where'] }),
      );
    }
  });

  it('accepts a series `where` containing a subquery-shaped string when whereLanguage is "lucene"', () => {
    const result = guardedSeriesSchema.safeParse({
      ...baseSeries,
      whereLanguage: 'lucene',
      where: '(SELECT 1)',
    });
    expect(result.success).toBe(true);
  });
});
