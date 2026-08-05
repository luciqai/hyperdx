import { validateColumnsExpression } from '@/routers/external-api/v2/search';

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
