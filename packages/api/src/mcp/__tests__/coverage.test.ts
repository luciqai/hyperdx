import { assertMcpCoverage } from '@/mcp/utils/coverage';

function serverWith(tools: string[], prompts: string[]) {
  return {
    _registeredTools: Object.fromEntries(tools.map(t => [t, {}])),
    _registeredPrompts: Object.fromEntries(prompts.map(p => [p, {}])),
  } as any;
}

const TOOLS = Array.from({ length: 28 }, (_, i) => `tool_${i}`);
const PROMPTS = ['create_dashboard', 'dashboard_examples', 'query_guide'];

const allDeclared = (names: string[]) =>
  new Map(names.map(n => [n, 'sources:read' as const]));

describe('assertMcpCoverage', () => {
  it('passes when every tool and prompt declares a permission', () => {
    expect(() =>
      assertMcpCoverage(
        serverWith(TOOLS, PROMPTS),
        allDeclared(TOOLS),
        allDeclared(PROMPTS),
      ),
    ).not.toThrow();
  });

  // SEC-1's root cause: the assertion inspected _registeredTools only, so an
  // undeclared prompt sailed past a check that was passing on 28 tools.
  it('fails when a prompt declares no permission', () => {
    expect(() =>
      assertMcpCoverage(
        serverWith(TOOLS, PROMPTS),
        allDeclared(TOOLS),
        allDeclared(['query_guide']),
      ),
    ).toThrow(/prompt.*create_dashboard/s);
  });

  it('fails when a tool declares no permission', () => {
    expect(() =>
      assertMcpCoverage(
        serverWith(TOOLS, PROMPTS),
        allDeclared(TOOLS.slice(1)),
        allDeclared(PROMPTS),
      ),
    ).toThrow(/tool.*tool_0/s);
  });

  // Non-vacuity, per slice C §12: a walker that enumerates nothing must not
  // pass. Guards each surface independently.
  it('fails vacuously-empty tool enumeration', () => {
    expect(() =>
      assertMcpCoverage(
        serverWith([], PROMPTS),
        new Map(),
        allDeclared(PROMPTS),
      ),
    ).toThrow(/could not enumerate registered tools/);
  });

  it('fails vacuously-empty prompt enumeration', () => {
    expect(() =>
      assertMcpCoverage(serverWith(TOOLS, []), allDeclared(TOOLS), new Map()),
    ).toThrow(/could not enumerate registered prompts/);
  });

  it('fails a tool list that shrank below the expected floor', () => {
    const few = TOOLS.slice(0, 5);
    expect(() =>
      assertMcpCoverage(
        serverWith(few, PROMPTS),
        allDeclared(few),
        allDeclared(PROMPTS),
      ),
    ).toThrow(/could not enumerate registered tools/);
  });
});
