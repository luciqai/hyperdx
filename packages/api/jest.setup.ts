// Overridable via JEST_RETRY_TIMES (e.g. the nightly zero-retry flake hunt).
// Honours an explicit 0 so retries can be forced off; an unset/blank/negative/
// non-integer value falls back to the default of 1 rather than coercing to 0.
const rawJestRetries = process.env.JEST_RETRY_TIMES;
const parsedJestRetries = rawJestRetries ? Number(rawJestRetries) : NaN;
jest.retryTimes(
  Number.isInteger(parsedJestRetries) && parsedJestRetries >= 0
    ? parsedJestRetries
    : 1,
  { logErrorsBeforeRetry: true },
);

// Rate limiter counters are process-global and keyed by origin, so every test
// in a file shares one bucket. The pre-auth limiters meter failed requests, and
// integration suites assert dozens of 4xx responses, so without this a suite
// exhausts a production-realistic failed-attempt budget partway through and
// unrelated cases start seeing 429. Reset between tests, alongside the DBs.
afterEach(async () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { resetRateLimitersForTests } = require('@/utils/rateLimiter');
  await resetRateLimitersForTests();
});

// http-proxy-middleware v4 is ESM-only and Jest's CJS module loader cannot
// load ESM packages. Auto-mock it; the clickhouse-proxy int tests opt out via
// jest.unmock() (jest.int.config.js transpiles the package for them).
jest.mock('http-proxy-middleware', () => ({
  createProxyMiddleware: jest.fn(() => jest.fn()),
}));

// Suppress noisy console output during test runs.
// - debug/info: ClickHouse query logging, server startup messages
// - warn: expected column-not-found warnings from renderChartConfig on CTE tables
jest.spyOn(console, 'debug').mockImplementation(() => {});
jest.spyOn(console, 'info').mockImplementation(() => {});
jest.spyOn(console, 'warn').mockImplementation(() => {});

// Mock alert notification functions to prevent HTTP calls during tests
jest.mock('@/utils/slack', () => ({
  ...jest.requireActual('@/utils/slack'),
  postMessageToWebhook: jest.fn().mockResolvedValue(null),
}));

// Mock global fetch for generic webhook calls
global.fetch = jest.fn().mockResolvedValue({
  ok: true,
  text: jest.fn().mockResolvedValue(''),
  json: jest.fn().mockResolvedValue({}),
} as any);
