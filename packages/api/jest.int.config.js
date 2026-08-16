const base = require('./jest.config.js');

/** @type {import("jest").Config} **/
module.exports = {
  ...base,
  testMatch: ['**/__tests__/**/*.int.test.ts?(x)'],
  // The base config pins `rootDir: './src'`, which would hide integration
  // tests that live outside it — notably the migration tests under
  // `migrations/`. Widening `roots` makes them discoverable without moving
  // `rootDir` (which ts-jest needs for the TS6 explicit-rootDir requirement).
  roots: ['<rootDir>', '<rootDir>/../migrations'],
  // Override the unit config's ignore list: it excludes `.int.test.ts`, which
  // would otherwise hide every integration test from this suite.
  testPathIgnorePatterns: ['<rootDir>/node_modules/'],
};
