// Unit tests for the query window runConfigTile gives a builder tile. Mocks
// the source/connection lookups and the ClickHouse client, so the chart config
// handed to the renderer can be inspected without ClickHouse or Mongo.

const mockGetSource = jest.fn();
const mockGetConnectionById = jest.fn();
const mockQueryChartConfig = jest.fn();

jest.mock('@/models/source', () => ({}));
jest.mock('@/controllers/sources', () => ({
  getSource: (...args: unknown[]) => mockGetSource(...args),
}));
jest.mock('@/controllers/connection', () => ({
  getConnectionById: (...args: unknown[]) => mockGetConnectionById(...args),
}));
jest.mock('@/clickhouse', () => ({
  ClickhouseClient: jest.fn().mockImplementation(() => ({
    queryChartConfig: (...args: unknown[]) => mockQueryChartConfig(...args),
  })),
}));

import { SourceKind } from '@hyperdx/common-utils/dist/types';
import mongoose from 'mongoose';

import {
  buildTile,
  resolveTimeChartRange,
  runConfigTile,
} from '@/mcp/tools/query/helpers';

const teamId = new mongoose.Types.ObjectId().toString();
const sourceId = new mongoose.Types.ObjectId().toString();
const connectionId = new mongoose.Types.ObjectId().toString();

// One hour that starts and ends mid-minute.
const start = new Date('2026-11-02T10:07:23Z');
const end = new Date('2026-11-02T11:07:23Z');
const at = (iso: string) => new Date(iso);

const logSource = {
  kind: SourceKind.Log,
  connection: { toString: () => connectionId },
  from: { databaseName: 'default', tableName: 'otel_logs' },
  timestampValueExpression: 'Timestamp',
};

const metricSource = {
  kind: SourceKind.Metric,
  connection: { toString: () => connectionId },
  from: { databaseName: 'default', tableName: '' },
  timestampValueExpression: 'TimeUnix',
  metricTables: { sum: 'otel_metrics_sum' },
  minAutoGranularity: '5 minute',
};

const countTile = (config: Record<string, unknown>) =>
  buildTile('Test tile', 12, 4, {
    sourceId,
    select: [{ aggFn: 'count', where: '' }],
    ...config,
  });

const increaseTile = (config: Record<string, unknown>) =>
  buildTile('Test tile', 12, 4, {
    sourceId,
    select: [
      {
        aggFn: 'increase',
        metricType: 'sum',
        metricName: 'http.requests',
        valueExpression: 'Value',
        where: '',
      },
    ],
    ...config,
  });

const queriedConfig = () => {
  expect(mockQueryChartConfig).toHaveBeenCalledTimes(1);
  return mockQueryChartConfig.mock.calls[0][0].config;
};

beforeEach(() => {
  jest.clearAllMocks();
  mockGetSource.mockResolvedValue(logSource);
  mockGetConnectionById.mockResolvedValue({
    host: 'http://localhost:8123',
    username: 'default',
    password: '',
  });
  mockQueryChartConfig.mockResolvedValue({ data: [], meta: [], rows: 0 });
});

describe('resolveTimeChartRange', () => {
  it('resolves auto granularity and widens the range to whole buckets', () => {
    // One hour over 80 buckets resolves to 1 minute.
    expect(resolveTimeChartRange({ dateRange: [start, end] })).toEqual({
      granularity: '1 minute',
      dateRange: [at('2026-11-02T10:07:00Z'), at('2026-11-02T11:08:00Z')],
      dateRangeEndInclusive: false,
    });
  });

  it('aligns to an explicit granularity', () => {
    expect(
      resolveTimeChartRange({
        granularity: '5 minute',
        dateRange: [start, end],
      }),
    ).toEqual({
      granularity: '5 minute',
      dateRange: [at('2026-11-02T10:05:00Z'), at('2026-11-02T11:10:00Z')],
      dateRangeEndInclusive: false,
    });
  });

  it('leaves an already aligned range as it is', () => {
    const alignedRange: [Date, Date] = [
      at('2026-11-02T10:00:00Z'),
      at('2026-11-02T11:00:00Z'),
    ];
    expect(
      resolveTimeChartRange({ dateRange: alignedRange }).dateRange,
    ).toEqual(alignedRange);
  });

  it('keeps the exact range, still end-exclusive, when alignment is off', () => {
    expect(
      resolveTimeChartRange({
        dateRange: [start, end],
        alignDateRangeToGranularity: false,
      }),
    ).toEqual({
      granularity: '1 minute',
      dateRange: [start, end],
      dateRangeEndInclusive: false,
    });
  });

  it('floors auto granularity at the minimum granularity', () => {
    expect(
      resolveTimeChartRange({
        dateRange: [start, end],
        minGranularitySeconds: 300,
      }),
    ).toMatchObject({
      granularity: '5 minute',
      dateRange: [at('2026-11-02T10:05:00Z'), at('2026-11-02T11:10:00Z')],
    });
  });
});

describe('runConfigTile query window', () => {
  it('queries a line tile over whole buckets with an exclusive end', async () => {
    await runConfigTile(teamId, countTile({ displayType: 'line' }), start, end);

    expect(queriedConfig()).toMatchObject({
      granularity: '1 minute',
      dateRange: [at('2026-11-02T10:07:00Z'), at('2026-11-02T11:08:00Z')],
      dateRangeEndInclusive: false,
    });
  });

  it.each(['stacked_bar', 'stacked_line'])(
    'queries a %s tile the same way',
    async displayType => {
      await runConfigTile(teamId, countTile({ displayType }), start, end);

      expect(queriedConfig()).toMatchObject({
        granularity: '1 minute',
        dateRange: [at('2026-11-02T10:07:00Z'), at('2026-11-02T11:08:00Z')],
        dateRangeEndInclusive: false,
      });
    },
  );

  it('aligns to the granularity the caller asked for', async () => {
    await runConfigTile(
      teamId,
      countTile({ displayType: 'line' }),
      start,
      end,
      { granularity: '5 minute' },
    );

    expect(queriedConfig()).toMatchObject({
      granularity: '5 minute',
      dateRange: [at('2026-11-02T10:05:00Z'), at('2026-11-02T11:10:00Z')],
      dateRangeEndInclusive: false,
    });
  });

  it('keeps the exact range when the tile turns alignment off', async () => {
    await runConfigTile(
      teamId,
      countTile({ displayType: 'line', alignDateRangeToGranularity: false }),
      start,
      end,
    );

    expect(queriedConfig()).toMatchObject({
      granularity: '1 minute',
      dateRange: [start, end],
      dateRangeEndInclusive: false,
    });
  });

  it("floors a metric tile's auto granularity at the source's minimum", async () => {
    mockGetSource.mockResolvedValue(metricSource);

    await runConfigTile(
      teamId,
      increaseTile({ displayType: 'line' }),
      start,
      end,
    );

    expect(queriedConfig()).toMatchObject({
      granularity: '5 minute',
      dateRange: [at('2026-11-02T10:05:00Z'), at('2026-11-02T11:10:00Z')],
      dateRangeEndInclusive: false,
      minGranularitySeconds: 300,
    });
  });

  it('leaves a number tile on the exact, end-inclusive range', async () => {
    mockGetSource.mockResolvedValue(metricSource);

    await runConfigTile(
      teamId,
      increaseTile({ displayType: 'number' }),
      start,
      end,
    );

    const config = queriedConfig();
    expect(config.dateRange).toEqual([start, end]);
    expect(config.granularity).toBeUndefined();
    expect(config.dateRangeEndInclusive).toBeUndefined();
    expect(config.minGranularitySeconds).toBe(300);
  });

  it('leaves a table tile on the exact, end-inclusive range', async () => {
    await runConfigTile(
      teamId,
      countTile({ displayType: 'table', groupBy: 'ServiceName' }),
      start,
      end,
    );

    const config = queriedConfig();
    expect(config.dateRange).toEqual([start, end]);
    expect(config.granularity).toBeUndefined();
    expect(config.dateRangeEndInclusive).toBeUndefined();
  });
});
