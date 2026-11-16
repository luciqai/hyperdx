---
'@hyperdx/api': patch
---

fix: MCP `clickstack_timeseries`, `clickstack_query_tile` and `clickstack_query_tiles` query line and stacked charts over the window the dashboard uses: the range is widened to whole time buckets (unless the tile turns "Show Complete Intervals" off) and its end is exclusive. The result no longer ends with an extra bucket that starts at the range end. Auto granularity resolves as it does in the app, including the metric source's minimum auto granularity
