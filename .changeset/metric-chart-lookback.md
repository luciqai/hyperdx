---
'@hyperdx/common-utils': patch
---

fix: Number, pie and table charts on cumulative counter and histogram metrics now count the first sample of each series in the selected range. These charts have no time bucket, so the query read nothing before the range start and that sample had no previous value to subtract. The query now reads back one auto-granularity interval (at least 5 minutes) before the range and aggregates only the samples inside it, so these charts agree with a time chart over the same range. Their values read slightly higher than before; gauges and delta-temporality metrics are unchanged
