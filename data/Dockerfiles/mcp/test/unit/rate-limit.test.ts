import { expect, test } from "vitest";

import { createIpRateLimiter } from "../../src/http/rate-limit.js";

test("bounds IP buckets and admits new clients after stale eviction", async () => {
  let now = 0;
  const limiter = createIpRateLimiter({
    limit: 10,
    windowMs: 100,
    maxEntries: 2,
    sweepIntervalMs: 10,
    now: () => now,
  });

  expect(limiter.consume("2001:db8::1")).toEqual({ allowed: true });
  expect(limiter.consume("2001:db8::2")).toEqual({ allowed: true });
  expect(limiter.consume("2001:db8::3")).toEqual({
    allowed: false,
    retryAfter: 1,
  });

  now = 101;
  expect(limiter.consume("2001:db8::3")).toEqual({ allowed: true });
});
