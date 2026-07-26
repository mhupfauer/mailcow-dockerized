import type Koa from "koa";
import { expect, test, vi } from "vitest";

import { createIpRateLimiter } from "../../src/http/rate-limit.js";

function fakeContext(ip: string): Koa.Context {
  return {
    ip,
    set: vi.fn(),
  } as unknown as Koa.Context;
}

test("bounds IP buckets and admits new clients after stale eviction", async () => {
  let now = 0;
  const limiter = createIpRateLimiter({
    limit: 10,
    windowMs: 100,
    maxEntries: 2,
    sweepIntervalMs: 10,
    now: () => now,
  });
  const firstNext = vi.fn();
  const secondNext = vi.fn();
  const blockedNext = vi.fn();

  await limiter(fakeContext("2001:db8::1"), firstNext);
  await limiter(fakeContext("2001:db8::2"), secondNext);
  const blocked = fakeContext("2001:db8::3");
  await limiter(blocked, blockedNext);

  expect(firstNext).toHaveBeenCalledOnce();
  expect(secondNext).toHaveBeenCalledOnce();
  expect(blockedNext).not.toHaveBeenCalled();
  expect(blocked.status).toBe(429);

  now = 101;
  const admittedNext = vi.fn();
  await limiter(fakeContext("2001:db8::3"), admittedNext);

  expect(admittedNext).toHaveBeenCalledOnce();
});
