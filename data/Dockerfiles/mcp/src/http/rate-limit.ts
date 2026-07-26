import type Koa from "koa";

interface IpRateLimitOptions {
  limit: number;
  windowMs: number;
  maxEntries?: number;
  sweepIntervalMs?: number;
  now?: () => number;
}

interface Window {
  count: number;
  startedAt: number;
}

export function createIpRateLimiter({
  limit,
  windowMs,
  maxEntries = 10_000,
  sweepIntervalMs = Math.min(windowMs, 60_000),
  now: currentTime = Date.now,
}: IpRateLimitOptions): Koa.Middleware {
  if (!Number.isSafeInteger(limit) || limit < 1) {
    throw new Error("rate limit must be a positive integer");
  }
  if (!Number.isSafeInteger(windowMs) || windowMs < 1) {
    throw new Error("rate limit window must be a positive integer");
  }
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
    throw new Error("rate limit max entries must be a positive integer");
  }
  if (!Number.isSafeInteger(sweepIntervalMs) || sweepIntervalMs < 1) {
    throw new Error("rate limit sweep interval must be a positive integer");
  }

  const windows = new Map<string, Window>();
  let nextSweepAt = 0;

  function sweep(now: number, force = false): void {
    if (!force && now < nextSweepAt) {
      return;
    }
    for (const [ip, window] of windows) {
      if (now - window.startedAt >= windowMs) {
        windows.delete(ip);
      }
    }
    nextSweepAt = now + sweepIntervalMs;
  }

  function reject(context: Koa.Context, retryAfter: number): void {
    context.set("Retry-After", retryAfter.toString());
    context.status = 429;
    context.body = {
      error: "too_many_requests",
      error_description: "registration rate limit exceeded",
    };
  }

  return async (context, next) => {
    const now = currentTime();
    sweep(now);
    const key = context.ip;
    let window = windows.get(key);
    if (window !== undefined && now - window.startedAt >= windowMs) {
      windows.delete(key);
      window = undefined;
    }

    if (window === undefined) {
      if (windows.size >= maxEntries) {
        sweep(now, true);
      }
      if (windows.size >= maxEntries) {
        reject(context, Math.ceil(windowMs / 1_000));
        return;
      }
      window = { count: 0, startedAt: now };
      windows.set(key, window);
    }

    if (window.count >= limit) {
      const retryAfter = Math.max(
        1,
        Math.ceil((window.startedAt + windowMs - now) / 1_000),
      );
      reject(context, retryAfter);
      return;
    }

    window.count += 1;
    await next();
  };
}
