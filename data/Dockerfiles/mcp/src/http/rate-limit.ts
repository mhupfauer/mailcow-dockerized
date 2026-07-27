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

export type RateLimitDecision =
  | { allowed: true }
  | { allowed: false; retryAfter: number };

export interface IpRateLimiter {
  consume(ip: string): RateLimitDecision;
}

export function createIpRateLimiter({
  limit,
  windowMs,
  maxEntries = 10_000,
  sweepIntervalMs = Math.min(windowMs, 60_000),
  now: currentTime = Date.now,
}: IpRateLimitOptions): IpRateLimiter {
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

  return {
    consume(ip) {
      const now = currentTime();
      sweep(now);
      let window = windows.get(ip);
      if (window !== undefined && now - window.startedAt >= windowMs) {
        windows.delete(ip);
        window = undefined;
      }

      if (window === undefined) {
        if (windows.size >= maxEntries) {
          sweep(now, true);
        }
        if (windows.size >= maxEntries) {
          return {
            allowed: false,
            retryAfter: Math.ceil(windowMs / 1_000),
          };
        }
        window = { count: 0, startedAt: now };
        windows.set(ip, window);
      }

      if (window.count >= limit) {
        return {
          allowed: false,
          retryAfter: Math.max(
            1,
            Math.ceil((window.startedAt + windowMs - now) / 1_000),
          ),
        };
      }

      window.count += 1;
      return { allowed: true };
    },
  };
}
