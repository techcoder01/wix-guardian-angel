import {
  RATE_LIMIT_MAX_REQUESTS,
  RATE_LIMIT_PER_HOST_MAX,
  RATE_LIMIT_WINDOW_MS,
} from "@/lib/constants";

/**
 * Two-tier rate limiter: per-IP and per-target-host. Tries Cloudflare KV when
 * the binding is provided, falls back to in-memory (per-Worker-instance).
 *
 * The fallback is fine for local dev and dissertation demos. Production should
 * inject a KV namespace (or a Durable Object). Both paths share the same
 * sliding-window algorithm.
 */

export interface RateLimitStore {
  get(key: string): Promise<number[]>;
  set(key: string, value: number[], ttlMs: number): Promise<void>;
}

class MemoryStore implements RateLimitStore {
  private map = new Map<string, number[]>();
  async get(key: string) {
    return this.map.get(key) ?? [];
  }
  async set(key: string, value: number[]) {
    this.map.set(key, value);
  }
}

interface KvNamespace {
  get(key: string, type?: "json"): Promise<unknown>;
  put(
    key: string,
    value: string,
    options?: { expirationTtl?: number },
  ): Promise<void>;
}

class KvStore implements RateLimitStore {
  constructor(private kv: KvNamespace) {}
  async get(key: string): Promise<number[]> {
    const v = (await this.kv.get(key, "json")) as number[] | null;
    return v ?? [];
  }
  async set(key: string, value: number[], ttlMs: number) {
    await this.kv.put(key, JSON.stringify(value), {
      expirationTtl: Math.max(60, Math.ceil(ttlMs / 1000)),
    });
  }
}

const memoryFallback = new MemoryStore();

export function getStore(kv?: unknown): RateLimitStore {
  if (kv && typeof kv === "object" && "get" in kv && "put" in kv) {
    return new KvStore(kv as KvNamespace);
  }
  return memoryFallback;
}

export interface RateLimitVerdict {
  allowed: boolean;
  reason?: string;
  retryAfterMs?: number;
}

async function consume(
  store: RateLimitStore,
  key: string,
  max: number,
): Promise<RateLimitVerdict> {
  const now = Date.now();
  const existing = await store.get(key);
  const fresh = existing.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  if (fresh.length >= max) {
    const oldest = Math.min(...fresh);
    return {
      allowed: false,
      reason: `Rate limit exceeded for ${key}`,
      retryAfterMs: RATE_LIMIT_WINDOW_MS - (now - oldest),
    };
  }
  fresh.push(now);
  await store.set(key, fresh, RATE_LIMIT_WINDOW_MS);
  return { allowed: true };
}

export async function checkRateLimit(
  store: RateLimitStore,
  ip: string,
  host: string,
): Promise<RateLimitVerdict> {
  const ipVerdict = await consume(
    store,
    `ip:${ip}`,
    RATE_LIMIT_MAX_REQUESTS,
  );
  if (!ipVerdict.allowed) return ipVerdict;
  return consume(store, `host:${host}`, RATE_LIMIT_PER_HOST_MAX);
}
