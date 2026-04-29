import { describe, it, expect } from "vitest";
import { checkRateLimit, getStore } from "@/utils/rate-limit";
import {
  RATE_LIMIT_MAX_REQUESTS,
  RATE_LIMIT_PER_HOST_MAX,
} from "@/lib/constants";

describe("rate limit", () => {
  it("allows under the limit", async () => {
    const store = getStore();
    const v = await checkRateLimit(store, "1.1.1.1", "example-1.com");
    expect(v.allowed).toBe(true);
  });

  it("blocks once IP exceeds per-IP max", async () => {
    const store = getStore();
    const ip = "2.2.2.2";
    for (let i = 0; i < RATE_LIMIT_MAX_REQUESTS; i++) {
      await checkRateLimit(store, ip, `host-${i}.com`);
    }
    const v = await checkRateLimit(store, ip, "host-final.com");
    expect(v.allowed).toBe(false);
    expect(v.reason).toMatch(/Rate limit/);
    expect(v.retryAfterMs).toBeGreaterThan(0);
  });

  it("blocks once host exceeds per-host max independently of IP", async () => {
    const store = getStore();
    const host = "shared-host.example";
    for (let i = 0; i < RATE_LIMIT_PER_HOST_MAX; i++) {
      await checkRateLimit(store, `ip-${i}.0.0.1`, host);
    }
    const v = await checkRateLimit(store, "fresh.ip.0.0", host);
    expect(v.allowed).toBe(false);
  });
});
