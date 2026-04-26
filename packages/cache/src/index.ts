import { Redis } from "ioredis";
import { Cached, IncomingRequest } from "@sentinel/schemas";
import { createHash } from "crypto";

export const redis = new Redis(
  process.env.REDIS_URL ?? "redis://localhost:6379"
);

export function hashRequest(req: IncomingRequest): string {
  // Explicitly pick ONLY what defines a unique request
  const rawData = JSON.stringify({
    m: req.method,
    r: req.route,
    b: req.body ?? {},
    // Don't hash all headers (too much noise like 'User-Agent' or 'Cookie')
    // Just hash the ones that matter for security, or skip headers if not needed.
  });

  return createHash("sha256").update(rawData).digest("hex");
}

const CACHE_TTL = 60 * 60; // 1 hour

export async function getCachedResult(hash: string): Promise<Cached | null> {
  const raw = await redis.get(`sg:cache:${hash}`);
  return raw ? JSON.parse(raw) : null;
}

export async function setCachedResult(
  hash: string,
  result: Cached
): Promise<void> {
  await redis.setex(`sg:cache:${hash}`, CACHE_TTL, JSON.stringify(result)); // ← colon not dot
}
