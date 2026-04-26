import { Redis } from "ioredis";
import { Cached, IncomingRequest } from "@sentinel/schemas";
import { createHash } from "crypto";

export const redis = new Redis(
  process.env.REDIS_URL ?? "redis://localhost:6379"
);

export function hashRequest(req: IncomingRequest): string {
  const hashable = {
    method: req.method,
    route: req.route,
    body: req.body ?? "",
  };
  const raw = JSON.stringify(hashable);
  return createHash("sha256").update(raw).digest("hex");
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
