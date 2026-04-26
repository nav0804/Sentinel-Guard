import { redis } from "@sentinel/cache";
import { IpRecord, Verdict } from "@sentinel/schemas";

const RATE_LIMIT = 100;
const WINDOW_SEC = 60;
const SAMPLE_RATE = 10; //Rating

export async function getIpRecord(ip: string): Promise<IpRecord> {
  const raw = await redis.get(`sg:ip:${ip}`);
  if (raw) return JSON.parse(raw);
  return { ip, trustScore: 50, requestCount: 0, isBlocked: false };
}

export async function checkRateLimit(ip: string): Promise<Verdict | null> {
  const key = `sg:rl:${ip}`;
  const count = await redis.incr(key);
  if (count === 1) await redis.expire(key, WINDOW_SEC);
  if (count > RATE_LIMIT) {
    return { decision: "MALICIOUS", reason: "Rate limit exceeded", tier: 1 };
  }
  return null;
}

export async function shouldRunLLM(ip: string): Promise<boolean> {
  const ipRecord = await getIpRecord(ip);
  if (ipRecord.trustScore >= 80) {
    return ipRecord.requestCount % SAMPLE_RATE === 0;
  }
  return true;
}

export async function updateTrustScore(
  ip: string,
  delta: number
): Promise<void> {
  const record = await getIpRecord(ip);
  record.trustScore = Math.max(0, Math.min(100, record.trustScore + delta));
  record.requestCount++;
  await redis.set(`sg:ip:${ip}`, JSON.stringify(record));
}
