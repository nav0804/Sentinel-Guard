import Redis from "ioredis";
import { CachedResult, IncomingRequestSchema } from "../../schemas/src";
import { createHash } from "crypto";

export const redis = new Redis(process.env.REDIS ?? "redis://localhost:6379");

export function hashRequest(req: IncomingRequestSchema):string{
    const rawReq = `${req.method}:${req.route}:${JSON.stringify(req.body ?? ' ')}`;
    return createHash('sha256').update(rawReq).digest('hex');
}

const CACHE_TTL = 60 * 60;

export async function getCachedResult(hash:string):Promise<CachedResult | null>{
    const raw = await redis.get(`sg:cache:${hash}`);
    return raw ? JSON.parse(raw) : null;
}

export async function setCachedResult(hash:string, result:CachedResult): Promise<void>{
    await redis.setex(`sg.cache:${hash}`, CACHE_TTL, JSON.stringify(result));
}
