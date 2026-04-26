import { z } from "zod";

export const IncomingRequestSchema = z.object({
  method: z.enum(["GET", "POST", "PATCH", "PUT", "DELETE"]),
  route: z.string(),
  headers: z.record(z.string(), z.union([z.string(), z.array(z.string())])),
  body: z.unknown().optional(),
  ip: z.string(),
});

export type IncomingRequest = z.infer<typeof IncomingRequestSchema>;

export const VerdictSchema = z.object({
  decision: z.enum(["SAFE", "MALICIOUS"]),
  reason: z.string(),
  tier: z.number().int().min(1).max(5),
  latencyMs: z.number().optional(),
});

export type Verdict = z.infer<typeof VerdictSchema>;

export const CachedResult = z.object({
  decision: z.enum(["SAFE", "MALICIOUS"]),
  cachedAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
});

export type Cached = z.infer<typeof CachedResult>;

export const IpRecordSchema = z.object({
  ip: z.string(),
  trustScore: z.number().min(0).max(100),
  requestCount: z.number(),
  isBlocked: z.boolean(),
});

export type IpRecord = z.infer<typeof IpRecordSchema>;
