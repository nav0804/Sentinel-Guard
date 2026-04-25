import { z } from "zod";

export const IncomingRequestSchema = z.object({
  method: z.enum(["GET", "POST", "PATCH", "PUT", "DELETE"]),
  route: z.string(),
  header: z.record(z.string(), z.union([z.string(), z.array(z.string())])),
  body: z.unknown().optional(),
  ip: z.string(),
});

export type IncomingRequestSchema = z.infer<typeof IncomingRequestSchema>;

export const VerdictSchema = z.object({
  decision: z.enum(["SAFE", "MALCIOUS"]),
  reason: z.string(),
  tier: z.number().int().min(1).max(5),
  latencyMs: z.number().optional(),
});

export type VerdictSchema = z.infer<typeof VerdictSchema>;

export const CachedResult = z.object({
  decision: z.enum(["SAFE", "MALCIOUS"]),
  cachedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
});

export type CachedResult = z.infer<typeof CachedResult>;

export const IpRecordSchema = z.object({
    ip: z.string(),
    trustScore: z.number().min(0).max(100),
    requestCount: z.number(),
    isBlocker: z.boolean()
})

export type IpRecordSchema = z.infer<typeof IpRecordSchema>