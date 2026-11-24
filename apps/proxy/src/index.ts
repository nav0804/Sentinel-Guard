import Fastify from "fastify";
import { IncomingRequestSchema } from "@sentinel/schemas";
import { logger } from "@sentinel/logger";
import { runPipeline } from "@sentinel/pipeline";
import { initializeMLModel } from "@sentinel/ml-detector";
import * as fs from "fs";
import * as path from "path";

const app = Fastify({ logger: false });
const DOWNSTREAM = process.env.DOWNSTREAM_URL ?? "http://localhost:4000";

app.get("/api/stats", async (req, reply) => {
  const LOG_DIR = path.join(process.cwd(), "../../logs");
  const EVENT_LOG_PATH = path.join(LOG_DIR, "waf-events.jsonl");

  if (!fs.existsSync(EVENT_LOG_PATH)) {
    return reply.send({
      total: 0,
      blocked: 0,
      allowed: 0,
      byTier: {},
      recent: [],
    });
  }

  const fileContent = fs.readFileSync(EVENT_LOG_PATH, "utf-8");
  const lines = fileContent.trim().split("\n").filter(Boolean);
  const events = lines.map((line) => JSON.parse(line));

  const total = events.length;
  const blocked = events.filter((e: any) => e.decision === "MALICIOUS").length;
  const allowed = total - blocked;

  const byTier: Record<string, number> = {};
  events
    .filter((e: any) => e.decision === "MALICIOUS")
    .forEach((e: any) => {
      const tierName = `Tier ${e.tier}`;
      byTier[tierName] = (byTier[tierName] || 0) + 1;
    });

  const recent = events
    .filter((e: any) => e.decision === "MALICIOUS")
    .slice(-10)
    .reverse()
    .map((e: any) => ({
      ...e,
      time: new Date(e.timestamp).toLocaleTimeString(),
    }));

  return reply.send({ total, blocked, allowed, byTier, recent });
});

// Ensure logs directory exists
const LOG_DIR = path.join(process.cwd(), "../../logs");
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
const EVENT_LOG_PATH = path.join(LOG_DIR, "waf-events.jsonl");

app.setErrorHandler((error: Error, req, reply) => {
  logger.error({ error: error.message, ip: req.ip }, "Request error");
  reply
    .code(500)
    .send({ error: "Internal Server Error", message: error.message });
});

app.all("/*", async (req, reply) => {
  try {
    const safeHeaders: Record<string, string> = {};
    for (const [key, value] of Object.entries(req.headers)) {
      if (
        !["host", "content-length", "connection"].includes(key.toLowerCase())
      ) {
        safeHeaders[key] = Array.isArray(value)
          ? value.join(", ")
          : String(value || "");
      }
    }

    const cleanRequest = {
      method: String(req.method),
      route: String(req.url),
      headers: safeHeaders,
      body: req.body ?? {},
      ip: String(req.ip),
    };

    const parsed = IncomingRequestSchema.safeParse(cleanRequest);
    if (!parsed.success) {
      return reply
        .code(400)
        .send({ error: "Bad Request", details: parsed.error.errors });
    }

    const verdict = await runPipeline(parsed.data);

    // 📝 LOG THE EVENT for the dashboard
    const logEntry = {
      timestamp: Date.now(),
      ip: cleanRequest.ip,
      route: cleanRequest.route,
      method: cleanRequest.method,
      decision: verdict.decision,
      reason: verdict.reason,
      tier: verdict.tier,
    };

    // Append to JSONL file (1 line per request)
    fs.appendFileSync(EVENT_LOG_PATH, JSON.stringify(logEntry) + "\n");

    if (verdict.decision === "MALICIOUS") {
      logger.warn(
        { ip: req.ip, route: req.url, reason: verdict.reason },
        "Request blocked by WAF"
      );
      return reply.code(403).send({
        error: "Forbidden",
        reason: verdict.reason,
        tier: verdict.tier,
      });
    }

    // Proxy to downstream
    const downstreamUrl = `${DOWNSTREAM}${req.url}`;
    const fetchOptions: RequestInit = {
      method: req.method,
      headers: safeHeaders,
    };

    if (["POST", "PUT", "PATCH"].includes(req.method) && req.body) {
      fetchOptions.body = JSON.stringify(req.body);
      safeHeaders["content-type"] = "application/json";
    }

    const downstreamResponse = await fetch(downstreamUrl, fetchOptions);
    const responseBody = await downstreamResponse.text();

    return reply
      .code(downstreamResponse.status)
      .type(
        downstreamResponse.headers.get("content-type") || "application/json"
      )
      .send(responseBody);
  } catch (error: any) {
    logger.error({ msg: "Pipeline crash", err: error.message });
    return reply.code(500).send({ error: "Internal Server Error" });
  }
});

async function startServer() {
  try {
    logger.info("🔧 Initializing Sentinel Guard...");
    await initializeMLModel();
    logger.info("✅ ML Model loaded and ready!");
    await app.listen({ port: 3000, host: "0.0.0.0" });
    logger.info(`🚀 Sentinel Guard proxy listening on http://0.0.0.0:3000`);
    logger.info(`📊 Dashboard events logging to: ${EVENT_LOG_PATH}`);
  } catch (error) {
    logger.error({ error }, "Failed to start Sentinel Guard");
    process.exit(1);
  }
}

startServer();
