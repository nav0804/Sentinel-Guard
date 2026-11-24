import Fastify from "fastify";
import websocket from "@fastify/websocket";
import { IncomingRequestSchema } from "@sentinel/schemas";
import { logger } from "@sentinel/logger";
import { runPipeline } from "@sentinel/pipeline";
import { initializeMLModel } from "@sentinel/ml-detector";
import type { WebSocket } from "ws";

const app = Fastify({ logger: false });
const DOWNSTREAM = process.env.DOWNSTREAM_URL ?? "http://localhost:4000";

// ==========================================
// 1. In-Memory State (no DB, no files)
// ==========================================
interface EventRecord {
  timestamp: number;
  ip: string;
  route: string;
  method: string;
  decision: "SAFE" | "MALICIOUS";
  reason: string;
  tier: number;
}

const state = {
  total: 0,
  blocked: 0,
  allowed: 0,
  byTier: {} as Record<string, number>,
  recent: [] as EventRecord[], // capped below
};

const RECENT_CAP = 100; // keep only the last 100 events in memory

function recordEvent(e: EventRecord) {
  state.total += 1;
  if (e.decision === "MALICIOUS") {
    state.blocked += 1;
    const tierName = `Tier ${e.tier}`;
    state.byTier[tierName] = (state.byTier[tierName] || 0) + 1;
    // newest first, capped
    state.recent.unshift(e);
    if (state.recent.length > RECENT_CAP) state.recent.pop();
  } else {
    state.allowed += 1;
  }
}

function getStats() {
  return {
    total: state.total,
    blocked: state.blocked,
    allowed: state.allowed,
    byTier: { ...state.byTier },
    recent: state.recent.slice(0, 10).map((r) => ({
      ...r,
      time: new Date(r.timestamp).toLocaleTimeString(),
    })),
  };
}

// ==========================================
// 2. WebSocket Hub
// ==========================================
const wsClients = new Set<WebSocket>();

function broadcast(event: EventRecord) {
  const payload = JSON.stringify({
    type: "event",
    data: { type: "event", event },
  });
  for (const client of wsClients) {
    if (client.readyState === 1) client.send(payload);
  }
}

app.register(websocket);

// ==========================================
// 3. Error Handler
// ==========================================
app.setErrorHandler((error: Error, req, reply) => {
  logger.error({ error: error.message, ip: req.ip }, "Request error");
  reply
    .code(500)
    .send({ error: "Internal Server Error", message: error.message });
});

// ==========================================
// 4. Routes (Stats + WebSocket) — no duplicates
// ==========================================
app.get("/api/stats", async (req, reply) => {
  return reply.send(getStats());
});

app.register(async (fastify) => {
  fastify.get("/ws", { websocket: true }, (socket: WebSocket) => {
    wsClients.add(socket);
    logger.info(
      { clients: wsClients.size },
      "Dashboard connected via WebSocket"
    );

    // Send current snapshot the instant a dashboard connects
    socket.send(
      JSON.stringify({
        type: "init",
        data: { type: "init", stats: getStats() },
      })
    );

    socket.on("close", () => {
      wsClients.delete(socket);
      logger.info({ clients: wsClients.size }, "Dashboard disconnected");
    });
  });
});

// ==========================================
// 5. Main WAF Proxy Route
// ==========================================
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

    const logEntry: EventRecord = {
      timestamp: Date.now(),
      ip: cleanRequest.ip,
      route: cleanRequest.route,
      method: cleanRequest.method,
      decision: verdict.decision,
      reason: verdict.reason,
      tier: verdict.tier,
    };

    // Update in-memory stats + push to dashboards
    recordEvent(logEntry);
    broadcast(logEntry);

    if (verdict.decision === "MALICIOUS") {
      logger.warn(
        { ip: req.ip, route: req.url, reason: verdict.reason },
        "Request blocked by WAF"
      );
      return reply
        .code(403)
        .send({
          error: "Forbidden",
          reason: verdict.reason,
          tier: verdict.tier,
        });
    }

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

// ==========================================
// 6. Startup
// ==========================================
async function startServer() {
  try {
    logger.info("🔧 Initializing Sentinel Guard...");
    await initializeMLModel();
    logger.info("✅ ML Model loaded and ready!");
    await app.listen({ port: 3000, host: "0.0.0.0" });
    logger.info("🚀 Sentinel Guard proxy listening on http://0.0.0.0:3000");
    logger.info(
      "🔌 WebSocket dashboard endpoint active at ws://localhost:3000/ws"
    );
  } catch (error) {
    logger.error({ error }, "Failed to start Sentinel Guard");
    process.exit(1);
  }
}

startServer();
