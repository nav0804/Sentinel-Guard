import Fastify from "fastify";
import proxy from "@fastify/http-proxy";
import { IncomingRequestSchema } from "@sentinel/schemas";
import { logger } from "@sentinel/logger";
import { runPipeline } from "@sentinel/pipeline";

const app = Fastify({ logger: false });
const DOWNSTREAM = process.env.DOWNSTREAM_URL ?? "http://localhost:4000";

// Global error handler to prevent circular reference errors
app.setErrorHandler((error: Error, req, reply) => {
  // Extract only the error message to avoid circular references
  const errorMessage = error.message || "Unknown error";
  const errorStack = error.stack || "No stack trace";

  // Log detailed error information
  logger.error(
    {
      error: errorMessage,
      stack: errorStack.split("\n").slice(0, 5).join("\n"), // First 5 lines of stack
      ip: req.ip,
      method: req.method,
      url: req.url,
    },
    "Request error"
  );

  reply.code(500).send({
    error: "Internal Server Error",
    message: errorMessage,
  });
});

// Tier 2: Fastify schema validation (structural check before route handlers)
app.addHook("preHandler", async (req, reply) => {
  try {
    const safeHeaders: Record<string, string> = {};
    for (const [key, value] of Object.entries(req.headers)) {
      safeHeaders[key] = Array.isArray(value)
        ? value.join(", ")
        : String(value || "");
    }

    // 🌟 THE FIX: Strictly serialize the body, or drop it if it's a Stream
    let safeBody = undefined;
    if (req.body) {
      // Check if it's a Stream (Streams have a .pipe method)
      if (typeof (req.body as any).pipe === "function") {
        safeBody = "[Raw Stream - Skipped]";
      } else {
        try {
          // Force a deep clone. If it's circular, it fails here safely.
          safeBody = JSON.parse(JSON.stringify(req.body));
        } catch (e) {
          safeBody = "[Circular Body - Skipped]";
        }
      }
    }

    const cleanRequest = {
      method: String(req.method),
      route: String(req.url),
      headers: safeHeaders,
      body: safeBody,
      ip: String(req.ip),
    };

    const parsed = IncomingRequestSchema.safeParse(cleanRequest);
    if (!parsed.success) {
      return reply.code(400).send({ error: "Bad Request" });
    }

    const verdict = await runPipeline(parsed.data);

    if (verdict.decision === "MALICIOUS") {
      return reply
        .code(403)
        .send({ error: "Forbidden", reason: verdict.reason });
    }
  } catch (error: any) {
    logger.error({ msg: "Pipeline crash", err: error.message });
    return reply.code(500).send({ error: "Internal Server Error" });
  }
});

app.register(proxy, { upstream: DOWNSTREAM, prefix: "/" });

app.listen({ port: 3000, host: "0.0.0.0" }, () =>
  logger.info("Sentinel Guard proxy on :3000")
);
