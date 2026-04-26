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
    // Sanitize headers to avoid circular references
    const sanitizedHeaders: Record<string, string> = {};
    for (const [key, value] of Object.entries(req.headers)) {
      if (typeof value === "string") {
        sanitizedHeaders[key] = value;
      } else if (Array.isArray(value)) {
        sanitizedHeaders[key] = value.join(", ");
      }
    }

    const incoming = {
      method: req.method,
      route: req.url,
      headers: sanitizedHeaders,
      body: req.body,
      ip: req.ip,
    };

    const parsed = IncomingRequestSchema.safeParse(incoming);
    if (!parsed.success) {
      logger.warn({ ip: req.ip }, "Tier 2 schema rejection");
      return reply.code(400).send({ error: "Invalid request shape" });
    }

    const verdict = await runPipeline(parsed.data);

    if (verdict.decision === "MALICIOUS") {
      logger.warn(
        {
          ip: req.ip,
          decision: verdict.decision,
          reason: verdict.reason,
          tier: verdict.tier,
        },
        "Request blocked"
      );
      return reply
        .code(403)
        .send({ error: "Forbidden", reason: verdict.reason });
    }

    logger.info(
      { ip: req.ip, tier: verdict.tier },
      "Request passed — proxying"
    );
  } catch (error) {
    // Catch any errors during request processing
    const errorMsg = error instanceof Error ? error.message : String(error);
    logger.error({ error: errorMsg, ip: req.ip }, "Request processing error");
    throw error;
  }
});

// Proxy clean requests downstream
app.register(proxy, { upstream: DOWNSTREAM, prefix: "/" });

app.listen({ port: 3000, host: "0.0.0.0" }, () =>
  logger.info("Sentinel Guard proxy on :3000")
);
