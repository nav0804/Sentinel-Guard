import Fastify from "fastify";
import { IncomingRequestSchema } from "@sentinel/schemas";
import { logger } from "@sentinel/logger";
import { runPipeline } from "@sentinel/pipeline";

const app = Fastify({ logger: false });
const DOWNSTREAM = process.env.DOWNSTREAM_URL ?? "http://localhost:4000";

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
      return reply.code(400).send({ error: "Bad Request" });
    }

    const verdict = await runPipeline(parsed.data);

    if (verdict.decision === "MALICIOUS") {
      return reply
        .code(403)
        .send({ error: "Forbidden", reason: verdict.reason });
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

app.listen({ port: 3000, host: "0.0.0.0" }, () =>
  logger.info("Sentinel Guard proxy on :3000")
);
