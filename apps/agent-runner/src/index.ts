import Fastify from "fastify";
import { IncomingRequestSchema } from "@sentinel/schemas";
import { evaluateRequest } from "@sentinel/agents";
import { logger } from "@sentinel/logger";

const app = Fastify({ logger: true });

app.post("/evaluate", async (req, reply) => {
  const parsed = IncomingRequestSchema.safeParse(req.body);
  if (!parsed.success) return reply.code(400).send({ error: "Bad request" });
  const start = Date.now();
  const verdict = await evaluateRequest(parsed.data);
  verdict.latencyMs = Date.now() - start;
  logger.info(
    {
      decision: verdict.decision,
      reason: verdict.reason,
      tier: verdict.tier,
      latencyMs: verdict.latencyMs,
    },
    "Agent evaluation complete"
  );
  return verdict;
});

app.listen({ port: 3001, host: "0.0.0.0" }, () =>
  logger.info("Agent runner on :3001")
);
