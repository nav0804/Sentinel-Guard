import { getCachedResult, hashRequest, setCachedResult } from "@sentinel/cache";
import {
  checkRateLimit,
  shouldRunLLM,
  updateTrustScore,
} from "@sentinel/ip-reputation";
import { logger } from "@sentinel/logger";
import { IncomingRequest, Verdict } from "@sentinel/schemas";

const AGENT_RUNNER_URL =
  process.env.AGENT_RUNNER_URL ?? "http://agent-runner:3001";
// Tier 3: regex WAF rules
const WAF_PATTERNS = [
  /(<script[\s\S]*?>)/i, // XSS
  /(union\s+select|or\s+1=1)/i, // SQLi
  /(\.\.\/)|(\.\.\\)/, // path traversal
];

function wafScan(req: IncomingRequest): Verdict | null {
  const payload = JSON.stringify(req.body ?? "");
  for (const pattern of WAF_PATTERNS) {
    if (pattern.test(payload)) {
      return {
        decision: "MALICIOUS",
        reason: `WAF pattern: ${pattern}`,
        tier: 3,
      };
    }
  }
  return null;
}

export async function runPipeline(
  req: IncomingRequest
): Promise<Verdict> {
  const t1 = await checkRateLimit(req.ip);
  if (t1) {
    logger.warn(
      { ip: req.ip, reason: t1.reason, tier: t1.tier },
      "Tier 1 block"
    );
    return t1;
  }

  // Tier 2: schema validated upstream by Fastify — pass through

  // Tier 3: WAF regex scan
  const t3 = wafScan(req);
  if (t3) {
    logger.warn(
      { ip: req.ip, reason: t3.reason, tier: t3.tier },
      "Tier 3 WAF hit"
    );
    return t3;
  }

  // Tier 4: cache lookup
  const hash = hashRequest(req);
  const cached = await getCachedResult(hash);
  if (cached) {
    logger.info({ hash, decision: cached.decision }, "Tier 4 cache hit");
    return { decision: cached.decision, reason: "Cache hit", tier: 4 };
  }

  // Tier 5: LLM agents (skip if trusted IP on non-sample turn)
  const runLLM = await shouldRunLLM(req.ip);
  if (!runLLM) {
    logger.info({ ip: req.ip }, "Trusted IP sampled out — SAFE");
    return { decision: "SAFE", reason: "Trusted IP sample bypass", tier: 5 };
  }

  const agentRes = await fetch(`${AGENT_RUNNER_URL}/evaluate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      method: req.method,
      route: req.route,
      headers: req.headers,
      body: req.body,
      ip: req.ip,
    }),
  });

  if (!agentRes.ok) {
    logger.error({ status: agentRes.status }, "Agent runner returned error");
    // Fail open — return SAFE if agent is down, or fail closed with MALICIOUS
    // For a WAF, failing closed is safer:
    return {
      decision: "MALICIOUS",
      reason: "Agent runner unavailable",
      tier: 5,
    };
  }
  const verdict: Verdict = await agentRes.json();

  // Cache the result for next time
  await setCachedResult(hash, {
    decision: verdict.decision,
    cachedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3600000).toISOString(),
  });
  await updateTrustScore(req.ip, verdict.decision === "SAFE" ? 1 : -10);

  return verdict;
}
