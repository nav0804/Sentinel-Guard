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

export async function runPipeline(req: IncomingRequest): Promise<Verdict> {
  console.log("--> Starting Tier 1 (Rate Limit)");
  const t1 = await checkRateLimit(req.ip);
  if (t1) return t1;

  console.log("--> Starting Tier 3 (WAF)");
  const t3 = wafScan(req);
  if (t3) return t3;

  console.log("--> Starting Tier 4 (Cache)");
  const hash = hashRequest(req);
  const cached = await getCachedResult(hash);
  if (cached)
    return { decision: cached.decision, reason: "Cache hit", tier: 4 };

  console.log("--> Starting Tier 5 (LLM)");
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
