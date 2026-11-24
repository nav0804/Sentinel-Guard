import { getCachedResult, hashRequest, setCachedResult } from "@sentinel/cache";
import { evaluateHeuristics } from "@sentinel/heuristics"; // NEW
import { analyzeWithML, isMLReady } from "@sentinel/ml-detector"; // NEW
import {
  checkRateLimit,
  shouldRunLLM, // We'll keep this for now, but local ML is so fast we might not even need to skip it
  updateTrustScore,
} from "@sentinel/ip-reputation";
import { logger } from "@sentinel/logger";
import { IncomingRequest, Verdict } from "@sentinel/schemas";

// REMOVED: AGENT_RUNNER_URL (No longer needed, ML runs locally now!)

const WAF_PATTERNS = [
  /(<script[\s\S]*?>)/i,
  /(union\s+select|or\s+1=1)/i,
  /(\.\.\/)|(\.\.\\)/,
];

function wafScan(req: IncomingRequest): Verdict | null {
  const payload = JSON.stringify(req.body ?? "");
  for (const pattern of WAF_PATTERNS) {
    if (pattern.test(payload)) {
      return {
        decision: "MALICIOUS",
        reason: `WAF pattern matched: ${pattern.source}`,
        tier: 3,
      };
    }
  }
  return null;
}

export async function runPipeline(req: IncomingRequest): Promise<Verdict> {
  const payload = JSON.stringify(req.body ?? "");

  console.log("--> Starting Tier 1 (Rate Limit)");
  const t1 = await checkRateLimit(req.ip);
  if (t1) return t1;

  console.log("--> Starting Tier 3 (WAF Regex)");
  const t3 = wafScan(req);
  if (t3) return t3;

  // ==========================================
  // NEW: Tier 3.5 (Heuristics - Fast Math)
  // ==========================================
  console.log("--> Starting Tier 3.5 (Heuristics)");
  const heuristicResult = evaluateHeuristics(payload);
  if (heuristicResult.isMalicious) {
    return {
      decision: "MALICIOUS",
      reason: `Heuristic detection: ${heuristicResult.reason}`,
      tier: 3.5,
    };
  }

  console.log("--> Starting Tier 4 (Cache)");
  const hash = hashRequest(req);
  const cached = await getCachedResult(hash);
  if (cached) {
    return {
      decision: cached.decision,
      reason: "Cache hit",
      tier: 4,
    };
  }

  // ==========================================
  // UPDATED: Tier 5 (Local ML instead of HTTP fetch)
  // ==========================================
  console.log("--> Starting Tier 5 (Local ML)");

  // Optional: Keep your trust score sampling, but since local ML is <50ms,
  // you can safely remove the `if (!runLLM)` check and just run it every time.
  const runDeepCheck = await shouldRunLLM(req.ip);
  if (!runDeepCheck) {
    logger.info({ ip: req.ip }, "Trusted IP sampled out — SAFE");
    return { decision: "SAFE", reason: "Trusted IP sample bypass", tier: 5 };
  }

  // Check if ML is ready (it should be, if initialized in proxy)
  if (!isMLReady()) {
    logger.warn("ML Model not ready, failing open to SAFE");
    return { decision: "SAFE", reason: "ML_NOT_READY", tier: 5 };
  }

  // Run the local ML model
  const mlResult = await analyzeWithML(payload);

  let verdict: Verdict;
  if (mlResult.isMalicious) {
    verdict = {
      decision: "MALICIOUS",
      reason: `ML detected: ${mlResult.label} (${(
        mlResult.confidence * 100
      ).toFixed(1)}% confidence)`,
      tier: 5,
    };
  } else {
    verdict = {
      decision: "SAFE",
      reason: "ML clean",
      tier: 5,
    };
  }

  // ==========================================
  // Post-processing: Cache and Trust Score
  // ==========================================
  await setCachedResult(hash, {
    decision: verdict.decision,
    cachedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3600000).toISOString(), // 1 hour TTL
  });

  await updateTrustScore(req.ip, verdict.decision === "SAFE" ? 1 : -10);

  return verdict;
}
