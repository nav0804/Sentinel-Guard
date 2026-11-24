import { analyzeWithML, isMLReady } from "@sentinel/ml-detector";
import type { Verdict } from "@sentinel/schemas";

export async function tier5MLCheck(payload: string): Promise<Verdict> {
  // If ML isn't ready yet, fail-open (allow the request)
  if (!isMLReady()) {
    return {
      decision: "SAFE",
      reason: "ML_NOT_READY",
      tier: 5,
    };
  }

  const result = await analyzeWithML(payload);

  if (result.isMalicious) {
    return {
      decision: "MALICIOUS",
      reason: `ML detected: ${result.label} (${(
        result.confidence * 100
      ).toFixed(1)}% confidence)`,
      tier: 5,
    };
  }

  return {
    decision: "SAFE",
    reason: "ML_CLEAN",
    tier: 5,
  };
}
