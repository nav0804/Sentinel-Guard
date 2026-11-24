import { evaluateHeuristics } from "@sentinel/heuristics";
import type { Verdict } from "@sentinel/schemas";

export async function tier3_5HeuristicsCheck(
  payload: string
): Promise<Verdict | null> {
  const result = evaluateHeuristics(payload);

  if (result.isMalicious) {
    return {
      decision: "MALICIOUS",
      reason: `Heuristic detection: ${result.reason}`,
      tier: 3.5,
    };
  }

  // Return null to signal the pipeline to continue to the next tier
  return null;
}
