import { pipeline, env } from "@xenova/transformers";

// Disable downloading progress logs (cleaner startup)
env.allowLocalModels = false;
env.useBrowserCache = false;

export interface MLDetectionResult {
  isMalicious: boolean;
  confidence: number; // 0-1
  label: string;
}

// ============================================================
// PICK YOUR MODEL - Choose ONE of these tested options:
// ============================================================
// Option A (Recommended): Toxic content detector - catches many attack patterns
// const MODEL_NAME = 'Xenova/toxic-bert';
// const MALICIOUS_LABELS = ['toxic', 'severe_toxic', 'obscene', 'threat', 'insult', 'identity_hate'];
//
// Option B: Prompt injection detector (for LLM apps)
// const MODEL_NAME = 'Xenova/deberta-v3-base-prompt-injection';
// const MALICIOUS_LABELS = ['injection'];
//
// Option C: Malicious URL detector (works well on payloads too)
const MODEL_NAME = "Xenova/urlspam-classification-model";
const MALICIOUS_LABELS = ["malicious"];
// ============================================================

// For Option A (toxic-bert), use these settings:
const SELECTED_MODEL = "Xenova/toxic-bert";
const MALICIOUS_LABEL_SET = new Set([
  "toxic",
  "severe_toxic",
  "obscene",
  "threat",
  "insult",
  "identity_hate",
]);
const CONFIDENCE_THRESHOLD = 0.8; // Block if >80% confident it's malicious

let classifier: any = null;
let initializationPromise: Promise<void> | null = null;

/**
 * Initialize the ML model. Call this ONCE at app startup.
 * The first call downloads the model (~50MB) and caches it locally.
 * Subsequent startups load from cache instantly.
 */
export async function initializeMLModel(): Promise<void> {
  if (classifier) return;
  if (initializationPromise) return initializationPromise;

  initializationPromise = (async () => {
    console.log("🤖 [ML] Loading pre-trained model:", SELECTED_MODEL);
    console.log("   (First run downloads ~50MB, then caches locally)");

    try {
      classifier = await pipeline("text-classification", SELECTED_MODEL, {
        quantized: true, // Smaller + faster
      });
      console.log("✅ [ML] Model loaded and ready!");
    } catch (error) {
      console.error("❌ [ML] Failed to load model:", error);
      throw error;
    }
  })();

  return initializationPromise;
}

/**
 * Analyze a payload with the ML model.
 * Returns { isMalicious, confidence, label }
 */
export async function analyzeWithML(
  payload: string
): Promise<MLDetectionResult> {
  if (!classifier) {
    throw new Error(
      "ML model not initialized. Call initializeMLModel() first."
    );
  }

  // Truncate very long payloads to avoid model limits
  const truncatedPayload =
    payload.length > 512 ? payload.slice(0, 512) : payload;

  try {
    const results = await classifier(truncatedPayload, {
      topk: 5, // Get top 5 predictions (for multi-label models)
    });

    // Normalize results (handles both single and multi-label outputs)
    const predictions = Array.isArray(results) ? results : [results];

    // Find the highest-confidence malicious label
    let maxMaliciousScore = 0;
    let topLabel = "benign";

    for (const pred of predictions) {
      const label = pred.label.toLowerCase();
      const score = pred.score;

      if (MALICIOUS_LABEL_SET.has(label) && score > maxMaliciousScore) {
        maxMaliciousScore = score;
        topLabel = label;
      }
    }

    const isMalicious = maxMaliciousScore >= CONFIDENCE_THRESHOLD;

    return {
      isMalicious,
      confidence: maxMaliciousScore,
      label: topLabel,
    };
  } catch (error) {
    console.error("[ML] Inference error:", error);
    // Fail-open: don't block on ML errors (let heuristics/regex handle it)
    return { isMalicious: false, confidence: 0, label: "error" };
  }
}

/**
 * Check if the model is ready for inference.
 */
export function isMLReady(): boolean {
  return classifier !== null;
}
