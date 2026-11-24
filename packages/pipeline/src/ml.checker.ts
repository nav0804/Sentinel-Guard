import { pipeline } from "@xenova/transformers";

// We will use a pre-trained model designed for text classification.
// You can swap this model name later with a WAF-specific one from Hugging Face.
const MODEL_NAME = "Xenova/distilbert-base-uncased-finetuned-sst-2-english";

let classifier: any = null;

// Initialize the model once when the app starts
export async function initializeMLModel() {
  console.log("🤖 Loading local ML model (this happens only once)...");
  // This downloads the model to a local cache and loads it into memory
  classifier = await pipeline("text-classification", MODEL_NAME, {
    quantized: true, // Makes the model smaller and faster
  });
  console.log("✅ ML Model loaded and ready!");
}

export async function checkPayload(
  payload: string
): Promise<{ isMalicious: boolean; confidence: number }> {
  if (!classifier) {
    throw new Error(
      "ML Model not initialized. Call initializeMLModel() first."
    );
  }

  // The model analyzes the text and returns a score
  // Note: The default model above classifies "Positive" vs "Negative".
  // We will treat "Negative" (or a specific label) as malicious for this example.
  // You will replace this with a WAF-specific model (see Step 3).
  const result = await classifier(payload);

  // Example result: [{ label: 'NEGATIVE', score: 0.95 }]
  const prediction = result[0];

  // For demonstration: if the model is highly confident it's "NEGATIVE", we block it.
  // When you use a WAF-specific model, the labels will be 'MALICIOUS' and 'BENIGN'.
  const isMalicious =
    prediction.label === "NEGATIVE" && prediction.score > 0.85;

  return {
    isMalicious,
    confidence: prediction.score,
  };
}
