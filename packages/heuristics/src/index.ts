export interface HeuristicResult {
  isMalicious: boolean;
  reason?: string;
  score: number; // 0-1, higher = more suspicious
}

/**
 * Calculate Shannon entropy of a string.
 * High entropy = lots of randomness = likely obfuscated attack.
 */
function calculateEntropy(str: string): number {
  if (str.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Fast, pure-JS heuristic checks. No ML, no dependencies.
 * Runs in < 1ms per request.
 */
export function evaluateHeuristics(payload: string): HeuristicResult {
  if (!payload || payload.length === 0) {
    return { isMalicious: false, score: 0 };
  }

  const lowerPayload = payload.toLowerCase();
  let suspiciousScore = 0;
  const reasons: string[] = [];

  // 1. Entropy check (obfuscated/base64 attacks)
  const entropy = calculateEntropy(payload);
  if (payload.length > 30 && entropy > 5.5) {
    suspiciousScore += 0.4;
    reasons.push(`HIGH_ENTROPY(${entropy.toFixed(2)})`);
  }

  // 2. Dangerous keyword density
  const dangerousPatterns = [
    "select ",
    " union ",
    "drop ",
    "insert ",
    "delete from",
    "<script",
    "</script",
    "javascript:",
    "onerror=",
    "onload=",
    "eval(",
    "exec(",
    "system(",
    "passthru(",
    "../",
    "..\\",
    "/etc/passwd",
    "/etc/shadow",
    "cmd.exe",
    "powershell",
    "/bin/sh",
    "/bin/bash",
    "ignore previous",
    "ignore all",
    "disregard",
  ];

  const keywordMatches = dangerousPatterns.filter((p) =>
    lowerPayload.includes(p)
  ).length;
  if (keywordMatches >= 2) {
    suspiciousScore += 0.5;
    reasons.push(`MULTIPLE_KEYWORDS(${keywordMatches})`);
  } else if (keywordMatches === 1) {
    suspiciousScore += 0.15;
    reasons.push(`SINGLE_KEYWORD`);
  }

  // 3. Special character ratio
  const specialCharCount = (payload.match(/[^a-zA-Z0-9\s]/g) || []).length;
  const specialRatio = specialCharCount / payload.length;
  if (payload.length > 20 && specialRatio > 0.45) {
    suspiciousScore += 0.3;
    reasons.push(`HIGH_SPECIAL_CHARS(${(specialRatio * 100).toFixed(0)}%)`);
  }

  // 4. SQL injection specific patterns
  const sqliPatterns =
    /(\b(or|and)\b\s+\d+\s*=\s*\d+|'\s*(or|and)\s+'|--\s*$|\/\*.*\*\/)/i;
  if (sqliPatterns.test(payload)) {
    suspiciousScore += 0.4;
    reasons.push("SQLI_PATTERN");
  }

  // 5. Path traversal patterns
  if (/(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f)/i.test(payload)) {
    suspiciousScore += 0.35;
    reasons.push("PATH_TRAVERSAL");
  }

  // Cap score at 1.0
  suspiciousScore = Math.min(suspiciousScore, 1.0);

  // Threshold: 0.6+ is considered malicious by heuristics alone
  const isMalicious = suspiciousScore >= 0.6;

  return {
    isMalicious,
    reason: reasons.length > 0 ? reasons.join("|") : undefined,
    score: suspiciousScore,
  };
}
