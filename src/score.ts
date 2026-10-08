import { HeaderMap, MAX_SCORE, RuleResult, RULES } from "./rules.js";

export interface Report {
  url?: string;
  results: RuleResult[];
  score: number; // 0-100
  grade: "A" | "B" | "C" | "D" | "F";
}

function gradeFor(score: number): Report["grade"] {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

/** Normalizes a raw header map (any casing) to lowercase keys. */
export function normalizeHeaders(raw: HeaderMap): HeaderMap {
  const out: HeaderMap = {};
  for (const [k, v] of Object.entries(raw)) {
    out[k.toLowerCase()] = v;
  }
  return out;
}

export function scoreHeaders(rawHeaders: HeaderMap, url?: string): Report {
  const headers = normalizeHeaders(rawHeaders);
  const results = RULES.map((rule) => rule.evaluate(headers));
  const earned = results.reduce((sum, r) => sum + r.points, 0);
  const score = Math.round((earned / MAX_SCORE) * 100);
  return { url, results, score, grade: gradeFor(score) };
}
