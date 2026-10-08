import { describe, expect, it } from "vitest";
import { normalizeHeaders, scoreHeaders } from "../src/score.js";

const STRONG_HEADERS = {
  "Content-Security-Policy": "default-src 'self'; script-src 'self'",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "geolocation=(), camera=()",
};

const EMPTY_HEADERS = {};

const WEAK_HEADERS = {
  "Content-Security-Policy": "default-src *",
  "Strict-Transport-Security": "max-age=100",
  "X-Frame-Options": "ALLOW-FROM https://example.com",
  "Referrer-Policy": "unsafe-url",
  Server: "Apache/2.4.49",
  "X-Powered-By": "PHP/7.4.3",
};

describe("normalizeHeaders", () => {
  it("lowercases keys", () => {
    const normalized = normalizeHeaders({ "Content-Type": "text/html" });
    expect(normalized["content-type"]).toBe("text/html");
  });
});

describe("scoreHeaders", () => {
  it("gives a strong header set an A grade and near-perfect score", () => {
    const report = scoreHeaders(STRONG_HEADERS);
    expect(report.score).toBeGreaterThanOrEqual(90);
    expect(report.grade).toBe("A");
    expect(report.results.every((r) => r.verdict !== "fail")).toBe(true);
  });

  it("gives a completely empty header set an F grade and a zero-ish score", () => {
    const report = scoreHeaders(EMPTY_HEADERS);
    expect(report.grade).toBe("F");
    expect(report.score).toBeLessThan(40);
    expect(report.results.some((r) => r.header === "Content-Security-Policy" && r.verdict === "fail")).toBe(true);
  });

  it("flags a wildcard CSP as a warning, not a pass", () => {
    const report = scoreHeaders(WEAK_HEADERS);
    const csp = report.results.find((r) => r.header === "Content-Security-Policy")!;
    expect(csp.verdict).toBe("warn");
  });

  it("flags a short HSTS max-age as a warning", () => {
    const report = scoreHeaders(WEAK_HEADERS);
    const hsts = report.results.find((r) => r.header === "Strict-Transport-Security")!;
    expect(hsts.verdict).toBe("warn");
  });

  it("flags missing X-Content-Type-Options as a failure", () => {
    const report = scoreHeaders(WEAK_HEADERS);
    const xcto = report.results.find((r) => r.header === "X-Content-Type-Options")!;
    expect(xcto.verdict).toBe("fail");
  });

  it("accepts CSP frame-ancestors as a valid substitute for X-Frame-Options", () => {
    const report = scoreHeaders({
      "Content-Security-Policy": "frame-ancestors 'self'",
    });
    const xfo = report.results.find((r) => r.header === "X-Frame-Options")!;
    expect(xfo.verdict).toBe("pass");
  });

  it("warns (not fails) on an unusual X-Frame-Options value", () => {
    const report = scoreHeaders(WEAK_HEADERS);
    const xfo = report.results.find((r) => r.header === "X-Frame-Options")!;
    expect(xfo.verdict).toBe("warn");
  });

  it("flags server version disclosure", () => {
    const report = scoreHeaders(WEAK_HEADERS);
    const server = report.results.find((r) => r.header === "Server / X-Powered-By")!;
    expect(server.verdict).toBe("warn");
  });

  it("does not flag a generic Server header with no version info", () => {
    const report = scoreHeaders({ Server: "nginx" });
    const server = report.results.find((r) => r.header === "Server / X-Powered-By")!;
    expect(server.verdict).toBe("pass");
  });

  it("is case-insensitive on header names", () => {
    const upper = scoreHeaders({ "X-CONTENT-TYPE-OPTIONS": "nosniff" });
    const lower = scoreHeaders({ "x-content-type-options": "nosniff" });
    const xctoUpper = upper.results.find((r) => r.header === "X-Content-Type-Options")!;
    const xctoLower = lower.results.find((r) => r.header === "X-Content-Type-Options")!;
    expect(xctoUpper.verdict).toBe(xctoLower.verdict);
    expect(xctoUpper.verdict).toBe("pass");
  });

  it("produces a score between 0 and 100 for any input", () => {
    for (const headers of [STRONG_HEADERS, EMPTY_HEADERS, WEAK_HEADERS]) {
      const report = scoreHeaders(headers);
      expect(report.score).toBeGreaterThanOrEqual(0);
      expect(report.score).toBeLessThanOrEqual(100);
    }
  });
});
