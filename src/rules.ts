/**
 * Each rule inspects the lowercase-keyed header map for one security
 * header and reports a verdict: pass, warn, or fail, plus a human
 * explanation of why it matters and what a good value looks like.
 */

export type Verdict = "pass" | "warn" | "fail";

export interface RuleResult {
  header: string;
  verdict: Verdict;
  message: string;
  points: number; // contribution toward the overall score, 0-10
}

export type HeaderMap = Record<string, string>;

export interface Rule {
  header: string;
  weight: number; // max points this rule contributes
  evaluate(headers: HeaderMap): RuleResult;
}

function get(headers: HeaderMap, name: string): string | undefined {
  return headers[name.toLowerCase()];
}

export const RULES: Rule[] = [
  {
    header: "Content-Security-Policy",
    weight: 20,
    evaluate(headers) {
      const value = get(headers, "content-security-policy");
      if (!value) {
        return {
          header: "Content-Security-Policy",
          verdict: "fail",
          points: 0,
          message:
            "Missing. CSP is the strongest defense against XSS and data injection — " +
            "without it, the browser will run any script the page includes or an " +
            "attacker manages to inject.",
        };
      }
      if (/default-src\s+\*/.test(value) || /script-src\s+\*(?!\S)/.test(value)) {
        return {
          header: "Content-Security-Policy",
          verdict: "warn",
          points: 10,
          message: "Present, but uses a wildcard source that defeats most of its protection.",
        };
      }
      return {
        header: "Content-Security-Policy",
        verdict: "pass",
        points: 20,
        message: "Present with a restrictive policy.",
      };
    },
  },
  {
    header: "Strict-Transport-Security",
    weight: 15,
    evaluate(headers) {
      const value = get(headers, "strict-transport-security");
      if (!value) {
        return {
          header: "Strict-Transport-Security",
          verdict: "fail",
          points: 0,
          message:
            "Missing. Without HSTS, a user's first visit (and any downgraded link) can be " +
            "silently sent over plain HTTP and intercepted.",
        };
      }
      const maxAgeMatch = value.match(/max-age=(\d+)/i);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
      if (maxAge < 15552000) {
        // 180 days
        return {
          header: "Strict-Transport-Security",
          verdict: "warn",
          points: 8,
          message: `Present, but max-age=${maxAge} is short. Recommended minimum is 15552000 (180 days), ideally 31536000 (1 year) with includeSubDomains.`,
        };
      }
      return {
        header: "Strict-Transport-Security",
        verdict: "pass",
        points: 15,
        message: "Present with a strong max-age.",
      };
    },
  },
  {
    header: "X-Content-Type-Options",
    weight: 10,
    evaluate(headers) {
      const value = get(headers, "x-content-type-options");
      if (!value || value.toLowerCase() !== "nosniff") {
        return {
          header: "X-Content-Type-Options",
          verdict: "fail",
          points: 0,
          message:
            "Missing or not 'nosniff'. Without it, browsers may MIME-sniff a response and " +
            "execute it as a different content type than declared (a classic path to XSS " +
            "via file upload endpoints).",
        };
      }
      return {
        header: "X-Content-Type-Options",
        verdict: "pass",
        points: 10,
        message: "Set to 'nosniff'.",
      };
    },
  },
  {
    header: "X-Frame-Options",
    weight: 10,
    evaluate(headers) {
      const value = get(headers, "x-frame-options");
      const csp = get(headers, "content-security-policy");
      const hasFrameAncestors = csp ? /frame-ancestors/i.test(csp) : false;
      if (!value && !hasFrameAncestors) {
        return {
          header: "X-Frame-Options",
          verdict: "fail",
          points: 0,
          message:
            "Missing (and no CSP frame-ancestors directive either). The page can be framed " +
            "by any other site, enabling clickjacking.",
        };
      }
      if (hasFrameAncestors) {
        return {
          header: "X-Frame-Options",
          verdict: "pass",
          points: 10,
          message: "Covered via CSP frame-ancestors (the modern replacement for this header).",
        };
      }
      if (/^(deny|sameorigin)$/i.test(value!)) {
        return {
          header: "X-Frame-Options",
          verdict: "pass",
          points: 10,
          message: `Set to ${value}.`,
        };
      }
      return {
        header: "X-Frame-Options",
        verdict: "warn",
        points: 5,
        message: `Set to an unusual value (${value}); DENY or SAMEORIGIN is recommended.`,
      };
    },
  },
  {
    header: "Referrer-Policy",
    weight: 8,
    evaluate(headers) {
      const value = get(headers, "referrer-policy");
      if (!value) {
        return {
          header: "Referrer-Policy",
          verdict: "fail",
          points: 0,
          message:
            "Missing. By default, full URLs (including query strings, which sometimes carry " +
            "tokens or PII) can leak to third parties via the Referer header on outbound links.",
        };
      }
      const weak = ["unsafe-url"];
      if (weak.includes(value.toLowerCase())) {
        return {
          header: "Referrer-Policy",
          verdict: "warn",
          points: 3,
          message: `Set to '${value}', which leaks the full URL on every cross-origin request.`,
        };
      }
      return {
        header: "Referrer-Policy",
        verdict: "pass",
        points: 8,
        message: `Set to '${value}'.`,
      };
    },
  },
  {
    header: "Permissions-Policy",
    weight: 7,
    evaluate(headers) {
      const value = get(headers, "permissions-policy");
      if (!value) {
        return {
          header: "Permissions-Policy",
          verdict: "warn",
          points: 2,
          message:
            "Missing. Without it, powerful browser features (camera, microphone, geolocation, " +
            "USB, etc.) default to being available to the page and any embedded frame.",
        };
      }
      return {
        header: "Permissions-Policy",
        verdict: "pass",
        points: 7,
        message: "Present, restricting browser feature access.",
      };
    },
  },
  {
    header: "Server / X-Powered-By",
    weight: 5,
    evaluate(headers) {
      const server = get(headers, "server");
      const poweredBy = get(headers, "x-powered-by");
      if (poweredBy || (server && /\d/.test(server))) {
        return {
          header: "Server / X-Powered-By",
          verdict: "warn",
          points: 2,
          message:
            `Reveals server/framework details (${[server, poweredBy].filter(Boolean).join(", ")}). ` +
            "Not a vulnerability by itself, but it hands an attacker a head start on picking " +
            "known exploits for that exact version.",
        };
      }
      return {
        header: "Server / X-Powered-By",
        verdict: "pass",
        points: 5,
        message: "No verbose version info disclosed.",
      };
    },
  },
];

export const MAX_SCORE = RULES.reduce((sum, r) => sum + r.weight, 0);
