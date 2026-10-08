# headerhawk

[![CI](https://github.com/Afaguayo/headerhawk/actions/workflows/ci.yml/badge.svg)](https://github.com/Afaguayo/headerhawk/actions/workflows/ci.yml)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A command-line HTTP **security header auditor**, written in TypeScript.
Point it at a URL and it grades the response's security headers A
through F, explaining what's missing and why it matters.

## Why

[securityheaders.com](https://securityheaders.com) does this as a web
service; `headerhawk` is the same idea as a scriptable CLI you can drop
into CI, a pre-deploy check, or just run locally without sending your
URL to a third party.

## How it works

1. **Fetch** — a plain `GET` (not `HEAD`, since some servers answer the
   two differently) via Node's built-in `http`/`https`, following up to
   5 redirects.
2. **Evaluate** — seven independent rules each inspect one header (or
   header pair) and return `pass` / `warn` / `fail` with an explanation:
   - `Content-Security-Policy` — present? wildcard sources?
   - `Strict-Transport-Security` — present? `max-age` long enough?
   - `X-Content-Type-Options` — `nosniff`?
   - `X-Frame-Options` — set, or covered by CSP's `frame-ancestors`?
   - `Referrer-Policy` — present and not `unsafe-url`?
   - `Permissions-Policy` — present?
   - `Server` / `X-Powered-By` — leaking version info?
3. **Score** — each rule contributes weighted points toward a 0-100
   score, which maps to a letter grade (A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40,
   else F).

## Install / build

Requires Node 20+.

```bash
npm install
npm run build
```

## Usage

```bash
node dist/cli.js https://example.com
```

Or during development, without building first:

```bash
npm run dev -- https://example.com
```

Example (real output against a well-configured site):

```
HTTP 200
headerhawk report for https://github.com
========================================
[✔] Content-Security-Policy
    Present with a restrictive policy.
[✔] Strict-Transport-Security
    Present with a strong max-age.
[✔] X-Content-Type-Options
    Set to 'nosniff'.
[✔] X-Frame-Options
    Covered via CSP frame-ancestors (the modern replacement for this header).
[✔] Referrer-Policy
    Set to 'origin-when-cross-origin, strict-origin-when-cross-origin'.
[!] Permissions-Policy
    Missing. Without it, powerful browser features (camera, microphone, geolocation, USB, etc.) default to being available to the page and any embedded frame.
[✔] Server / X-Powered-By
    No verbose version info disclosed.

Score: 93/100  Grade: A
```

Machine-readable output:

```bash
node dist/cli.js https://example.com --json
```

Exit codes: `0` grade A/B, `2` grade C/D/F, `1` usage or network error —
convenient as a CI gate.

## Tests

```bash
npm test
```

12 Vitest tests cover every rule's pass/warn/fail branches using mocked
header objects — no live network calls in the test suite itself (the
`fetchHeaders` network layer is isolated from the scoring logic
specifically so it's testable without hitting the internet).

## Limitations

- Scores the *response headers only* — it doesn't parse the actual CSP
  for logical mistakes beyond wildcard detection, or check cookie
  flags (`Secure`, `HttpOnly`, `SameSite`) yet.
- A `GET` request is made (and its body discarded) rather than `HEAD`,
  which is slightly heavier but more reliable across servers.

## License

MIT — see [LICENSE](LICENSE).
