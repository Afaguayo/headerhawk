import * as http from "node:http";
import * as https from "node:https";

export interface FetchResult {
  statusCode: number | undefined;
  headers: Record<string, string>;
}

/**
 * Fetches response headers for `url` with a GET request (some servers
 * ignore HEAD or return different headers for it), following at most
 * `maxRedirects` redirects, with a timeout.
 */
export function fetchHeaders(
  url: string,
  { timeoutMs = 10000, maxRedirects = 5 }: { timeoutMs?: number; maxRedirects?: number } = {}
): Promise<FetchResult> {
  return new Promise((resolve, reject) => {
    const attempt = (currentUrl: string, redirectsLeft: number) => {
      let parsed: URL;
      try {
        parsed = new URL(currentUrl);
      } catch (e) {
        reject(new Error(`Invalid URL: ${currentUrl}`));
        return;
      }

      const client = parsed.protocol === "http:" ? http : https;
      const req = client.get(
        parsed,
        { timeout: timeoutMs, headers: { "User-Agent": "headerhawk/1.0" } },
        (res) => {
          const status = res.statusCode ?? 0;
          if (status >= 300 && status < 400 && res.headers.location && redirectsLeft > 0) {
            const next = new URL(res.headers.location, parsed).toString();
            res.resume(); // discard body
            attempt(next, redirectsLeft - 1);
            return;
          }

          const headers: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (Array.isArray(v)) headers[k] = v.join(", ");
            else if (typeof v === "string") headers[k] = v;
          }
          res.resume();
          resolve({ statusCode: res.statusCode, headers });
        }
      );

      req.on("timeout", () => {
        req.destroy(new Error(`Request to ${currentUrl} timed out after ${timeoutMs}ms`));
      });
      req.on("error", reject);
    };

    attempt(url, maxRedirects);
  });
}
