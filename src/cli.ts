#!/usr/bin/env node
import { fetchHeaders } from "./fetchHeaders.js";
import { Report, scoreHeaders } from "./score.js";
import { RuleResult } from "./rules.js";

function printUsage(): void {
  console.error(`headerhawk - HTTP security header auditor

Usage:
  headerhawk <url> [--json]

Options:
  --json   Emit a JSON report instead of a formatted one
  --help   Show this help

Exit codes:
  0  grade A or B
  1  usage error / network error
  2  grade C, D, or F
`);
}

const symbolFor = (verdict: RuleResult["verdict"]): string =>
  verdict === "pass" ? "✔" : verdict === "warn" ? "!" : "✘";

function printTextReport(report: Report): void {
  console.log(`headerhawk report${report.url ? ` for ${report.url}` : ""}`);
  console.log("=".repeat(40));
  for (const r of report.results) {
    console.log(`[${symbolFor(r.verdict)}] ${r.header}`);
    console.log(`    ${r.message}`);
  }
  console.log("");
  console.log(`Score: ${report.score}/100  Grade: ${report.grade}`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h") || args.length === 0) {
    printUsage();
    process.exit(args.length === 0 ? 1 : 0);
  }

  const json = args.includes("--json");
  const url = args.find((a) => !a.startsWith("--"));
  if (!url) {
    console.error("Error: a URL is required.\n");
    printUsage();
    process.exit(1);
  }

  try {
    const { headers, statusCode } = await fetchHeaders(url!);
    const report = scoreHeaders(headers, url);

    if (json) {
      console.log(JSON.stringify({ statusCode, ...report }, null, 2));
    } else {
      console.log(`HTTP ${statusCode}`);
      printTextReport(report);
    }

    process.exit(report.grade === "A" || report.grade === "B" ? 0 : 2);
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }
}

main();
