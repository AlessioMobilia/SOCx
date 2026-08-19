import { describe, expect, it } from "vitest"

import type { BulkCheckSummaryRow } from "./bulk-check.types"
import { getVerdict, hasFailedLookup } from "./bulk-verdict"

const buildRow = (
  overrides: Partial<BulkCheckSummaryRow> = {}
): BulkCheckSummaryRow => ({
  ioc: "8.8.8.8",
  displayType: "IP",
  rawType: "IP",
  serviceStatuses: [],
  statusKind: "clean",
  statusText: "No detections",
  result: {},
  isPending: false,
  ...overrides
})

describe("getVerdict", () => {
  it("reports a malicious verdict for a widely detected indicator", () => {
    const entry = buildRow({
      statusKind: "flagged",
      statusText: "8 malicious • 2 suspicious",
      result: {
        VirusTotal: {
          data: {
            attributes: { last_analysis_stats: { malicious: 8, suspicious: 2 } }
          }
        }
      }
    })

    expect(getVerdict(entry)).toBe("malicious")
  })

  it("reports a suspicious verdict for a single detection", () => {
    const entry = buildRow({
      statusKind: "flagged",
      statusText: "1 malicious • 0 suspicious",
      result: {
        VirusTotal: {
          data: {
            attributes: {
              last_analysis_stats: { malicious: 1, suspicious: 0, harmless: 60 }
            }
          }
        }
      }
    })

    expect(getVerdict(entry)).toBe("suspicious")
  })

  it("reports a clean verdict when no provider flags the indicator", () => {
    const entry = buildRow({
      result: {
        AbuseIPDB: { data: { abuseConfidenceScore: 0, totalReports: 0 } }
      }
    })

    expect(getVerdict(entry)).toBe("clean")
  })

  it("keeps a positive result actionable when another provider failed", () => {
    const entry = buildRow({
      statusKind: "flagged",
      statusText: "8 malicious",
      serviceStatuses: [
        { name: "VirusTotal", status: "flagged", text: "8 malicious" },
        { name: "AbuseIPDB", status: "error", text: "HTTP 429" }
      ],
      result: {
        VirusTotal: {
          data: { attributes: { last_analysis_stats: { malicious: 8 } } }
        },
        AbuseIPDB: { error: "HTTP 429" }
      }
    })

    expect(getVerdict(entry)).toBe("malicious")
    expect(hasFailedLookup(entry.result)).toBe(true)
  })

  it("keeps pending, error and skipped rows out of the risk verdicts", () => {
    expect(getVerdict(buildRow({ isPending: true }))).toBe("pending")
    expect(
      getVerdict(buildRow({ statusKind: "error", statusText: "429" }))
    ).toBe("error")
    expect(
      getVerdict(buildRow({ statusKind: "skipped", statusText: "Private IP" }))
    ).toBe("skipped")
  })
})

describe("hasFailedLookup", () => {
  it("detects row level and provider level failures", () => {
    expect(hasFailedLookup({ error: "Error during bulk check." })).toBe(true)
    expect(hasFailedLookup({ VirusTotal: { error: "429" } })).toBe(true)
  })

  it("ignores successful payloads", () => {
    expect(hasFailedLookup({ VirusTotal: { data: {} } })).toBe(false)
    expect(hasFailedLookup({})).toBe(false)
    expect(hasFailedLookup(undefined)).toBe(false)
  })
})
