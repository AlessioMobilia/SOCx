import { describe, expect, it } from "vitest"

import {
  buildAbuseIntel,
  buildVirusTotalIntel,
  classifyIntelTextLine,
  formatIntelSummary
} from "./intelFormatting"
import {
  ABUSE_FIELDS,
  getAbuseExportFields,
  getVirusTotalExportFields,
  VT_FIELDS
} from "./utils"

describe("compact intelligence formatting", () => {
  it("caps file aliases and reports a valid digital signature", () => {
    const summary = buildVirusTotalIntel({
      data: {
        id: "a".repeat(64),
        type: "file",
        attributes: {
          meaningful_name: "invoice_update.exe",
          names: [
            "invoice_update.exe",
            "invoice.exe",
            "update.exe",
            "viewer.scr",
            "sample.bin"
          ],
          type_description: "Win32 EXE",
          size: 844_000,
          sha256: "a".repeat(64),
          last_analysis_stats: {
            malicious: 34,
            suspicious: 2,
            harmless: 10,
            undetected: 26
          },
          signature_info: {
            verified: "Signed",
            signers: "Example Software S.p.A.",
            product: "Example Viewer"
          },
          last_analysis_results: {
            Microsoft: {
              category: "malicious",
              result: "Trojan:Win32/FakeDoc"
            },
            ESET: { category: "malicious", result: "Win32/TrojanDownloader" },
            Sophos: { category: "suspicious", result: "Mal/Generic-S" },
            Extra: { category: "malicious", result: "Generic" }
          }
        }
      }
    })

    const text = formatIntelSummary(summary!)
    expect(text).toMatch(
      /Other names:\s+invoice\.exe, update\.exe, viewer\.scr \(\+1\)/
    )
    expect(text).toContain("Status:  Signed — valid")
    expect(text).toContain("Additional detections: +1")
    expect(
      summary?.sections.find((section) => section.title === "Digital signature")
        ?.fields[0].tone
    ).toBe("success")
  })

  it("marks an invalid signature as warning rather than asserting malware", () => {
    const summary = buildVirusTotalIntel({
      data: {
        id: "b".repeat(64),
        type: "file",
        attributes: {
          last_analysis_stats: {},
          signature_info: {
            verified: "Signed",
            "signers details": [
              { name: "Example Ltd", status: "Certificate expired" }
            ]
          }
        }
      }
    })
    const status = summary?.sections.find(
      (section) => section.title === "Digital signature"
    )?.fields[0]
    expect(status?.value).toContain("Signed — invalid")
    expect(status?.tone).toBe("warning")
  })

  it("extracts a compact WHOIS summary", () => {
    const summary = buildVirusTotalIntel({
      data: {
        id: "example.test",
        type: "domain",
        attributes: {
          last_analysis_stats: {
            malicious: 0,
            suspicious: 0,
            harmless: 12,
            undetected: 30
          },
          whois: [
            "Registrar: Example Registrar LLC",
            "Creation Date: 2024-11-07T00:00:00Z",
            "Registry Expiry Date: 2026-11-07T00:00:00Z",
            "Registrant Organization: Example Hosting Ltd",
            "Registrant Country: NL"
          ].join("\n")
        }
      }
    })
    const text = formatIntelSummary(summary!)
    expect(text).toMatch(/Registrar:\s+Example Registrar LLC/)
    expect(text).toMatch(/Organization:\s+Example Hosting Ltd/)
    expect(text).toMatch(/Country:\s+NL/)
  })

  it("caps AbuseIPDB hostnames and distinguishes whitelist from risk signals", () => {
    const summary = buildAbuseIntel({
      data: {
        ipAddress: "203.0.113.10",
        abuseConfidenceScore: 92,
        totalReports: 184,
        numDistinctUsers: 37,
        isp: "Example Hosting",
        usageType: "Data Center/Web Hosting/Transit",
        hostnames: ["one.test", "two.test", "three.test", "four.test"],
        isTor: true,
        isWhitelisted: true
      }
    })
    const text = formatIntelSummary(summary!)
    expect(text).toContain("Hostnames: one.test, two.test, three.test (+1)")
    expect(
      summary?.sections[0].fields.find((field) => field.label === "Abuse score")
        ?.tone
    ).toBe("danger")
    expect(
      summary?.sections[2].fields.find((field) => field.label === "TOR")?.tone
    ).toBe("warning")
    expect(
      summary?.sections[2].fields.find((field) => field.label === "Whitelisted")
        ?.tone
    ).toBe("success")
  })

  it("does not color undetected counts or unsigned files as benign", () => {
    expect(classifyIntelTextLine("- Undetected: 70")).toBe("neutral")
    expect(classifyIntelTextLine("- Status: Unsigned")).toBe("neutral")
    expect(
      classifyIntelTextLine(
        "- Verdict: 0 malicious · 0 suspicious · 10 harmless"
      )
    ).toBe("success")
  })

  it("keeps spreadsheet export schemas aligned with enriched values", () => {
    expect(getAbuseExportFields({})).toHaveLength(ABUSE_FIELDS.length)
    expect(getVirusTotalExportFields({}, {})).toHaveLength(VT_FIELDS.length)
  })
})
