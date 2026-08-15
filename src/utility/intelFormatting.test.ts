import { describe, expect, it } from "vitest"

import {
  buildAbuseIntel,
  buildNvdIntel,
  buildVirusTotalIntel,
  classifyIntelTextLine,
  formatIntelSummary
} from "./intelFormatting"
import {
  ABUSE_FIELDS,
  getAbuseExportFields,
  getNvdExportFields,
  getVirusTotalExportFields,
  NVD_FIELDS,
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
    expect(text).toMatch(/Signature:\s+Signed — valid/)
    expect(text).toMatch(/Signature signer:\s+Example Software S\.p\.A\./)
    expect(text).toMatch(/Detection \(Microsoft\):\s+Trojan:Win32\/FakeDoc/)
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
          ].join("\n"),
          last_https_certificate: {
            subject: { CN: "example.test" },
            issuer: { CN: "Example CA" },
            validity: {
              not_before: "2026-01-01T00:00:00Z",
              not_after: "2026-04-01T00:00:00Z"
            }
          }
        }
      }
    })
    const text = formatIntelSummary(summary!)
    expect(text).not.toContain("\nOverview\n")
    expect(text).not.toContain("\nWHOIS\n")
    expect(text).toMatch(/Registrar:\s+Example Registrar LLC/)
    expect(text).toMatch(/Organization:\s+Example Hosting Ltd/)
    expect(text).toMatch(/Country:\s+NL/)
    expect(text).toMatch(/Certificate Subject:\s+example\.test/)
    expect(text).toMatch(/Certificate Issuer:\s+Example CA/)
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
    expect(text).not.toContain("\nNetwork\n")
    expect(text).not.toContain("\nSignals\n")
    expect(text).toMatch(
      /Hostnames:\s+one\.test, two\.test, three\.test \(\+1\)/
    )
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
    expect(getNvdExportFields({})).toHaveLength(NVD_FIELDS.length)
  })

  it("formats NVD CVE details using CVSS, CWE, affected products and KEV data", () => {
    const summary = buildNvdIntel({
      vulnerabilities: [
        {
          cve: {
            id: "CVE-2021-44228",
            vulnStatus: "Analyzed",
            published: "2021-12-10T10:15:09.143",
            lastModified: "2026-08-11T19:33:44.513",
            descriptions: [
              { lang: "en", value: "Remote code execution in Apache Log4j." }
            ],
            metrics: {
              cvssMetricV31: [
                {
                  type: "Primary",
                  cvssData: {
                    version: "3.1",
                    baseScore: 10,
                    baseSeverity: "CRITICAL",
                    vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                  },
                  exploitabilityScore: 3.9,
                  impactScore: 6
                }
              ]
            },
            weaknesses: [
              {
                description: [
                  { lang: "en", value: "CWE-20" },
                  { lang: "en", value: "CWE-502" }
                ]
              }
            ],
            configurations: [
              {
                nodes: [
                  {
                    cpeMatch: [
                      {
                        vulnerable: true,
                        criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                        versionStartIncluding: "2.0-beta9",
                        versionEndExcluding: "2.16.0"
                      }
                    ]
                  }
                ]
              }
            ],
            cisaExploitAdd: "2021-12-10",
            cisaActionDue: "2021-12-24",
            cisaVulnerabilityName: "Apache Log4j2 Remote Code Execution",
            cisaRequiredAction: "Apply updates.",
            references: [{ url: "https://logging.apache.org/security.html" }]
          }
        }
      ]
    })

    const text = formatIntelSummary(summary!)
    expect(text).toMatch(/CVE:\s+CVE-2021-44228/)
    expect(text).toMatch(/CVSS:\s+v3\.1 · 10\.0 · CRITICAL/)
    expect(text).toContain("CWE-20, CWE-502")
    expect(text).toContain("apache log4j (>= 2.0-beta9; < 2.16.0)")
    expect(text).toContain("CISA KEV:")
    expect(text).toContain("Remote code execution in Apache Log4j")
  })
})
