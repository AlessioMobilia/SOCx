import { describe, expect, it } from "vitest"

import {
  restoreIntelClipboardText,
  sanitizeIntelClipboardText
} from "./clipboardSanitization"

describe("clipboard intelligence sanitization", () => {
  it("defangs VirusTotal and AbuseIPDB indicator fields", () => {
    const text = [
      "VirusTotal",
      "- IOC:                 https://malicious.example/path/file.exe",
      "- Network:             203.0.113.0/24",
      "- Certificate Subject: *.malicious.example",
      "AbuseIPDB",
      "- IP:                   2001:db8::10",
      "- Domain:               host.example",
      "- Hostnames:            one.example, two.example"
    ].join("\n")

    const sanitized = sanitizeIntelClipboardText(text)

    expect(sanitized).toContain("hxxps://malicious[.]example/path/file[.]exe")
    expect(sanitized).toContain("203[.]0[.]113[.]0/24")
    expect(sanitized).toContain("*.malicious[.]example")
    expect(sanitized).toContain("2001[:]db8[:][:]10")
    expect(sanitized).toContain("one[.]example, two[.]example")
  })

  it("sanitizes report headings and ranges without changing descriptive fields", () => {
    const text = [
      "## 198.51.100.4 (IPv4/32)",
      "Range: 198.51.100.4 → 198.51.100.4",
      "Primary name: invoice.v2.exe",
      "Signature signer: Example S.p.A."
    ].join("\n")

    const sanitized = sanitizeIntelClipboardText(text)

    expect(sanitized).toContain("## 198[.]51[.]100[.]4 (IPv4/32)")
    expect(sanitized).toContain(
      "Range: 198[.]51[.]100[.]4 → 198[.]51[.]100[.]4"
    )
    expect(sanitized).toContain("Primary name: invoice.v2.exe")
    expect(sanitized).toContain("Signature signer: Example S.p.A.")
  })

  it("restores pre-defanged indicator fields when sanitization is disabled", () => {
    const text = [
      "- IOC (defanged): hxxps://malicious[.]example/path",
      "- IP:             203[.]0[.]113[.]4",
      "- IP:             2001[:]db8[:][:]10"
    ].join("\n")

    expect(restoreIntelClipboardText(text)).toBe(
      [
        "- IOC (defanged): https://malicious.example/path",
        "- IP:             203.0.113.4",
        "- IP:             2001:db8::10"
      ].join("\n")
    )
  })

  it("sanitizes source URLs and arbitrary details in service-page reports", () => {
    const text = [
      "SOCx IOC report",
      "- Source: https://example.com/report/203.0.113.8",
      "- Detail: Resolved host — malware.example at 203.0.113.9"
    ].join("\n")

    const sanitized = sanitizeIntelClipboardText(text)

    expect(sanitized).toContain(
      "hxxps://example[.]com/report/203[.]0[.]113[.]8"
    )
    expect(sanitized).toContain(
      "Resolved host — malware[.]example at 203[.]0[.]113[.]9"
    )
  })
})
