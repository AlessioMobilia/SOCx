import { describe, expect, it } from "vitest"

import { resolveServicePage } from "./servicePageAdapters"
import {
  extractServicePageFields,
  formatServicePageReport,
  isServicePageReady
} from "./servicePageIntel"

describe("IOC service page intelligence", () => {
  it("extracts table, definition-list and text-pair data", () => {
    document.body.innerHTML = `
      <main>
        <table>
          <tr><th>Risk</th><th>Country</th></tr>
          <tr><td>High</td><td>IT</td></tr>
        </table>
        <dl><dt>ASN</dt><dd>AS64496</dd></dl>
        <div>Resolved IP: 203.0.113.8</div>
      </main>
    `
    const page = resolveServicePage(
      "https://stat.ripe.net/resource/203.0.113.8"
    )!

    const fields = extractServicePageFields(page, document)

    expect(fields).toContainEqual({
      label: "Table 1, row 2",
      value: "Risk=High | Country=IT"
    })
    expect(fields).toContainEqual({ label: "ASN", value: "AS64496" })
    expect(fields).toContainEqual({
      label: "Resolved IP",
      value: "203.0.113.8"
    })
  })

  it("flattens JSON reports and formats a sanitizable SOCx report", () => {
    document.body.innerHTML = `<main>{"file_name":"sample.exe","parents":["example.com"]}</main>`
    const page = resolveServicePage(
      "https://hashlookup.circl.lu/lookup/sha256/abc123"
    )!
    const fields = extractServicePageFields(page, document)
    const report = formatServicePageReport({
      page,
      fields,
      sourceUrl:
        "https://hashlookup.circl.lu/lookup/sha256/abc123?utm_source=test&__cf_token=secret",
      capturedAt: new Date("2026-08-15T10:00:00.000Z")
    })

    expect(fields).toContainEqual({ label: "file_name", value: "sample.exe" })
    expect(report).toContain("SOCx IOC report")
    expect(report).toContain("- Service: CIRCL Hashlookup")
    expect(report).toContain("- Detail: parents 1 — example.com")
    expect(report).not.toContain("utm_source")
    expect(report).not.toContain("__cf_token")
  })

  it("keeps concise visible summaries when a SPA exposes no tables", () => {
    document.body.innerHTML = `
      <main>
        <h2>Routing status</h2>
        <p>At 2026-08-14 16:00 UTC, 8.8.8.0/24 was visible by all peers.</p>
        <p>Originated by AS15169 with valid RPKI status.</p>
      </main>
    `
    const page = resolveServicePage("https://stat.ripe.net/resource/8.8.8.8")!

    const fields = extractServicePageFields(page, document)

    expect(
      fields.some(({ value }) => value.includes("visible by all peers"))
    ).toBe(true)
    expect(fields.some(({ value }) => value.includes("valid RPKI"))).toBe(true)
  })

  it("waits until anti-bot interstitials have been cleared", () => {
    document.title = "Just a moment..."
    document.body.innerHTML = "<main>Checking your browser</main>"
    expect(isServicePageReady(document)).toBe(false)

    document.title = "Domain information"
    document.body.innerHTML = "<main>Risk: Low</main>"
    expect(isServicePageReady(document)).toBe(true)
  })
})
