import { beforeEach, describe, expect, it } from "vitest"

import { resolveServicePage } from "./servicePageAdapters"
import {
  extractServicePageFields,
  formatServicePageReport,
  isServicePageReady
} from "./servicePageIntel"

const attachShadowFixture = (tagName: string, markup: string): HTMLElement => {
  const host = document.createElement(tagName)
  host.attachShadow({ mode: "open" }).innerHTML = markup
  document.body.appendChild(host)
  return host
}

describe("IOC service page intelligence", () => {
  beforeEach(() => {
    document.title = ""
    document.body.innerHTML = ""
  })

  it("extracts VirusTotal result fields without copying UI descriptions", () => {
    attachShadowFixture(
      "vt-ioc-score-widget-detections-chart",
      `<div><span id="positives">0</span><span> / 91</span></div>`
    )
    attachShadowFixture(
      "vt-ui-ip-card",
      `<div class="card-header"><div class="fw-bold">No security vendor flagged this IP address as malicious</div></div>
       <vt-ui-time-ago data-tooltip-text="2026-08-15 00:58:53 UTC"></vt-ui-time-ago>`
    )
    attachShadowFixture(
      "vt-ui-key-val-table",
      `<div><div class="label">Network</div></div><div class="value" data-tooltip-text="12.4.64.0/18"></div>
       <div><div class="label">Autonomous System Number</div></div><div class="value" data-tooltip-text="7018"></div>
       <div><div class="label">Autonomous System Label</div></div><div class="value" data-tooltip-text="AT&amp;T Enterprises, LLC"></div>
       <div><div class="label">Country</div></div><div class="value" data-tooltip-text="US"></div>
       <div><div class="label">JARM fingerprint</div></div><div class="value">SSL configuration fingerprint</div>
       <div><div class="label">Last HTTPS Certificate</div></div><div class="value">Last certificate observed when attempting HTTPS</div>`
    )
    const page = resolveServicePage(
      "https://www.virustotal.com/gui/ip-address/12.4.78.4"
    )!

    const fields = extractServicePageFields(page, document)

    expect(fields).toContainEqual({
      label: "Verdict",
      value: "0 malicious / 91 vendors"
    })
    expect(fields).toContainEqual({ label: "Network", value: "12.4.64.0/18" })
    expect(fields).toContainEqual({ label: "ASN", value: "7018" })
    expect(fields).toContainEqual({
      label: "AS owner",
      value: "AT&T Enterprises, LLC"
    })
    expect(fields).toContainEqual({ label: "Country", value: "US" })
    expect(fields.map(({ label }) => label)).not.toContain("JARM fingerprint")
    expect(fields.map(({ value }) => value)).not.toContain(
      "SSL configuration fingerprint"
    )
  })

  it("extracts only recognized AbuseIPDB report fields", () => {
    document.body.innerHTML = `
      <div class="col-md-6">
        <div class="well">
          <h3>IP address <b>12.4.78.4</b></h3>
          <p>This IP was reported 17 times.</p>
          <div class="progress-bar" aria-valuenow="42"><span>42%</span></div>
          <table>
            <tr><th>ISP</th><td>AT&amp;T Enterprises, LLC</td></tr>
            <tr><th>Usage Type</th><td>Fixed Line ISP</td></tr>
            <tr><th>Country</th><td>US</td></tr>
            <tr><th>Unrelated explanation</th><td>Should not be copied</td></tr>
          </table>
        </div>
      </div>`
    const page = resolveServicePage(
      "https://www.abuseipdb.com/check/12.4.78.4"
    )!

    const fields = extractServicePageFields(page, document)

    expect(fields).toEqual([
      { label: "IP", value: "12.4.78.4" },
      { label: "Abuse score", value: "42%" },
      { label: "Reports", value: "17" },
      { label: "ISP", value: "AT&T Enterprises, LLC" },
      { label: "Usage", value: "Fixed Line ISP" },
      { label: "Country", value: "US" }
    ])
  })

  it("rejects localized and structural anti-bot interstitials", () => {
    const page = resolveServicePage(
      "https://www.abuseipdb.com/check/12.4.78.4"
    )!
    document.title = "Esecuzione della verifica di sicurezza"
    document.body.innerHTML = `
      <main>
        Questo sito web utilizza un servizio di sicurezza per la protezione dai bot dannosi.
      </main>`

    expect(isServicePageReady(document)).toBe(false)
    expect(extractServicePageFields(page, document)).toEqual([])

    document.title = "AbuseIPDB"
    document.body.innerHTML = `<div id="challenge-stage">Attendere</div>`
    expect(isServicePageReady(document)).toBe(false)
    expect(extractServicePageFields(page, document)).toEqual([])
  })

  it("does not fall back to page summaries or incomplete results", () => {
    const page = resolveServicePage("https://stat.ripe.net/resource/8.8.8.8")!
    document.body.innerHTML = `
      <main>
        <h2>Routing status</h2>
        <p>At 2026-08-14 16:00 UTC, 8.8.8.0/24 was visible by all peers.</p>
        <p>Country: US</p>
      </main>`

    expect(extractServicePageFields(page, document)).toEqual([])

    document.body.innerHTML = `
      <main>
        <p>Prefix: 8.8.8.0/24</p>
        <p>ASN: AS15169</p>
        <p>This arbitrary explanatory paragraph must stay out.</p>
      </main>`
    expect(extractServicePageFields(page, document)).toEqual([
      { label: "Prefix", value: "8.8.8.0/24" },
      { label: "ASN", value: "AS15169" }
    ])
  })

  it("allowlists JSON fields and formats them like API summaries", () => {
    document.body.innerHTML = `<main>{"sha256":"abc123","file_name":"sample.exe","parents":["example.com"],"description":"Ignore me"}</main>`
    const page = resolveServicePage(
      "https://hashlookup.circl.lu/lookup/sha256/abc123"
    )!
    const fields = extractServicePageFields(page, document)
    const report = formatServicePageReport({ page, fields })

    expect(fields).toEqual(
      expect.arrayContaining([
        { label: "SHA256", value: "abc123" },
        { label: "File name", value: "sample.exe" }
      ])
    )
    expect(fields.map(({ label }) => label)).not.toContain("parents")
    expect(fields.map(({ label }) => label)).not.toContain("description")
    expect(report).toContain("CIRCL Hashlookup")
    expect(report).toContain("- IOC:")
    expect(report).toContain("- SHA256:")
    expect(report).not.toContain("SOCx IOC report")
    expect(report).not.toContain("Source:")
    expect(report).not.toContain("Captured:")
    expect(report).not.toContain("Detail:")
  })
})
