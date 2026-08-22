import { describe, expect, it } from "vitest"

import { formatSmartContainer } from "./smartFormatting"

const fixture = (html: string): HTMLElement => {
  const root = document.createElement("div")
  root.innerHTML = html
  return root
}

describe("smart formatting structure matrix", () => {
  it("treats a spanning OSINT table title as context, not column headers", () => {
    const result = formatSmartContainer(
      fixture(`
        <table>
          <thead><tr><th colspan="2">IP address summary information</th></tr></thead>
          <tbody>
            <tr><td>Location</td><td>Mountain View, California, US</td></tr>
            <tr><td>ASN</td><td><a>AS15169 — Google LLC</a><button data-testid="copy">Copy</button></td></tr>
            <tr><td>Hostname</td><td>dns.google</td></tr>
            <tr><td>Range</td><td>8.8.8.0/24</td></tr>
          </tbody>
        </table>
      `)
    )

    expect(result?.kind).toBe("semantic-key-value")
    expect(result?.text).toContain("Location: Mountain View, California, US")
    expect(result?.text).toContain("ASN:      AS15169 — Google LLC")
    expect(result?.text).not.toContain("IP address summary information:")
    expect(result?.text).not.toContain("Copy")
  })

  it("reads an OSINT label grid with separators and multiline values", () => {
    const result = formatSmartContainer(
      fixture(`
        <section class="grid-table">
          <label>Hostnames</label>
          <div class="font-mono"><a>resolver.example</a><br><a>dns.example</a></div>
          <div class="grid-border"></div>
          <label>Country</label><div>United States</div><div class="grid-border"></div>
          <label>Organization</label><div>Example Networks LLC</div><div class="grid-border"></div>
          <label>ASN</label><div>AS64500</div>
        </section>
      `)
    )

    expect(result?.kind).toBe("semantic-key-value")
    expect(result?.text).toContain("Hostnames:    resolver.example dns.example")
    expect(result?.text).toContain("Organization: Example Networks LLC")
  })

  it("reads accessible EDR detail groups labelled with aria-labelledby", () => {
    const result = formatSmartContainer(
      fixture(`
        <section>
          <div role="group" aria-labelledby="source-label">
            <span id="source-label">Source IP</span>
            <a>203.0.113.24</a>
            <button aria-label="Copy source IP">Copy</button>
          </div>
          <div role="group" aria-labelledby="process-label">
            <span id="process-label">Process</span>
            <code>powershell.exe</code>
          </div>
          <div role="group" aria-labelledby="severity-label">
            <span id="severity-label">Severity</span>
            <span class="badge">High</span>
          </div>
        </section>
      `)
    )

    expect(result?.kind).toBe("semantic-key-value")
    expect(result?.text).toContain("Source IP: 203.0.113.24")
    expect(result?.text).toContain("Process:   powershell.exe")
    expect(result?.text).toContain("Severity:  High")
    expect(result?.text).not.toContain("Copy")
  })

  it("supports ARIA term and definition pairs used by SIEM flyouts", () => {
    const result = formatSmartContainer(
      fixture(`
        <div role="list">
          <div role="term">Rule name</div>
          <div role="definition">Suspicious PowerShell</div>
          <div role="term">Tactic</div>
          <div role="definition"><span>Execution</span></div>
          <div role="term">Technique</div>
          <div role="definition"><a>T1059.001</a></div>
        </div>
      `)
    )

    expect(result?.kind).toBe("semantic-key-value")
    expect(result?.text).toContain("Rule name: Suspicious PowerShell")
    expect(result?.text).toContain("Technique: T1059.001")
  })

  it("joins consecutive definitions for multi-valued XDR fields", () => {
    const result = formatSmartContainer(
      fixture(`
        <dl>
          <dt>Affected hosts</dt>
          <dd>WS-FIN-01</dd>
          <dd>WS-FIN-02</dd>
          <dt>Tags</dt>
          <dd>
            <span class="chip">Credential Access</span>
            <button aria-label="More tag actions">More</button>
            <span role="tooltip">Internal tag metadata</span>
          </dd>
          <dd><span class="chip">Lateral Movement</span></dd>
        </dl>
      `)
    )

    expect(result?.kind).toBe("semantic-key-value")
    expect(result?.text).toContain("Affected hosts: WS-FIN-01 WS-FIN-02")
    expect(result?.text).toContain(
      "Tags:           Credential Access Lateral Movement"
    )
    expect(result?.text).not.toContain("More")
    expect(result?.text).not.toContain("Internal tag metadata")
  })

  it("treats a two-column table as key/value data", () => {
    const result = formatSmartContainer(
      fixture(`
        <table>
          <thead><tr><th>Entity</th><th>Risk</th></tr></thead>
          <tbody>
            <tr><td>DC-01</td><td>Critical</td></tr>
            <tr><td>WS-023</td><td>High</td></tr>
          </tbody>
        </table>
      `)
    )

    expect(result?.kind).toBe("semantic-key-value")
    expect(result?.text).toBe("DC-01:  Critical\nWS-023: High")
  })

  it("reads nested definition-list cards used by investigation panels", () => {
    const result = formatSmartContainer(
      fixture(`
        <dl class="details-grid">
          <div class="detail-card"><dt>Command line</dt><dd><code>cmd.exe /c whoami</code></dd></div>
          <div class="detail-card"><dt>Parent process</dt><dd>winword.exe</dd></div>
          <div class="detail-card"><dt>Disposition</dt><dd><span class="badge">Blocked</span></dd></div>
        </dl>
      `)
    )

    expect(result?.kind).toBe("semantic-key-value")
    expect(result?.text).toContain("Command line:   cmd.exe /c whoami")
    expect(result?.text).toContain("Parent process: winword.exe")
  })

  it("does not extract navigation controls merely labelled by ARIA", () => {
    const result = formatSmartContainer(
      fixture(`
        <nav aria-labelledby="navigation-title">
          <h2 id="navigation-title">Investigation navigation</h2>
          <a>Overview</a><a>Timeline</a><a>Entities</a>
        </nav>
      `)
    )

    expect(result).toBeNull()
  })
})
