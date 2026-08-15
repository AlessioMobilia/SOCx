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

  it("extracts only the verified RIPEstat routing widget", () => {
    const page = resolveServicePage("https://stat.ripe.net/resource/8.8.8.8")!
    document.title = "RIPEstat · 8.8.8.8"
    document.body.innerHTML = `
      <main id="resource-tabs">
        At 2026-08-14 16:00:00 UTC, 8.8.8.0/24 was 100% visible (by 325 of 325 RIS full peers).
        First ever seen announced by AS21284, on 2002-11-06 16:00:00 UTC.
        Originated by: AS15169 - RPKI Status: Valid Route object: RADB
      </main>`

    expect(extractServicePageFields(page, document)).toEqual([
      { label: "Observed at", value: "2026-08-14 16:00:00 UTC" },
      { label: "Prefix", value: "8.8.8.0/24" },
      {
        label: "Visibility",
        value: "100% visible (by 325 of 325 RIS full peers)"
      },
      { label: "First origin", value: "AS21284" },
      { label: "First seen", value: "2002-11-06 16:00:00 UTC" },
      { label: "Origin", value: "AS15169" },
      { label: "RPKI", value: "Valid" },
      { label: "Route object", value: "RADB" }
    ])
  })

  it("never falls back to arbitrary summaries", () => {
    const page = resolveServicePage("https://stat.ripe.net/resource/8.8.8.8")!
    document.title = "RIPEstat · 8.8.8.8"

    document.body.innerHTML = `
      <main>
        <p>Prefix: 8.8.8.0/24</p>
        <p>ASN: AS15169</p>
        <p>This arbitrary explanatory paragraph must stay out.</p>
      </main>`
    expect(extractServicePageFields(page, document)).toEqual([])
  })

  it("reads MxToolbox only from the ARIN result transcript", () => {
    document.body.innerHTML = `
      <div class="tool-result-div lookup-type-arin">
        <div>arin:12.4.78.4</div>
        <div class="tool-result-body">
          NetRange: 12.0.0.0 - 12.255.255.255
          CIDR: 12.0.0.0/8
          NetName: ATT
          NetType: Direct Allocation
          Organization: AT&amp;T Enterprises, LLC (AEL-360)
          Country: US
          OrgAbuseEmail: abuse@att.net
        </div>
      </div>
      <section>
        <h3>About the SuperTool!</h3>
        <table><tr><td>Domain</td><td>IP Address</td></tr><tr><td>IP</td><td>Host Name.</td></tr></table>
      </section>`
    const page = resolveServicePage(
      "https://mxtoolbox.com/SuperTool.aspx?action=arin%3a12.4.78.4"
    )!

    expect(extractServicePageFields(page, document)).toEqual([
      { label: "Network range", value: "12.0.0.0 - 12.255.255.255" },
      { label: "CIDR", value: "12.0.0.0/8" },
      { label: "Network name", value: "ATT" },
      { label: "Network type", value: "Direct Allocation" },
      {
        label: "Organization",
        value: "AT&T Enterprises, LLC (AEL-360)"
      },
      { label: "Country", value: "US" },
      { label: "Abuse email", value: "abuse@att.net" }
    ])
  })

  it("reads IBM X-Force only from Details and WHOIS", () => {
    document.body.innerHTML = `
      <h2>X-Force IP Report 12.4.78.4</h2>
      <h3 class="h3details">Details</h3>
      <table class="detailsline">
        <tr id="categories"><th>Categorization</th><td>Unsuspicious</td></tr>
        <tr id="hosted"><th>Application</th><td>No known application</td></tr>
        <tr id="country-of-ip"><th>Location</th><td></td></tr>
        <tr id="asn"><th>ASN</th><td>AS 7018: AT&amp;T Enterprises, LLC, US</td></tr>
      </table>
      <div id="whois"><table class="detailsline">
        <tr><th>Created</th><td>23 ago 1983</td></tr>
        <tr><th>Registrant Organization</th><td>AT&amp;T Enterprises, LLC</td></tr>
        <tr><th>Registrant Country or Region</th><td>United States</td></tr>
      </table></div>
      <table class="timeline"><tr><th>Category</th><th>Reason</th><th>Location</th></tr>
        <tr><td>Miscellaneous</td><td>Regional Internet Registry</td><td>United States</td></tr>
      </table>`
    const page = resolveServicePage(
      "https://exchange.xforce.ibmcloud.com/ip/12.4.78.4"
    )!

    expect(extractServicePageFields(page, document)).toEqual([
      { label: "Categorization", value: "Unsuspicious" },
      { label: "Application", value: "No known application" },
      { label: "ASN", value: "AS 7018: AT&T Enterprises, LLC, US" },
      { label: "Created", value: "23 ago 1983" },
      { label: "Organization", value: "AT&T Enterprises, LLC" },
      { label: "Country", value: "United States" }
    ])
  })

  it("extracts Pulsedive Highlights and Events", () => {
    document.body.innerHTML = `<main>
      <h1>12.4.78.4</h1>
      <p><i class="fas fa-risk-unknown"></i>Unknown risk</p>
      <div class="info"><h3>Highlights</h3>
        <div class="highlight"><span>Washington, District of Columbia, AT&amp;T Enterprises, LLC</span></div>
        <div class="highlight"><div class="descriptor" data-note="ASN"><span>AS7018</span></div></div>
      </div>
      <div class="info"><h3>Events</h3>
        <p><label>Registered</label><span class="stamp" data-utc="2024-11-22 00:00:00"></span></p>
        <p><label>Seen</label><span class="stamp" data-utc="2026-08-15 02:18:08"></span></p>
      </div>
    </main>`
    const page = resolveServicePage(
      "https://pulsedive.com/indicator/12.4.78.4"
    )!

    expect(extractServicePageFields(page, document)).toEqual([
      { label: "Risk", value: "Unknown risk" },
      {
        label: "Location",
        value: "Washington, District of Columbia, AT&T Enterprises, LLC"
      },
      { label: "ASN", value: "AS7018" },
      { label: "Registered", value: "2024-11-22 00:00:00" },
      { label: "Last seen", value: "2026-08-15 02:18:08" }
    ])
  })

  it("extracts Spur IP Context label/value pairs", () => {
    document.body.innerHTML = `<main>
      <h1>12.4.78.4</h1>
      <p>Average Devices Count</p><p>N/A</p>
      <p>Infrastructure Type</p><p>Unknown</p>
      <p>IP Behavior</p><p>Not Anonymous</p>
      <p>Observed Risks</p><p>None</p>
      <p>ASN</p><a>7018</a>
      <p>Registered To</p><p>AT&amp;T Enterprises, LLC</p>
      <p>Exit Location</p><img alt="US flag"><div>Washington D.C., District of Columbia, US</div>
    </main>`
    const page = resolveServicePage("https://spur.us/context/12.4.78.4")!

    expect(extractServicePageFields(page, document)).toEqual([
      { label: "Infrastructure", value: "Unknown" },
      { label: "Behavior", value: "Not Anonymous" },
      { label: "Risks", value: "None" },
      { label: "ASN", value: "7018" },
      { label: "Organization", value: "AT&T Enterprises, LLC" },
      {
        label: "Location",
        value: "Washington D.C., District of Columbia, US"
      }
    ])
  })

  it("keeps IPQualityScore extraction inside the lookup result card", () => {
    document.body.innerHTML = `<div class="surface-default card-shadow">
      <form id="lookupForm"></form><div>8.8.8.8</div>
      <div class="lookup-section"><table>
        <tr><th>Country</th><th>Region</th><th>VPN</th><th>PROXY</th></tr>
        <tr><td>United States</td><td>California</td><td>No</td><td>No</td></tr>
        <tr><th>ISP</th><th>Hostname</th><th>ASN</th><th>TOR</th></tr>
        <tr><td>Google</td><td>dns.google</td><td>AS15169</td><td>No</td></tr>
      </table></div>
      <div>0 <div><h3>Risk Summary</h3><p>Low Risk - clean result</p></div></div>
    </div>
    <table><tr><th>Detection Method</th><th>How It Works</th></tr>
      <tr><td>Static blocklists</td><td>Marketing explanation</td></tr></table>`
    const page = resolveServicePage(
      "https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/8.8.8.8"
    )!

    const fields = extractServicePageFields(page, document)
    expect(fields).toEqual(
      expect.arrayContaining([
        { label: "Country", value: "United States" },
        { label: "VPN", value: "No" },
        { label: "ISP", value: "Google" },
        { label: "ASN", value: "AS15169" },
        { label: "Fraud score", value: "0/100" },
        { label: "Risk", value: "Low Risk" }
      ])
    )
    expect(fields.map(({ value }) => value)).not.toContain(
      "Marketing explanation"
    )
  })

  it("reads IPinfo two-cell result tables", () => {
    document.body.innerHTML = `<main class="flex-grow">
      <h1>8.8.8.8</h1><table><tbody>
        <tr><td>Location</td><td>Mountain View, California, US</td></tr>
        <tr><td>ASN</td><td>AS15169 — Google LLC</td></tr>
        <tr><td>Hostname</td><td>dns.google</td></tr>
        <tr><td>Range</td><td>8.8.8.0/24</td></tr>
      </tbody></table>
      <table><tbody><tr><td>City</td><td>Mountain View</td></tr>
        <tr><td>Country</td><td>United States</td></tr></tbody></table>
    </main>`
    const page = resolveServicePage("https://ipinfo.io/8.8.8.8")!

    expect(extractServicePageFields(page, document)).toEqual([
      { label: "Location", value: "Mountain View, California, US" },
      { label: "ASN", value: "AS15169 — Google LLC" },
      { label: "Hostname", value: "dns.google" },
      { label: "Range", value: "8.8.8.0/24" },
      { label: "City", value: "Mountain View" },
      { label: "Country", value: "United States" }
    ])
  })

  it("reads OTX and Shodan only from their result components", () => {
    document.title = "IPv4: 8.8.8.8 - LevelBlue - Open Threat Exchange"
    document.body.innerHTML = `<otx-ip-summary>
      <div class="item"><div class="title">Location</div><div class="value">United States</div></div>
      <div class="item"><div class="title">ASN</div><div class="value">AS15169 google llc</div></div>
    </otx-ip-summary>`
    const otx = resolveServicePage(
      "https://otx.alienvault.com/indicator/ip/8.8.8.8"
    )!
    expect(extractServicePageFields(otx, document)).toEqual([
      { label: "Location", value: "United States" },
      { label: "ASN", value: "AS15169 google llc" }
    ])

    document.title = "8.8.8.8"
    document.body.innerHTML = `<div id="host">
      <div class="top-info"><h6 class="grid-heading">Last Seen: 2026-08-15</h6></div>
      <h1 id="general">General Information</h1><div class="grid-table">
        <label>Hostnames</label><div>dns.google</div>
        <label>Country</label><div>United States</div>
        <label>Organization</label><div>Google LLC</div>
        <label>ISP</label><div>Google LLC</div>
        <label>ASN</label><div>AS15169</div>
      </div></div>`
    const shodan = resolveServicePage("https://www.shodan.io/host/8.8.8.8")!
    expect(extractServicePageFields(shodan, document)).toEqual([
      { label: "Hostnames", value: "dns.google" },
      { label: "Country", value: "United States" },
      { label: "Organization", value: "Google LLC" },
      { label: "ISP", value: "Google LLC" },
      { label: "ASN", value: "AS15169" },
      { label: "Last seen", value: "2026-08-15" }
    ])
  })

  it("reads BGP Toolkit, ViewDNS and Cloudflare named result areas", () => {
    document.body.innerHTML = `<h1>AS15169 Google LLC</h1><div id="asinfo">
      <div class="asleft">Company Website:</div><div class="asright">https://about.google/</div>
      <div class="asleft">Country of Origin:</div><div class="asright">United States</div>
      Internet Exchanges: 211
      Prefixes Originated (all): 1,422
      Prefixes Announced (all): 5,366
      RPKI Originated Valid (all): 1,418
    </div>`
    const bgp = resolveServicePage("https://bgp.he.net/AS15169")!
    expect(extractServicePageFields(bgp, document)).toEqual(
      expect.arrayContaining([
        { label: "AS name", value: "Google LLC" },
        { label: "Country", value: "United States" },
        { label: "Prefixes originated", value: "1,422" }
      ])
    )

    document.body.innerHTML = `<main><h2>Reverse DNS results for '8.8.8.8'</h2>
      <table><tr><th>HOSTNAME</th></tr><tr><td>dns.google</td></tr></table></main>`
    const viewDns = resolveServicePage(
      "https://viewdns.info/reversedns/?ip=8.8.8.8"
    )!
    expect(extractServicePageFields(viewDns, document)).toEqual([
      { label: "Reverse DNS", value: "dns.google" }
    ])

    document.body.innerHTML = `<main><h1>Domain Information for example.com</h1>
      <article><h2>WHOIS</h2><dl>
        <div class="group"><dt>Created</dt><dd>Aug 14, 1995</dd></div>
        <div class="group"><dt>Registrar</dt><dd>IANA</dd></div>
        <div class="group"><dt>Nameservers</dt><dd>elliott.ns.cloudflare.com hera.ns.cloudflare.com</dd></div>
      </dl></article>
      <article><h2>DNS records</h2><table><tbody>
        <tr><td>A</td><td>example.com</td><td>104.20.23.154</td></tr>
        <tr><td>A</td><td>example.com</td><td>172.66.147.243</td></tr>
      </tbody></table></article></main>`
    const cloudflare = resolveServicePage(
      "https://radar.cloudflare.com/domains/domain/example.com"
    )!
    expect(extractServicePageFields(cloudflare, document)).toEqual([
      { label: "Created", value: "Aug 14, 1995" },
      { label: "Registrar", value: "IANA" },
      {
        label: "Nameservers",
        value: "elliott.ns.cloudflare.com hera.ns.cloudflare.com"
      },
      { label: "DNS A", value: "104.20.23.154, 172.66.147.243" }
    ])
  })

  it("does not parse aggregate search pages", () => {
    document.body.innerHTML = `<main><table>
      <tr><th>URL</th><th>IP</th><th>Score</th></tr>
      <tr><td>example.com</td><td>8.8.8.8</td><td>1</td></tr>
      <tr><td>unrelated.example</td><td>203.0.113.8</td><td>9</td></tr>
    </table></main>`
    const page = resolveServicePage("https://urlscan.io/search/#example.com")!

    expect(extractServicePageFields(page, document)).toEqual([])
  })

  it("allowlists JSON fields and formats them like API summaries", () => {
    document.body.innerHTML = `<main>{"sha256":"abc123","file_name":"sample.exe","ProductCode":{"ProductName":"Example Product"},"parents":["example.com"],"description":"Ignore me"}</main>`
    const page = resolveServicePage(
      "https://hashlookup.circl.lu/lookup/sha256/abc123"
    )!
    const fields = extractServicePageFields(page, document)
    const report = formatServicePageReport({ page, fields })

    expect(fields).toEqual(
      expect.arrayContaining([
        { label: "SHA256", value: "abc123" },
        { label: "File name", value: "sample.exe" },
        { label: "Product", value: "Example Product" }
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
    expect(report).not.toContain("[object Object]")
  })
})
