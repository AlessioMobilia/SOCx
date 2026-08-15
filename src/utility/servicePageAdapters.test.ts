import { describe, expect, it } from "vitest"

import { resolveServicePage, servicePageAdapters } from "./servicePageAdapters"
import {
  parserProviderIds,
  servicePageParserSupport
} from "./servicePageParsers"

describe("IOC service page adapters", () => {
  it.each([
    ["https://www.abuseipdb.com/check/203.0.113.8", "AbuseIPDB", "203.0.113.8"],
    [
      "https://www.virustotal.com/gui/domain/example.com",
      "VirusTotal",
      "example.com"
    ],
    [
      "https://www.virustotal.com/gui/url/aHR0cHM6Ly9leGFtcGxlLmNvbS9wYXRo",
      "VirusTotal",
      "https://example.com/path"
    ],
    [
      "https://otx.alienvault.com/indicator/ip/8.8.8.8",
      "AlienVault",
      "8.8.8.8"
    ],
    ["https://stat.ripe.net/resource/AS13335", "RIPEstat", "AS13335"],
    [
      "https://haveibeenpwned.com/unifiedsearch/analyst%40example.com",
      "HaveIBeenPwned",
      "analyst@example.com"
    ],
    [
      "https://www.threatminer.org/domain.php?q=example.com",
      "ThreatMiner",
      "example.com"
    ],
    ["https://crt.sh/?q=example.com", "CTSearch", "example.com"],
    [
      "https://hashlookup.circl.lu/lookup/sha256/abc123",
      "CIRCLHashlookup",
      "abc123"
    ]
  ])("resolves %s", (url, service, ioc) => {
    const page = resolveServicePage(url)

    expect(page?.adapter.id).toBe(service)
    expect(page?.ioc).toBe(ioc)
  })

  it("ignores unsupported pages and service landing pages without an IOC", () => {
    expect(resolveServicePage("https://example.com/check/8.8.8.8")).toBeNull()
    expect(resolveServicePage("https://www.virustotal.com/gui/home")).toBeNull()
  })

  it("has an explicit parser contract for every page adapter", () => {
    expect([...parserProviderIds].sort()).toEqual(
      servicePageAdapters.map(({ id }) => id).sort()
    )
    expect(Object.keys(servicePageParserSupport).sort()).toEqual(
      servicePageAdapters.map(({ id }) => id).sort()
    )
  })

  it("disables extraction on aggregate or unverifiable result pages", () => {
    expect(
      [
        "Censys",
        "PassiveDNS",
        "Hunter",
        "SecurityTrails",
        "UrlScan",
        "HaveIBeenPwned",
        "WiresharkOUI",
        "GreyNoise",
        "MalwareBazaar",
        "Robtex",
        "Tria_ge",
        "ThreatFox",
        "CiscoTalos",
        "URLhaus",
        "Spamhaus",
        "ThreatMiner",
        "CTSearch"
      ].every((id) => servicePageParserSupport[id]?.supported === false)
    ).toBe(true)
  })
})
