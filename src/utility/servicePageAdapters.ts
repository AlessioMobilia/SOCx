export type ServicePageAdapter = {
  id: string
  label: string
  hostnames: string[]
  resolveIOC: (url: URL) => string | null
  rootSelectors?: string[]
}

export type ResolvedServicePage = {
  adapter: ServicePageAdapter
  ioc: string
}

const decode = (value: string | null | undefined): string | null => {
  if (!value) return null
  try {
    return decodeURIComponent(value).trim() || null
  } catch {
    return value.trim() || null
  }
}

const segmentAfter = (url: URL, marker: string): string | null => {
  const segments = url.pathname.split("/").filter(Boolean)
  const markerIndex = segments.indexOf(marker)
  return decode(markerIndex >= 0 ? segments[markerIndex + 1] : null)
}

const firstSegment = (url: URL): string | null =>
  decode(url.pathname.split("/").filter(Boolean)[0])

const queryValue = (url: URL, name: string): string | null =>
  decode(url.searchParams.get(name))

const hashQueryValue = (url: URL, name: string): string | null => {
  const queryIndex = url.hash.indexOf("?")
  if (queryIndex < 0) return null
  return decode(new URLSearchParams(url.hash.slice(queryIndex + 1)).get(name))
}

const stripPrefix = (value: string | null, prefix: RegExp): string | null =>
  value ? value.replace(prefix, "").trim() || null : null

const decodeVirusTotalUrl = (value: string | null): string | null => {
  if (!value) return null
  try {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/")
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=")
    return decode(atob(padded))
  } catch {
    return value
  }
}

const virusTotalIOC = (url: URL): string | null => {
  const segments = url.pathname.split("/").filter(Boolean)
  const guiIndex = segments.indexOf("gui")
  const type = guiIndex >= 0 ? segments[guiIndex + 1] : null
  const value = decode(guiIndex >= 0 ? segments[guiIndex + 2] : null)
  return type === "url" ? decodeVirusTotalUrl(value) : value
}

const otxIOC = (url: URL): string | null => {
  const segments = url.pathname.split("/").filter(Boolean)
  const indicatorIndex = segments.indexOf("indicator")
  return decode(indicatorIndex >= 0 ? segments[indicatorIndex + 2] : null)
}

const xForceIOC = (url: URL): string | null => {
  const segments = url.pathname.split("/").filter(Boolean)
  return decode(segments.length >= 2 ? segments.slice(1).join("/") : null)
}

const mxToolboxIOC = (url: URL): string | null =>
  stripPrefix(queryValue(url, "action"), /^(?:arin|dns):/i)

const threatFoxIOC = (url: URL): string | null =>
  stripPrefix(queryValue(url, "search"), /^ioc\s*:\s*/i)

const viewDnsIOC = (url: URL): string | null =>
  queryValue(url, "ip") ?? queryValue(url, "domain") ?? queryValue(url, "asn")

const circlIOC = (url: URL): string | null => {
  const segments = url.pathname.split("/").filter(Boolean)
  return decode(segments[0] === "lookup" ? segments[2] : null)
}

export const servicePageAdapters: ServicePageAdapter[] = [
  {
    id: "VirusTotal",
    label: "VirusTotal",
    hostnames: ["www.virustotal.com"],
    resolveIOC: virusTotalIOC,
    rootSelectors: ["#view-container", "main", "[role='main']"]
  },
  {
    id: "AbuseIPDB",
    label: "AbuseIPDB",
    hostnames: ["www.abuseipdb.com"],
    resolveIOC: (url) => segmentAfter(url, "check"),
    rootSelectors: [".col-md-6 .well", "main", ".container"]
  },
  {
    id: "Censys",
    label: "Censys",
    hostnames: ["search.censys.io"],
    resolveIOC: (url) => segmentAfter(url, "hosts") ?? queryValue(url, "q")
  },
  {
    id: "IPQualityScore",
    label: "IPQualityScore",
    hostnames: ["www.ipqualityscore.com"],
    resolveIOC: (url) => segmentAfter(url, "lookup")
  },
  {
    id: "IPinfo",
    label: "IPinfo",
    hostnames: ["ipinfo.io"],
    resolveIOC: firstSegment
  },
  {
    id: "AlienVault",
    label: "LevelBlue OTX",
    hostnames: ["otx.alienvault.com"],
    resolveIOC: otxIOC
  },
  {
    id: "IBMXForce",
    label: "IBM X-Force",
    hostnames: ["exchange.xforce.ibmcloud.com"],
    resolveIOC: xForceIOC
  },
  {
    id: "MxToolbox",
    label: "MxToolbox",
    hostnames: ["mxtoolbox.com", "www.mxtoolbox.com"],
    resolveIOC: mxToolboxIOC
  },
  {
    id: "Pulsedive",
    label: "Pulsedive",
    hostnames: ["pulsedive.com"],
    resolveIOC: (url) => segmentAfter(url, "indicator")
  },
  {
    id: "Spur",
    label: "Spur",
    hostnames: ["spur.us"],
    resolveIOC: (url) => segmentAfter(url, "context")
  },
  {
    id: "PassiveDNS",
    label: "Mnemonic Passive DNS",
    hostnames: ["passivedns.mnemonic.no"],
    resolveIOC: (url) => hashQueryValue(url, "query")
  },
  {
    id: "Hunter",
    label: "Hunter",
    hostnames: ["hunter.io"],
    resolveIOC: (url) => segmentAfter(url, "email-verifier")
  },
  {
    id: "Shodan",
    label: "Shodan",
    hostnames: ["www.shodan.io"],
    resolveIOC: (url) => segmentAfter(url, "host")
  },
  {
    id: "SecurityTrails",
    label: "SecurityTrails",
    hostnames: ["securitytrails.com"],
    resolveIOC: (url) => segmentAfter(url, "domain")
  },
  {
    id: "UrlScan",
    label: "urlscan.io",
    hostnames: ["urlscan.io"],
    resolveIOC: (url) => decode(url.hash.replace(/^#/, ""))
  },
  {
    id: "HaveIBeenPwned",
    label: "Have I Been Pwned",
    hostnames: ["haveibeenpwned.com"],
    resolveIOC: (url) => segmentAfter(url, "unifiedsearch")
  },
  {
    id: "MACVendors",
    label: "MAC Vendors",
    hostnames: ["api.macvendors.com"],
    resolveIOC: firstSegment
  },
  {
    id: "WiresharkOUI",
    label: "Wireshark OUI",
    hostnames: ["www.wireshark.org"],
    resolveIOC: (url) => queryValue(url, "search")
  },
  {
    id: "GreyNoise",
    label: "GreyNoise",
    hostnames: ["viz.greynoise.io"],
    resolveIOC: (url) => segmentAfter(url, "ip")
  },
  {
    id: "MalwareBazaar",
    label: "MalwareBazaar",
    hostnames: ["bazaar.abuse.ch"],
    resolveIOC: (url) => segmentAfter(url, "sample")
  },
  {
    id: "Robtex",
    label: "Robtex",
    hostnames: ["www.robtex.com"],
    resolveIOC: (url) => segmentAfter(url, "ip-lookup")
  },
  {
    id: "BGPToolkit",
    label: "Hurricane Electric BGP Toolkit",
    hostnames: ["bgp.he.net"],
    resolveIOC: firstSegment
  },
  {
    id: "Tria_ge",
    label: "Triage",
    hostnames: ["tria.ge"],
    resolveIOC: (url) => queryValue(url, "q")
  },
  {
    id: "ThreatFox",
    label: "ThreatFox",
    hostnames: ["threatfox.abuse.ch"],
    resolveIOC: threatFoxIOC
  },
  {
    id: "ViewDNS",
    label: "ViewDNS.info",
    hostnames: ["viewdns.info", "www.viewdns.info"],
    resolveIOC: viewDnsIOC
  },
  {
    id: "CiscoTalos",
    label: "Cisco Talos",
    hostnames: ["talosintelligence.com", "www.talosintelligence.com"],
    resolveIOC: (url) => queryValue(url, "search")
  },
  {
    id: "URLhaus",
    label: "URLhaus",
    hostnames: ["urlhaus.abuse.ch"],
    resolveIOC: (url) => queryValue(url, "search")
  },
  {
    id: "Spamhaus",
    label: "Spamhaus",
    hostnames: ["check.spamhaus.org"],
    resolveIOC: (url) => queryValue(url, "query")
  },
  {
    id: "RIPEstat",
    label: "RIPEstat",
    hostnames: ["stat.ripe.net"],
    resolveIOC: (url) => segmentAfter(url, "resource")
  },
  {
    id: "CloudflareRadar",
    label: "Cloudflare Radar",
    hostnames: ["radar.cloudflare.com"],
    resolveIOC: (url) => segmentAfter(url, "domain")
  },
  {
    id: "ThreatMiner",
    label: "ThreatMiner",
    hostnames: ["threatminer.org", "www.threatminer.org"],
    resolveIOC: (url) => queryValue(url, "q")
  },
  {
    id: "CTSearch",
    label: "Certificate Transparency",
    hostnames: ["crt.sh"],
    resolveIOC: (url) => queryValue(url, "q")
  },
  {
    id: "CIRCLHashlookup",
    label: "CIRCL Hashlookup",
    hostnames: ["hashlookup.circl.lu"],
    resolveIOC: circlIOC
  }
]

export const resolveServicePage = (
  value: string | URL
): ResolvedServicePage | null => {
  let url: URL
  try {
    url = value instanceof URL ? value : new URL(value)
  } catch {
    return null
  }

  const adapter = servicePageAdapters.find(({ hostnames }) =>
    hostnames.includes(url.hostname.toLowerCase())
  )
  if (!adapter) return null

  const ioc = adapter.resolveIOC(url)
  return ioc ? { adapter, ioc } : null
}
