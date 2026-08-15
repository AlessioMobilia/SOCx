import type { ResolvedServicePage } from "./servicePageAdapters"

export type ServiceIntelField = {
  label: string
  value: string
}

type QueryRoot = Document | ShadowRoot
type AliasMap = Record<string, string[]>
type ParserSpec = {
  aliases: AliasMap
  minimumFields?: number
  rawJson?: boolean
}

const MAX_FIELDS = 48
const MAX_VALUE_LENGTH = 600
const EXCLUDED_SELECTOR = [
  "nav",
  "header",
  "footer",
  "aside",
  "script",
  "style",
  "noscript",
  "template",
  "[role='dialog']",
  "[aria-hidden='true']",
  "[data-socx-service-copy]"
].join(",")

export const normalizeServiceText = (
  value: string | null | undefined
): string =>
  (value ?? "")
    .replace(/\u00a0/g, " ")
    .replace(/\s+/g, " ")
    .trim()

const normalizeLabel = (value: string): string =>
  normalizeServiceText(value)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim()

const collectOpenRoots = (rootDocument: Document): QueryRoot[] => {
  const roots: QueryRoot[] = [rootDocument]
  for (let index = 0; index < roots.length && roots.length < 150; index += 1) {
    roots[index].querySelectorAll("*").forEach((element) => {
      if (element.shadowRoot && !roots.includes(element.shadowRoot)) {
        roots.push(element.shadowRoot)
      }
    })
  }
  return roots
}

const queryAllDeep = <T extends Element>(
  roots: QueryRoot[],
  selector: string
): T[] =>
  roots.flatMap((root) => Array.from(root.querySelectorAll<T>(selector)))

const readableText = (element: Element | null): string => {
  if (!element) return ""
  const htmlElement = element as HTMLElement
  return normalizeServiceText(
    element.getAttribute("data-tooltip-text") ||
      htmlElement.innerText ||
      htmlElement.textContent
  )
}

const isExcluded = (element: Element): boolean =>
  element.matches(EXCLUDED_SELECTOR) ||
  Boolean(element.closest(EXCLUDED_SELECTOR))

const createCollector = () => {
  const fields: ServiceIntelField[] = []
  const seen = new Set<string>()

  const add = (label: string, rawValue: string) => {
    if (fields.length >= MAX_FIELDS) return
    const value = normalizeServiceText(rawValue).slice(0, MAX_VALUE_LENGTH)
    if (
      !label ||
      !value ||
      value === label ||
      /^(?:n\/?a|none|null|undefined|-+)$/i.test(value)
    ) {
      return
    }
    const key = `${label.toLowerCase()}\u0000${value.toLowerCase()}`
    if (seen.has(key)) return
    seen.add(key)
    fields.push({ label, value })
  }

  return { fields, add }
}

const aliasLookup = (aliases: AliasMap): Map<string, string> => {
  const lookup = new Map<string, string>()
  Object.entries(aliases).forEach(([canonical, candidates]) => {
    ;[canonical, ...candidates].forEach((candidate) =>
      lookup.set(normalizeLabel(candidate), canonical)
    )
  })
  return lookup
}

const findSiblingValue = (labelElement: Element): string => {
  let current: Element | null = labelElement
  for (let depth = 0; current && depth < 2; depth += 1) {
    const sibling = current.nextElementSibling
    const value = readableText(sibling)
    if (
      value &&
      value.length <= MAX_VALUE_LENGTH &&
      value !== readableText(labelElement)
    ) {
      return value
    }
    current = current.parentElement
  }
  return ""
}

const extractAllowedPairs = (
  roots: QueryRoot[],
  aliases: AliasMap,
  add: (label: string, value: string) => void
): void => {
  const lookup = aliasLookup(aliases)

  queryAllDeep<HTMLTableRowElement>(roots, "tr")
    .slice(0, 250)
    .forEach((row) => {
      if (isExcluded(row)) return
      const cells = Array.from(row.querySelectorAll("th,td"))
      if (cells.length === 2 && !cells.every((cell) => cell.matches("th"))) {
        const canonical = lookup.get(normalizeLabel(readableText(cells[0])))
        if (canonical) add(canonical, readableText(cells[1]))
      }
    })

  queryAllDeep<HTMLTableElement>(roots, "table")
    .slice(0, 20)
    .forEach((table) => {
      if (isExcluded(table)) return
      const rows = Array.from(table.querySelectorAll("tr")).slice(0, 80)
      const headers = Array.from(rows[0]?.querySelectorAll("th") ?? []).map(
        readableText
      )
      if (headers.length < 2) return
      rows.slice(1).forEach((row) => {
        const values = Array.from(row.querySelectorAll("th,td")).map(
          readableText
        )
        headers.forEach((header, index) => {
          const canonical = lookup.get(normalizeLabel(header))
          if (canonical && values[index]) add(canonical, values[index])
        })
      })
    })

  queryAllDeep<HTMLElement>(roots, "dt").forEach((term) => {
    if (isExcluded(term)) return
    const canonical = lookup.get(normalizeLabel(readableText(term)))
    if (canonical && term.nextElementSibling?.matches("dd")) {
      add(canonical, readableText(term.nextElementSibling))
    }
  })

  queryAllDeep<HTMLElement>(
    roots,
    "[class*='label'],[class*='key'],[data-testid*='label'],th,strong,b,dt"
  )
    .slice(0, 1_000)
    .forEach((labelElement) => {
      if (isExcluded(labelElement)) return
      const canonical = lookup.get(normalizeLabel(readableText(labelElement)))
      if (!canonical) return
      add(canonical, findSiblingValue(labelElement))
    })

  queryAllDeep<HTMLElement>(
    roots,
    "main,[role='main'],article,#content,.content"
  )
    .slice(0, 20)
    .forEach((root) => {
      if (isExcluded(root)) return
      const rawText = root.innerText || root.textContent || ""
      rawText.split(/\r?\n/).forEach((line) => {
        const match = normalizeServiceText(line).match(/^([^:]{2,80}):\s+(.+)$/)
        if (!match) return
        const canonical = lookup.get(normalizeLabel(match[1]))
        if (canonical) add(canonical, match[2])
      })
    })
}

const extractAllowedJson = (
  rootDocument: Document,
  aliases: AliasMap,
  add: (label: string, value: string) => void
): void => {
  const raw = (
    rootDocument.body?.innerText ||
    rootDocument.body?.textContent ||
    ""
  ).trim()
  if (!(raw.startsWith("{") || raw.startsWith("["))) return

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return
  }

  const lookup = aliasLookup(aliases)
  const visit = (value: unknown, depth = 0): void => {
    if (depth > 5 || !value || typeof value !== "object") return
    if (Array.isArray(value)) {
      value.slice(0, 12).forEach((item) => visit(item, depth + 1))
      return
    }
    Object.entries(value as Record<string, unknown>).forEach(([key, item]) => {
      const canonical = lookup.get(normalizeLabel(key))
      if (canonical) {
        if (Array.isArray(item)) {
          const values = item
            .filter((entry) =>
              ["string", "number", "boolean"].includes(typeof entry)
            )
            .slice(0, 8)
            .join(", ")
          if (values) add(canonical, values)
        } else if (["string", "number", "boolean"].includes(typeof item)) {
          add(canonical, String(item))
        }
      }
      visit(item, depth + 1)
    })
  }
  visit(parsed)
}

const parseWithSpec = (
  rootDocument: Document,
  spec: ParserSpec
): ServiceIntelField[] => {
  const roots = collectOpenRoots(rootDocument)
  const { fields, add } = createCollector()
  extractAllowedPairs(roots, spec.aliases, add)
  if (spec.rawJson) extractAllowedJson(rootDocument, spec.aliases, add)
  return fields.length >= (spec.minimumFields ?? 2) ? fields : []
}

const VT_ALIASES: AliasMap = {
  Network: ["Network"],
  ASN: ["Autonomous System Number", "ASN"],
  "AS owner": ["Autonomous System Label", "AS Owner"],
  RIR: ["Regional Internet Registry", "RIR"],
  Country: ["Country"],
  Continent: ["Continent"],
  Registrar: ["Registrar"],
  Registered: ["Creation Date", "Created"],
  Updated: ["Last Modification Date", "Updated"],
  "File type": ["File type", "Type Description", "Magic"],
  Size: ["File size", "Size"],
  MD5: ["MD5"],
  SHA1: ["SHA-1", "SHA1"],
  SHA256: ["SHA-256", "SHA256"],
  "First seen": ["First Submission", "First Seen In The Wild"],
  "Last submission": ["Last Submission"],
  "Certificate subject": ["Subject CN", "Subject"],
  "Certificate issuer": ["Issuer CN", "Issuer"],
  "Certificate valid from": ["Valid From", "Not Before"],
  "Certificate valid until": ["Valid Until", "Not After"]
}

const parseVirusTotal = (rootDocument: Document): ServiceIntelField[] => {
  const roots = collectOpenRoots(rootDocument)
  const { fields, add } = createCollector()
  const positives = queryAllDeep<HTMLElement>(roots, "#positives")[0]
  if (positives) {
    const scoreText = readableText(positives.parentElement)
    const score = scoreText.match(/(\d+)\s*\/\s*(\d+)/)
    if (score) add("Verdict", `${score[1]} malicious / ${score[2]} vendors`)
  }

  const card = queryAllDeep<HTMLElement>(
    roots,
    "vt-ui-ip-card,vt-ui-domain-card,vt-ui-url-card,vt-ui-file-card"
  )[0]
  if (card?.shadowRoot) {
    const assessment = readableText(
      card.shadowRoot.querySelector(".card-header .fw-bold")
    )
    if (assessment) add("Assessment", assessment)
    const lastScan = card.shadowRoot.querySelector("vt-ui-time-ago")
    if (lastScan) {
      add(
        "Last scan",
        lastScan.getAttribute("data-tooltip-text") || readableText(lastScan)
      )
    }
  }

  extractAllowedPairs(roots, VT_ALIASES, add)
  return fields.some(({ label }) => label === "Verdict") && fields.length >= 3
    ? fields
    : []
}

const ABUSE_ALIASES: AliasMap = {
  ISP: ["ISP"],
  Usage: ["Usage Type", "Usage"],
  ASN: ["ASN"],
  Hostnames: ["Hostname(s)", "Hostnames"],
  Domain: ["Domain Name", "Domain"],
  Country: ["Country"],
  City: ["City"],
  "Last report": ["Last Reported At", "Last Report"],
  "Distinct reporters": ["Distinct Users", "Number of Distinct Users"]
}

const parseAbuseIpdb = (
  page: ResolvedServicePage,
  rootDocument: Document
): ServiceIntelField[] => {
  const reportRoot = rootDocument.querySelector(".col-md-6 .well")
  const displayedIp = readableText(reportRoot?.querySelector("h3 > b") ?? null)
  if (!reportRoot || displayedIp.toLowerCase() !== page.ioc.toLowerCase()) {
    return []
  }

  const { fields, add } = createCollector()
  add("IP", displayedIp)
  const progress = reportRoot.querySelector<HTMLElement>(".progress-bar")
  const confidence =
    progress?.getAttribute("aria-valuenow") ||
    readableText(progress?.querySelector("span") ?? null)
  if (confidence)
    add("Abuse score", confidence.includes("%") ? confidence : `${confidence}%`)

  const reportText = readableText(reportRoot)
  const reportMatch =
    reportText.match(/reported\s+([\d,]+)\s+times?/i) ||
    reportText.match(/([\d,]+)\s+(?:abuse\s+)?reports?/i)
  if (reportMatch) add("Reports", reportMatch[1].replace(/,/g, ""))

  extractAllowedPairs([rootDocument], ABUSE_ALIASES, add)
  return fields.length >= 4 &&
    fields.some(({ label }) => label === "Abuse score")
    ? fields
    : []
}

const parseMacVendor = (rootDocument: Document): ServiceIntelField[] => {
  const value = normalizeServiceText(
    rootDocument.body?.innerText || rootDocument.body?.textContent
  )
  return value.length >= 2 &&
    value.length <= 200 &&
    !/error|limit|denied|forbidden/i.test(value)
    ? [{ label: "Vendor", value }]
    : []
}

const specs: Record<string, ParserSpec> = {
  Censys: {
    aliases: {
      IP: ["IP Address"],
      Location: ["Location"],
      ASN: ["ASN"],
      Organization: ["Organization"],
      "Operating system": ["Operating System"],
      Services: ["Services", "Protocols"],
      Hostnames: ["Hostnames", "DNS Names"],
      "Last updated": ["Last Updated", "Observed At"]
    }
  },
  IPQualityScore: {
    aliases: {
      "Fraud score": ["Fraud Score"],
      Proxy: ["Proxy"],
      VPN: ["VPN"],
      TOR: ["TOR"],
      Bot: ["Bot"],
      Country: ["Country"],
      City: ["City"],
      ISP: ["ISP"],
      ASN: ["ASN"],
      Organization: ["Organization"],
      Hostname: ["Hostname"]
    }
  },
  IPinfo: {
    aliases: {
      IP: ["IP"],
      Hostname: ["Hostname"],
      City: ["City"],
      Region: ["Region"],
      Country: ["Country"],
      Location: ["Location", "Loc"],
      Organization: ["Organization", "Org"],
      Postal: ["Postal"],
      Timezone: ["Timezone"],
      ASN: ["ASN"]
    }
  },
  AlienVault: {
    aliases: {
      Reputation: ["Reputation"],
      Pulses: ["Pulse Count", "Pulses"],
      Country: ["Country"],
      ASN: ["ASN"],
      City: ["City"],
      Malware: ["Malware"],
      "Passive DNS": ["Passive DNS"],
      WHOIS: ["WHOIS"]
    }
  },
  IBMXForce: {
    aliases: {
      "Risk score": ["Risk Score"],
      Reputation: ["Reputation"],
      Country: ["Country"],
      Categories: ["Categories", "Category"],
      Registrar: ["Registrar"],
      DNS: ["DNS"],
      WHOIS: ["WHOIS"]
    }
  },
  MxToolbox: {
    aliases: {
      Status: ["Status"],
      Result: ["Result"],
      IP: ["IP Address"],
      Domain: ["Domain Name"],
      ASN: ["ASN"],
      Blacklists: ["Blacklists"],
      DNS: ["DNS"],
      Location: ["Location"]
    }
  },
  Pulsedive: {
    aliases: {
      Risk: ["Risk"],
      Threats: ["Threats"],
      Feeds: ["Feeds"],
      "First seen": ["First Seen"],
      "Last seen": ["Last Seen"],
      DNS: ["DNS"],
      Ports: ["Ports"],
      Properties: ["Properties"]
    }
  },
  Spur: {
    aliases: {
      IP: ["IP"],
      Country: ["Country"],
      Organization: ["Organization"],
      ASN: ["ASN"],
      Infrastructure: ["Infrastructure"],
      Services: ["Services"],
      Risks: ["Risks"],
      VPN: ["VPN"],
      Proxy: ["Proxy"]
    }
  },
  PassiveDNS: {
    aliases: {
      Query: ["Query"],
      Type: ["RRtype", "Type"],
      Name: ["RRname", "Name"],
      Value: ["Rdata", "Value"],
      "First seen": ["First Seen"],
      "Last seen": ["Last Seen"],
      Count: ["Count"]
    }
  },
  Hunter: {
    aliases: {
      Email: ["Email"],
      Status: ["Status", "Result"],
      Score: ["Score"],
      Disposable: ["Disposable"],
      Webmail: ["Webmail"],
      MX: ["MX Records"],
      SMTP: ["SMTP"],
      Sources: ["Sources"]
    }
  },
  Shodan: {
    aliases: {
      IP: ["IP Address"],
      Organization: ["Organization"],
      ISP: ["ISP"],
      ASN: ["ASN"],
      Country: ["Country"],
      City: ["City"],
      Hostnames: ["Hostnames"],
      Domains: ["Domains"],
      Ports: ["Ports"],
      "Operating system": ["Operating System"],
      Vulnerabilities: ["Vulnerabilities", "Vulns"]
    }
  },
  SecurityTrails: {
    aliases: {
      Domain: ["Domain"],
      Rank: ["Alexa Rank"],
      Registrar: ["Registrar"],
      Created: ["Created Date", "Created"],
      Updated: ["Updated Date", "Updated"],
      Expires: ["Expires Date", "Expires"],
      Nameservers: ["Nameservers"],
      A: ["A"],
      AAAA: ["AAAA"],
      MX: ["MX"],
      NS: ["NS"]
    }
  },
  UrlScan: {
    aliases: {
      Verdict: ["Verdict"],
      Score: ["Score"],
      URL: ["URL"],
      Domain: ["Domain"],
      IP: ["IP"],
      ASN: ["ASN"],
      Country: ["Country"],
      Server: ["Server"],
      Status: ["Status"],
      Submitted: ["Submitted"],
      "Scan ID": ["Scan ID", "UUID"]
    }
  },
  HaveIBeenPwned: {
    rawJson: true,
    aliases: {
      Breach: ["Name", "Title"],
      Domain: ["Domain"],
      "Breach date": ["BreachDate"],
      "Added date": ["AddedDate"],
      Accounts: ["PwnCount"],
      "Data classes": ["DataClasses"],
      Verified: ["IsVerified"],
      Sensitive: ["IsSensitive"]
    }
  },
  WiresharkOUI: {
    aliases: {
      OUI: ["OUI", "Prefix"],
      Vendor: ["Vendor", "Company"],
      Address: ["Address"]
    }
  },
  GreyNoise: {
    aliases: {
      Classification: ["Classification"],
      Name: ["Name"],
      Actor: ["Actor"],
      "First seen": ["First Seen"],
      "Last seen": ["Last Seen"],
      Tags: ["Tags"],
      VPN: ["VPN"],
      Bot: ["Bot"],
      RIOT: ["RIOT"],
      Noise: ["Noise"]
    }
  },
  MalwareBazaar: {
    aliases: {
      SHA256: ["SHA256 hash", "SHA256"],
      SHA1: ["SHA1 hash", "SHA1"],
      MD5: ["MD5 hash", "MD5"],
      "File name": ["File name"],
      "File type": ["File type"],
      "File size": ["File size"],
      Signature: ["Signature"],
      Tags: ["Tags"],
      "First seen": ["First seen"],
      "Last seen": ["Last seen"],
      Reporter: ["Reporter"],
      Delivery: ["Delivery method"]
    }
  },
  Robtex: {
    aliases: {
      IP: ["IP"],
      City: ["City"],
      Country: ["Country"],
      ASN: ["ASN"],
      "AS name": ["AS Name"],
      Route: ["Route"],
      Reverse: ["Reverse"],
      Domains: ["Domains"],
      Nameservers: ["Name Servers"],
      "Mail servers": ["Mail Servers"]
    }
  },
  BGPToolkit: {
    aliases: {
      Prefix: ["Prefix"],
      Description: ["Description"],
      Country: ["Country"],
      "Origin AS": ["Origin AS"],
      "AS name": ["AS Name"],
      RPKI: ["RPKI", "RPKI Status"],
      Announced: ["Announced"]
    }
  },
  Tria_ge: {
    aliases: {
      Verdict: ["Verdict"],
      Score: ["Score"],
      Family: ["Family"],
      Tags: ["Tags"],
      Submitted: ["Submitted"],
      Completed: ["Completed"],
      SHA256: ["SHA256"],
      MD5: ["MD5"],
      "File name": ["File Name"]
    }
  },
  ThreatFox: {
    aliases: {
      IOC: ["IOC"],
      "Threat type": ["Threat Type"],
      Malware: ["Malware"],
      Confidence: ["Confidence Level", "Confidence"],
      "First seen": ["First Seen"],
      "Last seen": ["Last Seen"],
      Reporter: ["Reporter"],
      Tags: ["Tags"]
    }
  },
  ViewDNS: {
    aliases: {
      Domain: ["Domain Name"],
      IP: ["IP Address"],
      Registrar: ["Registrar"],
      Created: ["Creation Date"],
      Expires: ["Expiration Date"],
      Nameserver: ["Name Server"],
      "Reverse DNS": ["Reverse DNS"],
      ASN: ["ASN"],
      "AS name": ["AS Name"],
      Country: ["Country"]
    }
  },
  CiscoTalos: {
    aliases: {
      "Web reputation": ["Web Reputation"],
      "Email reputation": ["Email Reputation"],
      Reputation: ["Reputation"],
      Category: ["Category"],
      Owner: ["Owner", "Network Owner"],
      Country: ["Country"],
      Hostname: ["Hostname"],
      Domain: ["Domain"],
      IP: ["IP Address"]
    }
  },
  URLhaus: {
    aliases: {
      ID: ["ID"],
      URL: ["URL"],
      Status: ["URL Status", "Status"],
      Host: ["Host"],
      "Date added": ["Date added"],
      Threat: ["Threat"],
      Blocklist: ["URLhaus blocklist"],
      "Spamhaus DBL": ["Spamhaus DBL"],
      SURBL: ["SURBL"],
      Reporter: ["Reporter"],
      Tags: ["Tags"],
      SHA256: ["Payload (SHA256)", "SHA256"],
      Filename: ["Filename"],
      "File type": ["File Type"]
    }
  },
  Spamhaus: {
    aliases: {
      IP: ["IP"],
      Domain: ["Domain"],
      Status: ["Status"],
      Listing: ["Listing"],
      Blocklist: ["Blocklist"],
      Record: ["Record"],
      "Reverse DNS": ["Reverse DNS"],
      Country: ["Country"],
      ASN: ["ASN"]
    }
  },
  RIPEstat: {
    aliases: {
      Prefix: ["Prefix"],
      ASN: ["ASN"],
      "AS name": ["AS Name"],
      Country: ["Country"],
      RPKI: ["RPKI Status"],
      Routing: ["Routing Status"],
      Visibility: ["Visibility"],
      "First seen": ["First Seen"],
      "Announced by": ["Announced By", "Originated By"],
      "Abuse contact": ["Abuse Contact"],
      "Reverse DNS": ["Reverse DNS Hostname"],
      Registry: ["RIR"]
    }
  },
  CloudflareRadar: {
    aliases: {
      Categories: ["Categories"],
      Ranking: ["Ranking"],
      Security: ["Security"],
      TLD: ["TLD"],
      ASN: ["AS", "Autonomous System"],
      Created: ["Created"],
      Updated: ["Updated"],
      Expires: ["Expires"],
      Registrar: ["Registrar"],
      Nameservers: ["Nameservers"],
      Type: ["Type"],
      Name: ["Name"],
      Content: ["Content"]
    }
  },
  ThreatMiner: {
    aliases: {
      Domain: ["Domain"],
      IP: ["IP"],
      Registrar: ["Registrar"],
      Registrant: ["Registrant"],
      "First seen": ["First Seen"],
      "Last seen": ["Last Seen"],
      "Passive DNS": ["Passive DNS"],
      Subdomains: ["Subdomains"],
      Samples: ["Related Samples"],
      Certificates: ["SSL Certificates"]
    }
  },
  CTSearch: {
    aliases: {
      "Issuer name": ["Issuer Name"],
      "Common name": ["Common Name"],
      Names: ["Name Value"],
      ID: ["ID"],
      "Entry timestamp": ["Entry Timestamp"],
      "Not before": ["Not Before"],
      "Not after": ["Not After"],
      Serial: ["Serial Number"]
    }
  },
  CIRCLHashlookup: {
    rawJson: true,
    aliases: {
      "Trust level": ["hashlookup:trust", "trust"],
      SHA1: ["SHA-1", "sha1"],
      MD5: ["MD5", "md5"],
      SHA256: ["SHA-256", "sha256"],
      "File name": ["FileName", "file_name"],
      "File size": ["FileSize", "file_size"],
      Product: ["ProductCode", "product"],
      Package: ["PackageName", "package"],
      Source: ["source"]
    }
  }
}

export const parseServicePage = (
  page: ResolvedServicePage,
  rootDocument: Document = document
): ServiceIntelField[] => {
  if (page.adapter.id === "VirusTotal") return parseVirusTotal(rootDocument)
  if (page.adapter.id === "AbuseIPDB") return parseAbuseIpdb(page, rootDocument)
  if (page.adapter.id === "MACVendors") return parseMacVendor(rootDocument)
  const spec = specs[page.adapter.id]
  return spec ? parseWithSpec(rootDocument, spec) : []
}

export const parserProviderIds = new Set([
  "VirusTotal",
  "AbuseIPDB",
  "MACVendors",
  ...Object.keys(specs)
])
