import type { ResolvedServicePage } from "./servicePageAdapters"

export type ServiceIntelField = {
  label: string
  value: string
}

export type ServicePageParserSupport = {
  supported: boolean
  source: string
}

type QueryRoot = Document | ShadowRoot
type FieldAliases = Record<string, string[]>

const MAX_FIELDS = 48
const MAX_VALUE_LENGTH = 600

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

const readableText = (element: Element | null): string => {
  if (!element) return ""
  const htmlElement = element as HTMLElement
  return normalizeServiceText(
    element.getAttribute("data-tooltip-text") ||
      htmlElement.innerText ||
      htmlElement.textContent
  )
}

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

const createCollector = () => {
  const fields: ServiceIntelField[] = []
  const labels = new Set<string>()

  const add = (label: string, rawValue: string) => {
    if (fields.length >= MAX_FIELDS || labels.has(label.toLowerCase())) return
    const value = normalizeServiceText(rawValue).slice(0, MAX_VALUE_LENGTH)
    if (
      !label ||
      !value ||
      value.toLowerCase() === label.toLowerCase() ||
      /^(?:n\/?a|null|undefined|-+)$/i.test(value)
    ) {
      return
    }
    labels.add(label.toLowerCase())
    fields.push({ label, value })
  }

  return { fields, add }
}

const aliasLookup = (aliases: FieldAliases): Map<string, string> => {
  const lookup = new Map<string, string>()
  Object.entries(aliases).forEach(([canonical, candidates]) => {
    ;[canonical, ...candidates].forEach((candidate) => {
      lookup.set(normalizeLabel(candidate), canonical)
    })
  })
  return lookup
}

const addStrictTablePairs = (
  root: ParentNode,
  aliases: FieldAliases,
  add: (label: string, value: string) => void
): void => {
  const lookup = aliasLookup(aliases)
  root.querySelectorAll("tr").forEach((row) => {
    const cells = Array.from(row.querySelectorAll(":scope > th, :scope > td"))
    if (cells.length !== 2) return
    const canonical = lookup.get(normalizeLabel(readableText(cells[0])))
    if (canonical) add(canonical, readableText(cells[1]))
  })
}

const addMatrixTablePairs = (
  table: HTMLTableElement | null,
  aliases: FieldAliases,
  add: (label: string, value: string) => void
): void => {
  if (!table) return
  const lookup = aliasLookup(aliases)
  const rows = Array.from(table.querySelectorAll("tr"))
  rows.forEach((row, index) => {
    const headers = Array.from(row.querySelectorAll(":scope > th"))
    const values = Array.from(
      rows[index + 1]?.querySelectorAll(":scope > td") ?? []
    )
    if (headers.length < 1 || headers.length !== values.length) return
    headers.forEach((header, cellIndex) => {
      const canonical = lookup.get(normalizeLabel(readableText(header)))
      if (canonical) add(canonical, readableText(values[cellIndex]))
    })
  })
}

const exactHeading = (root: ParentNode, text: string): HTMLElement | null =>
  Array.from(root.querySelectorAll<HTMLElement>("h1,h2,h3,h4")).find(
    (heading) => readableText(heading) === text
  ) ?? null

const requireFields = (
  fields: ServiceIntelField[],
  minimum: number
): ServiceIntelField[] => (fields.length >= minimum ? fields : [])

const VT_ALIASES: FieldAliases = {
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
  const score = readableText(positives?.parentElement ?? null).match(
    /(\d+)\s*\/\s*(\d+)/
  )
  if (score) add("Verdict", `${score[1]} malicious / ${score[2]} vendors`)

  const card = queryAllDeep<HTMLElement>(
    roots,
    "vt-ui-ip-card,vt-ui-domain-card,vt-ui-url-card,vt-ui-file-card"
  )[0]
  if (card?.shadowRoot) {
    add(
      "Assessment",
      readableText(card.shadowRoot.querySelector(".card-header .fw-bold"))
    )
    const lastScan = card.shadowRoot.querySelector("vt-ui-time-ago")
    add(
      "Last scan",
      lastScan?.getAttribute("data-tooltip-text") || readableText(lastScan)
    )
  }

  const lookup = aliasLookup(VT_ALIASES)
  queryAllDeep<HTMLElement>(roots, ".label").forEach((labelElement) => {
    const canonical = lookup.get(normalizeLabel(readableText(labelElement)))
    const value = labelElement.parentElement?.nextElementSibling
    if (canonical && value) add(canonical, readableText(value))
  })
  return fields.some(({ label }) => label === "Verdict")
    ? requireFields(fields, 3)
    : []
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
  if (confidence) {
    add("Abuse score", confidence.includes("%") ? confidence : `${confidence}%`)
  }
  const reportText = readableText(reportRoot)
  const reportMatch =
    reportText.match(/reported\s+([\d,]+)\s+times?/i) ||
    reportText.match(/([\d,]+)\s+(?:abuse\s+)?reports?/i)
  if (reportMatch) add("Reports", reportMatch[1].replace(/,/g, ""))
  addStrictTablePairs(
    reportRoot,
    {
      ISP: ["ISP"],
      Usage: ["Usage Type", "Usage"],
      ASN: ["ASN"],
      Hostnames: ["Hostname(s)", "Hostnames"],
      Domain: ["Domain Name", "Domain"],
      Country: ["Country"],
      City: ["City"],
      "Last report": ["Last Reported At", "Last Report"],
      "Distinct reporters": ["Distinct Users", "Number of Distinct Users"]
    },
    add
  )
  return fields.some(({ label }) => label === "Abuse score")
    ? requireFields(fields, 4)
    : []
}

const parseIpQualityScore = (
  page: ResolvedServicePage,
  rootDocument: Document
): ServiceIntelField[] => {
  const root = rootDocument.querySelector("#lookupForm")?.parentElement
  if (!root || !readableText(root).includes(page.ioc)) return []
  const { fields, add } = createCollector()
  addMatrixTablePairs(
    root.querySelector<HTMLTableElement>(".lookup-section table"),
    {
      Country: ["Country"],
      City: ["City"],
      Region: ["Region"],
      VPN: ["VPN"],
      Proxy: ["PROXY"],
      ISP: ["ISP"],
      Organization: ["Organization"],
      Hostname: ["Hostname"],
      ASN: ["ASN"],
      TOR: ["TOR"]
    },
    add
  )
  const riskHeading = exactHeading(root, "Risk Summary")
  const riskText = readableText(
    riskHeading?.parentElement?.parentElement ?? null
  )
  const score = riskText.match(/^(\d+)\s+Risk Summary\s+(.+?)(?:\s+-|$)/i)
  if (score) {
    add("Fraud score", `${score[1]}/100`)
    add("Risk", score[2])
  }
  return requireFields(fields, 4)
}

const parseIpinfo = (
  page: ResolvedServicePage,
  rootDocument: Document
): ServiceIntelField[] => {
  const root = rootDocument.querySelector("main.flex-grow, main")
  if (!root || !readableText(root).includes(page.ioc)) return []
  const { fields, add } = createCollector()
  addStrictTablePairs(
    root,
    {
      Location: ["Location"],
      ASN: ["ASN"],
      Hostname: ["Hostname"],
      Range: ["Range"],
      Company: ["Company"],
      "Hosted domains": ["Hosted domains"],
      Privacy: ["Privacy"],
      Anycast: ["Anycast"],
      "AS type": ["AS Type"],
      "Abuse contact": ["Abuse contact"],
      City: ["City"],
      State: ["State"],
      Country: ["Country"],
      Postal: ["Postal"],
      Timezone: ["Timezone"],
      Coordinates: ["Coordinates"]
    },
    add
  )
  return requireFields(fields, 3)
}

const parseAlienVault = (
  page: ResolvedServicePage,
  rootDocument: Document
): ServiceIntelField[] => {
  const root = rootDocument.querySelector("otx-ip-summary")
  if (!root || !rootDocument.title.includes(page.ioc)) return []
  const { fields, add } = createCollector()
  const lookup = aliasLookup({
    Location: ["Location"],
    ASN: ["ASN"],
    "Related pulses": ["Related Pulses"]
  })
  root.querySelectorAll<HTMLElement>(".item").forEach((item) => {
    const canonical = lookup.get(
      normalizeLabel(readableText(item.querySelector(".title")))
    )
    const value = readableText(item.querySelector(".value"))
    if (canonical && !/^none$/i.test(value)) add(canonical, value)
  })
  return requireFields(fields, 2)
}

const parseIbmXForce = (
  page: ResolvedServicePage,
  rootDocument: Document
): ServiceIntelField[] => {
  const details = rootDocument.querySelector("h3.h3details + table.detailsline")
  const pageHeading = Array.from(
    rootDocument.querySelectorAll<HTMLElement>("h1,h2")
  ).find((heading) => readableText(heading).includes(page.ioc))
  if (!details || !pageHeading) return []
  const { fields, add } = createCollector()
  addStrictTablePairs(
    details,
    {
      Categorization: ["Categorization"],
      Application: ["Application"],
      Location: ["Location"],
      ASN: ["ASN"]
    },
    add
  )
  const whois = rootDocument.querySelector("#whois table.detailsline")
  if (whois) {
    addStrictTablePairs(
      whois,
      {
        Created: ["Created"],
        Updated: ["Updated"],
        Organization: ["Registrant Organization"],
        Country: ["Registrant Country or Region"],
        Email: ["Email"]
      },
      add
    )
  }
  return requireFields(fields, 2)
}

const parseMxToolbox = (
  page: ResolvedServicePage,
  rootDocument: Document
): ServiceIntelField[] => {
  const result = rootDocument.querySelector(
    ".tool-result-div.lookup-type-arin .tool-result-body"
  )
  const container = result?.closest(".tool-result-div.lookup-type-arin")
  if (!result || !readableText(container).includes(`arin:${page.ioc}`))
    return []
  const { fields, add } = createCollector()
  const lookup = aliasLookup({
    "Network range": ["NetRange"],
    CIDR: ["CIDR"],
    "Network name": ["NetName"],
    "Network type": ["NetType"],
    "Origin AS": ["OriginAS"],
    Organization: ["Organization", "OrgName"],
    Registered: ["RegDate"],
    Updated: ["Updated"],
    Country: ["Country"],
    City: ["City"],
    State: ["StateProv"],
    Postal: ["PostalCode"],
    "Abuse email": ["OrgAbuseEmail"]
  })
  const raw = (result as HTMLElement).innerText || result.textContent || ""
  raw.split(/\r?\n/).forEach((line) => {
    const match = line.match(/^\s*([^:#]{2,40})\s*:\s*(.+?)\s*$/)
    if (!match) return
    const canonical = lookup.get(normalizeLabel(match[1]))
    if (canonical) add(canonical, match[2])
  })
  return requireFields(fields, 4)
}

const parsePulsedive = (
  page: ResolvedServicePage,
  rootDocument: Document
): ServiceIntelField[] => {
  const root = rootDocument.querySelector("main")
  if (!root || !readableText(root.querySelector("h1")).startsWith(page.ioc)) {
    return []
  }
  const { fields, add } = createCollector()
  const risk = root.querySelector("[class*='fa-risk-']")?.closest("p")
  add("Risk", readableText(risk))

  const highlights = exactHeading(root, "Highlights")?.closest(".info")
  highlights?.querySelectorAll<HTMLElement>(".highlight").forEach((item) => {
    const descriptor = item.querySelector<HTMLElement>("[data-note]")
    const label = descriptor?.getAttribute("data-note") || "Location"
    add(label, readableText(descriptor ?? item))
  })

  const events = exactHeading(root, "Events")?.closest(".info")
  events?.querySelectorAll<HTMLElement>("p").forEach((item) => {
    const label = readableText(item.querySelector("label"))
    const stamp = item.querySelector<HTMLElement>(".stamp")
    const value = stamp?.getAttribute("data-utc") || readableText(stamp)
    if (label && value) add(label === "Seen" ? "Last seen" : label, value)
  })
  return requireFields(fields, 4)
}

const parseSpur = (
  page: ResolvedServicePage,
  rootDocument: Document
): ServiceIntelField[] => {
  const root = rootDocument.querySelector("main")
  if (!root || readableText(root.querySelector("h1")) !== page.ioc) return []
  const { fields, add } = createCollector()
  const aliases = aliasLookup({
    "Average devices": ["Average Devices Count"],
    Infrastructure: ["Infrastructure Type"],
    Behavior: ["IP Behavior"],
    Risks: ["Observed Risks"],
    ASN: ["ASN"],
    Organization: ["Registered To"],
    Location: ["Exit Location"]
  })
  root.querySelectorAll<HTMLElement>("p").forEach((labelElement) => {
    const canonical = aliases.get(normalizeLabel(readableText(labelElement)))
    if (!canonical) return
    let valueElement = labelElement.nextElementSibling
    while (valueElement?.matches("img"))
      valueElement = valueElement.nextElementSibling
    add(canonical, readableText(valueElement))
  })
  return requireFields(fields, 4)
}

const parseShodan = (
  page: ResolvedServicePage,
  rootDocument: Document
): ServiceIntelField[] => {
  const root = rootDocument.querySelector("#host")
  const general = root?.querySelector("#general + .grid-table")
  if (!root || !general || rootDocument.title.trim() !== page.ioc) return []
  const { fields, add } = createCollector()
  const lookup = aliasLookup({
    Hostnames: ["Hostnames"],
    Domains: ["Domains"],
    Country: ["Country"],
    City: ["City"],
    Organization: ["Organization"],
    ISP: ["ISP"],
    ASN: ["ASN"]
  })
  general.querySelectorAll<HTMLElement>(":scope > label").forEach((label) => {
    const canonical = lookup.get(normalizeLabel(readableText(label)))
    if (canonical) add(canonical, readableText(label.nextElementSibling))
  })
  const lastSeen = readableText(
    root.querySelector(".top-info .grid-heading")
  ).match(/Last Seen:\s*(.+)/i)
  if (lastSeen) add("Last seen", lastSeen[1])
  return requireFields(fields, 4)
}

const parseViewDns = (
  page: ResolvedServicePage,
  rootDocument: Document
): ServiceIntelField[] => {
  const root = rootDocument.querySelector("main")
  const resultHeading = Array.from(
    root?.querySelectorAll<HTMLElement>("h1,h2,h3") ?? []
  ).find((heading) => {
    const text = readableText(heading).toLowerCase()
    return text.includes("results for") && text.includes(page.ioc.toLowerCase())
  })
  const table =
    resultHeading?.parentElement?.querySelector("table") ??
    root?.querySelector("table")
  if (!root || !resultHeading || !table) return []
  const { fields, add } = createCollector()
  addStrictTablePairs(
    table,
    {
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
    },
    add
  )
  const rows = Array.from(table.querySelectorAll("tr"))
  const headers = Array.from(rows[0]?.querySelectorAll("th") ?? []).map(
    readableText
  )
  if (headers.length > 0) {
    headers.forEach((header, index) => {
      const values = rows
        .slice(1)
        .map((row) => readableText(row.querySelectorAll("td")[index] ?? null))
        .filter(Boolean)
      if (values.length > 0) {
        add(
          header === "HOSTNAME" ? "Reverse DNS" : header,
          values.slice(0, 5).join(", ")
        )
      }
    })
  }
  return requireFields(fields, 1)
}

const parseBgpToolkit = (
  page: ResolvedServicePage,
  rootDocument: Document
): ServiceIntelField[] => {
  const root = rootDocument.querySelector("#asinfo")
  const title = readableText(rootDocument.querySelector("h1"))
  if (!root || !title.toLowerCase().startsWith(page.ioc.toLowerCase()))
    return []
  const { fields, add } = createCollector()
  add("AS name", title.slice(page.ioc.length))
  const paired = aliasLookup({
    Website: ["Company Website"],
    "Looking glass": ["Looking Glass"],
    Country: ["Country of Origin"]
  })
  root.querySelectorAll<HTMLElement>(".asleft").forEach((label) => {
    const canonical = paired.get(normalizeLabel(readableText(label)))
    if (canonical && label.nextElementSibling?.matches(".asright")) {
      add(canonical, readableText(label.nextElementSibling))
    }
  })
  const stats = aliasLookup({
    "Internet exchanges": ["Internet Exchanges"],
    "Prefixes originated": ["Prefixes Originated (all)"],
    "Prefixes announced": ["Prefixes Announced (all)"],
    "RPKI valid": ["RPKI Originated Valid (all)"],
    "RPKI invalid": ["RPKI Originated Invalid (all)"],
    "BGP peers": ["BGP Peers Observed (all)"],
    "IPv4 addresses": ["IPs Originated (v4)"],
    "Average AS path": ["Average AS Path Length (all)"]
  })
  const raw = (root as HTMLElement).innerText || root.textContent || ""
  raw.split(/\r?\n/).forEach((line) => {
    const match = line.match(/^\s*([^:]+):\s*(.+?)\s*$/)
    if (!match) return
    const canonical = stats.get(normalizeLabel(match[1]))
    if (canonical) add(canonical, match[2])
  })
  return requireFields(fields, 4)
}

const parseRipeStat = (
  page: ResolvedServicePage,
  rootDocument: Document
): ServiceIntelField[] => {
  const root = rootDocument.querySelector("#resource-tabs")
  if (!root || !rootDocument.title.includes(page.ioc)) return []
  const { fields, add } = createCollector()
  const text = readableText(root)
  const status = text.match(/At (.+? UTC),\s+([^ ]+) was ([^.]+)\./i)
  if (status) {
    add("Observed at", status[1])
    add("Prefix", status[2])
    add("Visibility", status[3])
  }
  const firstSeen = text.match(
    /First ever seen announced by (AS\d+), on (.+? UTC)\./i
  )
  if (firstSeen) {
    add("First origin", firstSeen[1])
    add("First seen", firstSeen[2])
  }
  const origin = text.match(/Originated by:\s*(AS\d+)/i)
  if (origin) add("Origin", origin[1])
  const rpki = text.match(/RPKI Status:\s*(.*?)\s+Route object:/i)
  if (rpki?.[1]) add("RPKI", rpki[1])
  const routeObject = text.match(/Route object:\s*([^ ]+)/i)
  if (routeObject) add("Route object", routeObject[1])
  return requireFields(fields, 4)
}

const parseCloudflareRadar = (
  page: ResolvedServicePage,
  rootDocument: Document
): ServiceIntelField[] => {
  const root = rootDocument.querySelector("main")
  const heading = root?.querySelector("h1")
  if (!root || !readableText(heading).includes(page.ioc)) return []
  const { fields, add } = createCollector()
  const articles = Array.from(root.querySelectorAll("article"))
  const whois = articles.find(
    (article) => readableText(article.querySelector("h2")) === "WHOIS"
  )
  if (whois) {
    addStrictTablePairs(whois, {}, add)
    const lookup = aliasLookup({
      Created: ["Created"],
      Updated: ["Updated"],
      Expires: ["Expires"],
      Registrar: ["Registrar"],
      Nameservers: ["Nameservers"],
      "EPP status": ["EPP Status Codes"]
    })
    whois.querySelectorAll("dl .group").forEach((group) => {
      const canonical = lookup.get(
        normalizeLabel(readableText(group.querySelector("dt")))
      )
      if (canonical) add(canonical, readableText(group.querySelector("dd")))
    })
  }
  const dns = articles.find(
    (article) => readableText(article.querySelector("h2")) === "DNS records"
  )
  const dnsValues = new Map<string, string[]>()
  dns?.querySelectorAll("tbody tr").forEach((row) => {
    const cells = Array.from(row.querySelectorAll("td")).map(readableText)
    if (cells.length < 3 || !cells[0] || !cells[2]) return
    const values = dnsValues.get(cells[0]) ?? []
    if (!values.includes(cells[2]) && values.length < 5) values.push(cells[2])
    dnsValues.set(cells[0], values)
  })
  dnsValues.forEach((values, type) => add(`DNS ${type}`, values.join(", ")))
  return requireFields(fields, 3)
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

const readJsonDocument = (rootDocument: Document): unknown => {
  const raw = (
    rootDocument.body?.innerText ||
    rootDocument.body?.textContent ||
    ""
  ).trim()
  if (!(raw.startsWith("{") || raw.startsWith("["))) return null
  try {
    return JSON.parse(raw)
  } catch {
    return null
  }
}

const parseCirclHashlookup = (rootDocument: Document): ServiceIntelField[] => {
  const payload = readJsonDocument(rootDocument)
  if (!payload || Array.isArray(payload) || typeof payload !== "object")
    return []
  const data = payload as Record<string, unknown>
  const { fields, add } = createCollector()
  const scalarValues: Array<[string, string[]]> = [
    ["Trust level", ["hashlookup:trust", "trust"]],
    ["SHA1", ["SHA-1", "sha1"]],
    ["MD5", ["MD5", "md5"]],
    ["SHA256", ["SHA-256", "sha256"]],
    ["File name", ["FileName", "file_name"]],
    ["File size", ["FileSize", "file_size"]],
    ["Known malicious", ["KnownMalicious"]],
    ["MIME type", ["mimetype"]],
    ["Database", ["db"]],
    ["Source", ["source"]],
    ["Parent count", ["hashlookup:parent-total"]]
  ]
  scalarValues.forEach(([label, keys]) => {
    const key = keys.find((candidate) =>
      ["string", "number", "boolean"].includes(typeof data[candidate])
    )
    if (key) add(label, String(data[key]))
  })
  const product = data.ProductCode
  if (product && typeof product === "object" && !Array.isArray(product)) {
    add(
      "Product",
      String((product as Record<string, unknown>).ProductName ?? "")
    )
  }
  return requireFields(fields, 2)
}

const unsupported = (): ServiceIntelField[] => []

const parsers: Record<
  string,
  (page: ResolvedServicePage, rootDocument: Document) => ServiceIntelField[]
> = {
  VirusTotal: (_page, rootDocument) => parseVirusTotal(rootDocument),
  AbuseIPDB: parseAbuseIpdb,
  Censys: unsupported,
  IPQualityScore: parseIpQualityScore,
  IPinfo: parseIpinfo,
  AlienVault: parseAlienVault,
  IBMXForce: parseIbmXForce,
  MxToolbox: parseMxToolbox,
  Pulsedive: parsePulsedive,
  Spur: parseSpur,
  PassiveDNS: unsupported,
  Hunter: unsupported,
  Shodan: parseShodan,
  SecurityTrails: unsupported,
  UrlScan: unsupported,
  HaveIBeenPwned: unsupported,
  MACVendors: (_page, rootDocument) => parseMacVendor(rootDocument),
  WiresharkOUI: unsupported,
  GreyNoise: unsupported,
  MalwareBazaar: unsupported,
  Robtex: unsupported,
  BGPToolkit: parseBgpToolkit,
  Tria_ge: unsupported,
  ThreatFox: unsupported,
  ViewDNS: parseViewDns,
  CiscoTalos: unsupported,
  URLhaus: unsupported,
  Spamhaus: unsupported,
  RIPEstat: parseRipeStat,
  CloudflareRadar: parseCloudflareRadar,
  ThreatMiner: unsupported,
  CTSearch: unsupported,
  CIRCLHashlookup: (_page, rootDocument) => parseCirclHashlookup(rootDocument)
}

export const servicePageParserSupport: Record<
  string,
  ServicePageParserSupport
> = {
  VirusTotal: { supported: true, source: "score card and key/value widgets" },
  AbuseIPDB: { supported: true, source: "IP report well" },
  Censys: {
    supported: false,
    source: "redirects to the authenticated platform"
  },
  IPQualityScore: { supported: true, source: "lookup result card" },
  IPinfo: { supported: true, source: "summary and geolocation tables" },
  AlienVault: { supported: true, source: "OTX IP summary component" },
  IBMXForce: { supported: true, source: "Details and WHOIS tables" },
  MxToolbox: { supported: true, source: "ARIN result transcript" },
  Pulsedive: { supported: true, source: "Highlights and Events blocks" },
  Spur: { supported: true, source: "IP Context result fields" },
  PassiveDNS: { supported: false, source: "no stable public result DOM" },
  Hunter: { supported: false, source: "result requires an authenticated flow" },
  Shodan: { supported: true, source: "host General Information grid" },
  SecurityTrails: {
    supported: false,
    source: "record rows lack stable value hooks"
  },
  UrlScan: { supported: false, source: "aggregate search results" },
  HaveIBeenPwned: {
    supported: false,
    source: "unified search endpoint requires authorization"
  },
  MACVendors: { supported: true, source: "vendor text response" },
  WiresharkOUI: {
    supported: false,
    source: "lookup URL does not expose a result"
  },
  GreyNoise: {
    supported: false,
    source: "public page did not expose result data"
  },
  MalwareBazaar: { supported: false, source: "anti-bot interstitial" },
  Robtex: { supported: false, source: "public result could not be loaded" },
  BGPToolkit: { supported: true, source: "AS Info panel" },
  Tria_ge: { supported: false, source: "aggregate search results" },
  ThreatFox: { supported: false, source: "anti-bot interstitial" },
  ViewDNS: { supported: true, source: "result table" },
  CiscoTalos: { supported: false, source: "public result could not be loaded" },
  URLhaus: { supported: false, source: "anti-bot interstitial" },
  Spamhaus: { supported: false, source: "anti-bot interstitial" },
  RIPEstat: { supported: true, source: "Routing Status widget" },
  CloudflareRadar: { supported: true, source: "WHOIS and DNS widgets" },
  ThreatMiner: { supported: false, source: "public result timed out" },
  CTSearch: { supported: false, source: "public result timed out" },
  CIRCLHashlookup: { supported: true, source: "hashlookup JSON response" }
}

export const parseServicePage = (
  page: ResolvedServicePage,
  rootDocument: Document = document
): ServiceIntelField[] => parsers[page.adapter.id]?.(page, rootDocument) ?? []

export const parserProviderIds = new Set(Object.keys(parsers))
