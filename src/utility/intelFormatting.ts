export type IntelTone = "danger" | "warning" | "success" | "neutral"

export type IntelField = {
  label: string
  value: string
  tone?: IntelTone
}

export type IntelSection = {
  title: string
  fields: IntelField[]
}

export type IntelSummary = {
  title: string
  sections: IntelSection[]
}

const clean = (value: unknown): string =>
  value === null || value === undefined
    ? ""
    : String(value).replace(/\s+/g, " ").trim()

const asNumber = (value: unknown): number => {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : 0
}

const formatDate = (value: unknown): string => {
  if (value === null || value === undefined || value === "") return ""
  const compactDate = clean(value).match(/^(\d{4})(\d{2})(\d{2})$/)
  if (compactDate)
    return `${compactDate[1]}-${compactDate[2]}-${compactDate[3]}`
  const numeric = Number(value)
  const date =
    Number.isFinite(numeric) && numeric > 0 && clean(value).length <= 13
      ? new Date(numeric > 10_000_000_000 ? numeric : numeric * 1000)
      : new Date(String(value))
  return Number.isNaN(date.getTime())
    ? clean(value)
    : date.toISOString().split("T")[0]
}

const formatBytes = (value: unknown): string => {
  const bytes = asNumber(value)
  if (bytes <= 0) return ""
  const units = ["B", "KB", "MB", "GB"]
  const index = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1
  )
  const amount = bytes / 1024 ** index
  return `${amount >= 10 || index === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[index]}`
}

const defang = (value: string): string =>
  value
    .replace(/^https:/i, "hxxps:")
    .replace(/^http:/i, "hxxp:")
    .replace(/\./g, "[.]")

export const formatCappedValues = (values: unknown, limit = 3): string => {
  if (!Array.isArray(values)) return ""
  const normalized = Array.from(new Set(values.map(clean).filter(Boolean)))
  if (normalized.length === 0) return ""
  const visible = normalized.slice(0, limit).join(", ")
  const remaining = normalized.length - limit
  return remaining > 0 ? `${visible} (+${remaining})` : visible
}

const firstWhoisValue = (whois: string, labels: string[]): string => {
  for (const label of labels) {
    const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    const match = whois.match(new RegExp(`^\\s*${escaped}\\s*:\\s*(.+)$`, "im"))
    if (match?.[1]) return clean(match[1])
  }
  return ""
}

const extractWhois = (attributes: any): IntelField[] => {
  const whois =
    typeof attributes?.whois === "string"
      ? attributes.whois.replace(/\r/g, "").trim()
      : ""
  if (!whois && !attributes?.registrar && !attributes?.creation_date) return []

  const registrar =
    clean(attributes?.registrar) ||
    firstWhoisValue(whois, [
      "Registrar",
      "Registrar Name",
      "Sponsoring Registrar"
    ])
  const created =
    formatDate(attributes?.creation_date) ||
    formatDate(
      firstWhoisValue(whois, [
        "Creation Date",
        "Created",
        "Created On",
        "Registered On"
      ])
    )
  const expires = formatDate(
    firstWhoisValue(whois, [
      "Registry Expiry Date",
      "Expiry Date",
      "Expiration Date",
      "Expires On"
    ])
  )
  const organization = firstWhoisValue(whois, [
    "Registrant Organization",
    "Organization",
    "OrgName",
    "org-name"
  ])
  const country = firstWhoisValue(whois, ["Registrant Country", "Country"])

  return [
    { label: "Registrar", value: registrar },
    { label: "Registered", value: created },
    { label: "Expires", value: expires },
    { label: "Organization", value: organization },
    { label: "Country", value: country }
  ].filter((field) => field.value)
}

type SignatureSummary = {
  fields: IntelField[]
  valid: boolean
}

const extractSignature = (signatureInfo: any): SignatureSummary => {
  if (!signatureInfo || typeof signatureInfo !== "object")
    return { fields: [], valid: false }

  const verified = clean(signatureInfo.verified)
  const normalized = verified.toLowerCase()
  const signerDetails = Array.isArray(signatureInfo["signers details"])
    ? signatureInfo["signers details"]
    : []
  const signerStatuses = signerDetails
    .map((item: any) => clean(item?.status))
    .filter(Boolean)
  const invalidDetail = signerStatuses.find((status: string) =>
    /invalid|expired|revoked|error|not valid|untrusted|unable/i.test(status)
  )
  const unsigned = /unsigned|not signed/i.test(normalized)
  const signed = !unsigned && /signed/i.test(normalized)
  const valid =
    signed &&
    !invalidDetail &&
    !/invalid|expired|revoked|error|not valid|untrusted|unable/i.test(
      normalized
    )

  let status = verified
  let tone: IntelTone = "neutral"
  if (unsigned) {
    status = "Unsigned"
  } else if (valid) {
    status = "Signed — valid"
    tone = "success"
  } else if (verified || invalidDetail) {
    status = `Signed — invalid${invalidDetail ? ` (${invalidDetail})` : verified ? ` (${verified})` : ""}`
    tone = "warning"
  }

  const signer =
    clean(signatureInfo.signers) ||
    clean(signerDetails[0]?.name) ||
    clean(signatureInfo.subject) ||
    clean(signatureInfo["certificate subject"])

  return {
    valid,
    fields: [
      { label: "Status", value: status, tone },
      { label: "Signer", value: signer },
      { label: "Product", value: clean(signatureInfo.product) },
      { label: "Description", value: clean(signatureInfo.description) },
      { label: "Signed on", value: formatDate(signatureInfo["signing date"]) }
    ].filter((field) => field.value)
  }
}

export const getVirusTotalSignatureFields = (signatureInfo: any): string[] => {
  const fields = extractSignature(signatureInfo).fields
  const valueFor = (label: string) =>
    fields.find((field) => field.label === label)?.value || "N/A"
  return [valueFor("Status"), valueFor("Signer"), valueFor("Product")]
}

const getDetectionFields = (attributes: any, limit = 3): IntelField[] => {
  const entries: IntelField[] = Object.entries(
    attributes?.last_analysis_results ?? {}
  )
    .filter(([, raw]) => {
      const result = raw as any
      return (
        result?.category === "malicious" || result?.category === "suspicious"
      )
    })
    .map(([engine, raw]) => {
      const result = raw as any
      return {
        label: engine,
        value: `${clean(result?.result) || "Flagged"} · ${clean(result?.category)}`,
        tone:
          result?.category === "malicious"
            ? ("danger" as const)
            : ("warning" as const)
      }
    })

  const visible = entries.slice(0, limit)
  const remaining = entries.length - visible.length
  if (remaining > 0)
    visible.push({
      label: "Additional detections",
      value: `+${remaining}`,
      tone: "neutral"
    })
  return visible
}

export const buildVirusTotalIntel = (payload: any): IntelSummary | null => {
  const data = payload?.data
  const attributes = data?.attributes
  if (!attributes) return null

  const stats = attributes.last_analysis_stats ?? {}
  const malicious = asNumber(stats.malicious)
  const suspicious = asNumber(stats.suspicious)
  const harmless = asNumber(stats.harmless)
  const undetected = asNumber(stats.undetected)
  const total = malicious + suspicious + harmless + undetected
  const verdictTone: IntelTone =
    malicious > 0
      ? "danger"
      : suspicious > 0
        ? "warning"
        : total > 0
          ? "success"
          : "neutral"
  const type = clean(data.type)
  const isFile = type === "file"
  const isDomain = type === "domain"
  const isUrl = type === "url"
  const rawIoc = isUrl ? clean(attributes.url) : clean(data.id)

  const overview: IntelField[] = [
    { label: "IOC", value: isDomain || isUrl ? defang(rawIoc) : rawIoc },
    {
      label: "Verdict",
      value: `${malicious} malicious · ${suspicious} suspicious · ${harmless} harmless · ${undetected} undetected`,
      tone: verdictTone
    },
    { label: "Last scan", value: formatDate(attributes.last_analysis_date) }
  ].filter((field) => field.value)

  const fileInfo: IntelField[] = isFile
    ? [
        { label: "Primary name", value: clean(attributes.meaningful_name) },
        {
          label: "Other names",
          value: formatCappedValues(
            Array.isArray(attributes.names)
              ? attributes.names.filter(
                  (name: unknown) =>
                    clean(name).toLowerCase() !==
                    clean(attributes.meaningful_name).toLowerCase()
                )
              : [],
            3
          )
        },
        {
          label: "File",
          value: [
            clean(attributes.type_description),
            formatBytes(attributes.size)
          ]
            .filter(Boolean)
            .join(" · ")
        },
        { label: "SHA256", value: clean(attributes.sha256) || clean(data.id) },
        {
          label: "First seen",
          value: formatDate(attributes.first_submission_date)
        }
      ].filter((field) => field.value)
    : []

  const signature = isFile
    ? extractSignature(attributes.signature_info)
    : { fields: [], valid: false }
  const whois = isDomain ? extractWhois(attributes) : []
  const certificate = attributes.last_https_certificate
  const certificateFields: IntelField[] = certificate
    ? [
        { label: "Subject", value: clean(certificate.subject?.CN) },
        { label: "Issuer", value: clean(certificate.issuer?.CN) },
        {
          label: "Valid from",
          value: formatDate(certificate.validity?.not_before)
        },
        {
          label: "Valid until",
          value: formatDate(certificate.validity?.not_after)
        }
      ].filter((field) => field.value)
    : []

  const networkInfo: IntelField[] = !isFile
    ? [
        { label: "ASN", value: clean(attributes.asn) },
        { label: "AS owner", value: clean(attributes.as_owner) },
        { label: "Network", value: clean(attributes.network) },
        { label: "Country", value: clean(attributes.country) }
      ].filter((field) => field.value)
    : []

  const sections: IntelSection[] = [
    { title: "Overview", fields: overview },
    { title: "File", fields: fileInfo },
    { title: "Digital signature", fields: signature.fields },
    { title: "WHOIS", fields: whois },
    { title: "Network", fields: networkInfo },
    { title: "HTTPS certificate", fields: certificateFields },
    { title: "Top detections", fields: getDetectionFields(attributes) }
  ].filter((section) => section.fields.length > 0)

  return { title: "VirusTotal", sections }
}

export const buildAbuseIntel = (
  payload: any,
  extraSignals: string[] = []
): IntelSummary | null => {
  const data = payload?.data
  if (!data) return null

  const score = asNumber(data.abuseConfidenceScore)
  const reports = asNumber(data.totalReports)
  const scoreTone: IntelTone =
    score >= 60 ? "danger" : score >= 20 || reports > 0 ? "warning" : "success"
  const overview: IntelField[] = [
    { label: "IP", value: clean(data.ipAddress) },
    { label: "Abuse score", value: `${score}%`, tone: scoreTone },
    {
      label: "Reports",
      value: clean(data.totalReports) || "0",
      tone: reports > 0 ? scoreTone : "success"
    },
    { label: "Distinct reporters", value: clean(data.numDistinctUsers) },
    { label: "Last report", value: formatDate(data.lastReportedAt) }
  ].filter((field) => field.value)

  const network: IntelField[] = [
    { label: "ISP", value: clean(data.isp) },
    { label: "Usage", value: clean(data.usageType) },
    { label: "Country", value: clean(data.countryCode) },
    { label: "Domain", value: clean(data.domain) },
    { label: "Hostnames", value: formatCappedValues(data.hostnames, 3) }
  ].filter((field) => field.value)

  const signalCandidates: Array<IntelField | null> = [
    data.isTor === true
      ? { label: "TOR", value: "Detected", tone: "warning" as const }
      : null,
    data.isWhitelisted === true
      ? { label: "Whitelisted", value: "Yes", tone: "success" as const }
      : data.isWhitelisted === false
        ? { label: "Whitelisted", value: "No", tone: "neutral" as const }
        : null,
    ...extraSignals.map((signal) => {
      const separator = signal.indexOf(":")
      return {
        label: separator >= 0 ? clean(signal.slice(0, separator)) : "Signal",
        value:
          separator >= 0 ? clean(signal.slice(separator + 1)) : clean(signal),
        tone: /\b(?:true|detected|high|tor|proxy|vpn|compromised)\b/i.test(
          signal
        )
          ? ("warning" as const)
          : ("neutral" as const)
      }
    })
  ]
  const allSignals = signalCandidates.filter(
    (field): field is IntelField => field !== null && !!field.value
  )
  const seenSignals = new Set<string>()
  const signals = allSignals.filter((field) => {
    const key = `${field.label}:${field.value}`.toLowerCase()
    if (seenSignals.has(key)) return false
    seenSignals.add(key)
    return true
  })
  return {
    title: "AbuseIPDB",
    sections: [
      { title: "Overview", fields: overview },
      { title: "Network", fields: network },
      { title: "Signals", fields: signals }
    ].filter((section) => section.fields.length > 0)
  }
}

export type NvdCvssSummary = {
  version: string
  score: number
  severity: string
  vector: string
  exploitabilityScore?: number
  impactScore?: number
}

export const getNvdCve = (payload: any): any | null =>
  payload?.vulnerabilities?.[0]?.cve ?? null

export const getNvdCvss = (payload: any): NvdCvssSummary | null => {
  const metrics = getNvdCve(payload)?.metrics
  if (!metrics || typeof metrics !== "object") return null

  const metricGroups = [
    metrics.cvssMetricV40,
    metrics.cvssMetricV31,
    metrics.cvssMetricV30,
    metrics.cvssMetricV2
  ]

  for (const group of metricGroups) {
    if (!Array.isArray(group) || group.length === 0) continue
    const metric =
      group.find((entry: any) => entry?.type === "Primary") ?? group[0]
    const cvssData = metric?.cvssData
    const score = Number(cvssData?.baseScore)
    if (!cvssData || !Number.isFinite(score)) continue
    return {
      version: clean(cvssData.version),
      score,
      severity: clean(
        cvssData.baseSeverity ?? metric.baseSeverity
      ).toUpperCase(),
      vector: clean(cvssData.vectorString),
      ...(Number.isFinite(Number(metric.exploitabilityScore))
        ? { exploitabilityScore: Number(metric.exploitabilityScore) }
        : {}),
      ...(Number.isFinite(Number(metric.impactScore))
        ? { impactScore: Number(metric.impactScore) }
        : {})
    }
  }

  return null
}

const truncate = (value: unknown, limit: number): string => {
  const normalized = clean(value)
  if (normalized.length <= limit) return normalized
  return `${normalized.slice(0, limit - 1).trimEnd()}…`
}

const getNvdWeaknesses = (cve: any): string => {
  const values = (Array.isArray(cve?.weaknesses) ? cve.weaknesses : [])
    .flatMap((weakness: any) =>
      Array.isArray(weakness?.description) ? weakness.description : []
    )
    .filter((entry: any) => entry?.lang === "en")
    .map((entry: any) => clean(entry?.value))
    .filter((value: string) => /^CWE-\d+$/i.test(value))
  return formatCappedValues(values, 5)
}

const decodeCpeComponent = (value: string): string => {
  if (!value || value === "*" || value === "-") return ""
  try {
    return decodeURIComponent(value.replace(/\\([\\:!?*])/g, "$1"))
      .replace(/_/g, " ")
      .trim()
  } catch {
    return value.replace(/_/g, " ").trim()
  }
}

const getNvdAffectedProducts = (cve: any): string => {
  const matches: any[] = []
  const visit = (value: any) => {
    if (!value || typeof value !== "object") return
    if (Array.isArray(value)) {
      value.forEach(visit)
      return
    }
    if (Array.isArray(value.cpeMatch)) matches.push(...value.cpeMatch)
    Object.values(value).forEach(visit)
  }
  visit(cve?.configurations)

  const products = matches
    .filter((match) => match?.vulnerable === true && match?.criteria)
    .map((match) => {
      const parts = String(match.criteria).split(":")
      const vendor = decodeCpeComponent(parts[3])
      const product = decodeCpeComponent(parts[4])
      const version = decodeCpeComponent(parts[5])
      const start = clean(
        match.versionStartIncluding ?? match.versionStartExcluding
      )
      const end = clean(match.versionEndIncluding ?? match.versionEndExcluding)
      const range =
        start || end
          ? [
              start
                ? `${match.versionStartExcluding ? ">" : ">="} ${start}`
                : "",
              end ? `${match.versionEndExcluding ? "<" : "<="} ${end}` : ""
            ]
              .filter(Boolean)
              .join("; ")
          : version
      return (
        [vendor, product].filter(Boolean).join(" ") +
        (range ? ` (${range})` : "")
      )
    })
    .filter(Boolean)

  return formatCappedValues(products, 5)
}

export const buildNvdIntel = (payload: any): IntelSummary | null => {
  const cve = getNvdCve(payload)
  if (!cve?.id) return null

  const cvss = getNvdCvss(payload)
  const severity = cvss?.severity ?? ""
  const cvssTone: IntelTone =
    severity === "CRITICAL" || severity === "HIGH"
      ? "danger"
      : severity === "MEDIUM"
        ? "warning"
        : severity === "LOW"
          ? "success"
          : "neutral"
  const description =
    (Array.isArray(cve.descriptions)
      ? cve.descriptions.find((entry: any) => entry?.lang === "en")?.value
      : "") ?? ""
  const references = (Array.isArray(cve.references) ? cve.references : [])
    .map((entry: any) => clean(entry?.url))
    .filter(Boolean)

  const overview: IntelField[] = [
    { label: "CVE", value: clean(cve.id).toUpperCase() },
    { label: "Status", value: clean(cve.vulnStatus) },
    { label: "Published", value: formatDate(cve.published) },
    { label: "Last modified", value: formatDate(cve.lastModified) },
    {
      label: "CVSS",
      value: cvss
        ? `v${cvss.version} · ${cvss.score.toFixed(1)} · ${cvss.severity || "UNRATED"}`
        : "Not available",
      tone: cvssTone
    },
    { label: "Vector", value: cvss?.vector ?? "" },
    {
      label: "Exploitability / impact",
      value:
        cvss?.exploitabilityScore !== undefined ||
        cvss?.impactScore !== undefined
          ? `${cvss.exploitabilityScore ?? "N/A"} / ${cvss.impactScore ?? "N/A"}`
          : ""
    }
  ].filter((field) => field.value)

  const kev: IntelField[] = cve.cisaExploitAdd
    ? (
        [
          {
            label: "CISA KEV",
            value: `Listed since ${formatDate(cve.cisaExploitAdd)}`,
            tone: "danger"
          },
          { label: "Vulnerability", value: clean(cve.cisaVulnerabilityName) },
          { label: "Action due", value: formatDate(cve.cisaActionDue) },
          {
            label: "Required action",
            value: truncate(cve.cisaRequiredAction, 450),
            tone: "warning"
          }
        ] as IntelField[]
      ).filter((field) => field.value)
    : []

  return {
    title: "NVD",
    sections: [
      { title: "Overview", fields: overview },
      {
        title: "Vulnerability",
        fields: [
          { label: "Description", value: truncate(description, 900) },
          { label: "Weaknesses", value: getNvdWeaknesses(cve) },
          { label: "Affected products", value: getNvdAffectedProducts(cve) }
        ].filter((field) => field.value)
      },
      { title: "Known exploitation", fields: kev },
      {
        title: "References",
        fields: [
          { label: "Links", value: formatCappedValues(references, 3) }
        ].filter((field) => field.value)
      }
    ].filter((section) => section.fields.length > 0)
  }
}

export const formatIntelSummary = (summary: IntelSummary): string => {
  const contextualizeLabel = (section: string, label: string): string => {
    if (section === "HTTPS certificate") return `Certificate ${label}`
    if (section === "Digital signature") {
      if (label === "Status") return "Signature"
      if (label === "Signer") return "Signature signer"
      if (label === "Product") return "Signed product"
      if (label === "Description") return "Signed description"
    }
    if (section === "Top detections" && label !== "Additional detections") {
      return `Detection (${label})`
    }
    return label
  }

  const flattened = summary.sections.flatMap((section) =>
    section.fields.map((field) => ({
      ...field,
      section: section.title,
      label: contextualizeLabel(section.title, field.label)
    }))
  )
  const labelOccurrences = new Map<string, number>()
  const fields = flattened.map((field) => {
    const normalizedLabel = field.label.toLowerCase()
    const occurrence = labelOccurrences.get(normalizedLabel) ?? 0
    labelOccurrences.set(normalizedLabel, occurrence + 1)
    return occurrence === 0
      ? field
      : { ...field, label: `${field.section} ${field.label}` }
  })
  const labels = fields.map((field) => `${field.label}:`)
  const width = Math.max(0, ...labels.map((label) => label.length))
  const lines: string[] = [summary.title]
  fields.forEach((field, index) => {
    lines.push(`- ${labels[index].padEnd(width, " ")} ${field.value}`)
  })
  return lines.join("\n")
}

export const classifyIntelTextLine = (line: string): IntelTone => {
  const normalized = line.trim().toLowerCase()
  if (!normalized) return "neutral"

  const malicious = normalized.match(/\b(\d+)\s+malicious\b/)
  if (malicious && Number(malicious[1]) > 0) return "danger"
  if (/·\s*malicious\b/.test(normalized)) return "danger"
  const suspicious = normalized.match(/\b(\d+)\s+suspicious\b/)
  if (suspicious && Number(suspicious[1]) > 0) return "warning"
  if (/·\s*suspicious\b/.test(normalized)) return "warning"
  if (
    /signed\s+[—-]\s+invalid|certificate\s+(?:expired|revoked|invalid)/i.test(
      line
    )
  )
    return "warning"
  if (/signed\s+[—-]\s+valid|whitelisted:\s+yes/i.test(line)) return "success"

  const score = normalized.match(/abuse score:\s*(\d+)%/)
  if (score) {
    const value = Number(score[1])
    return value >= 60 ? "danger" : value >= 20 ? "warning" : "success"
  }
  const reports = normalized.match(/reports:\s*(\d+)/)
  if (reports) return Number(reports[1]) > 0 ? "warning" : "success"
  if (/\b(tor|proxy|vpn|compromised):\s+(?:true|detected|yes)\b/i.test(line))
    return "warning"
  if (/verdict:.*\b0 malicious\b.*\b0 suspicious\b/i.test(line))
    return "success"
  const cvss = normalized.match(/cvss:\s*v[\d.]+\s+·\s+([\d.]+)\s+·\s+(\w+)/)
  if (cvss) {
    if (cvss[2] === "critical" || cvss[2] === "high") return "danger"
    if (cvss[2] === "medium") return "warning"
    if (cvss[2] === "low") return "success"
  }
  if (/cisa kev:\s+listed/i.test(normalized)) return "danger"
  return "neutral"
}
