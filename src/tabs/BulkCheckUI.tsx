import React, { useMemo } from "react"
import {
  ArrowDownTrayIcon,
  ArrowPathIcon,
  ClipboardDocumentListIcon,
  PlayCircleIcon,
  TrashIcon
} from "@heroicons/react/24/outline"
import { parseAndFormatResults } from "../utility/utils"
import type { BulkCheckSummaryRow, BulkStatusKind } from "./bulk-check.types"

interface BulkCheckUIProps {
  textareaValue: string
  onTextAreaChange: (e: React.ChangeEvent<HTMLTextAreaElement>) => void
  onFileUpload: (e: React.ChangeEvent<HTMLInputElement>) => void
  selectedServices: string[]
  onServiceToggle: (service: string, checked: boolean) => void
  onCheckBulk: () => void
  onClearList: () => void
  isLoading: boolean
  message: string
  results: { [key: string]: any }
  isDarkMode: boolean
  proxyCheckEnabled: boolean
  onExport: (format: "csv" | "xlsx") => void
  onProxyCheckToggle: (value: boolean) => void
  iocTypeSummary: { type: string; count: number }[]
  ignoredTypes: string[]
  onTypeToggle: (type: string) => void
  onRefreshIocs: () => void
  dailyCounters: {
    vt: number
    abuse: number
    proxy: number
  }
  iocSummaries: BulkCheckSummaryRow[]
}

const SERVICE_STATUS_PILL: Record<HighlightStatus, string> = {
  pending: "bg-slate-500/20 text-slate-100",
  clean: "bg-emerald-500/15 text-emerald-100",
  flagged: "bg-amber-500/15 text-amber-100",
  error: "bg-slate-500/20 text-slate-100",
  skipped: "bg-socx-cloud-soft/70 text-socx-muted dark:bg-socx-panel/50 dark:text-socx-muted-dark",
  "flagged-high": "bg-rose-500/30 text-rose-50",
  "flagged-medium": "bg-amber-500/30 text-amber-50"
}

const SERVICE_CARD_TONE: Record<HighlightStatus, string> = {
  pending: "border-slate-500/30 bg-slate-500/5 dark:border-slate-400/40 dark:bg-socx-panel/40",
  clean: "border-emerald-500/30 bg-emerald-500/5 dark:border-emerald-400/30 dark:bg-emerald-500/10",
  flagged: "border-amber-500/30 bg-amber-500/5 dark:border-amber-400/40 dark:bg-amber-500/10",
  error: "border-slate-500/40 bg-slate-500/10 dark:border-slate-400/40 dark:bg-slate-700/30",
  skipped: "border-socx-border-light bg-socx-cloud-soft/50 dark:border-socx-border-dark dark:bg-socx-panel/40",
  "flagged-high": "border-rose-500/40 bg-rose-500/10 dark:border-rose-400/40 dark:bg-rose-500/20",
  "flagged-medium": "border-amber-500/40 bg-amber-500/10 dark:border-amber-400/40 dark:bg-amber-500/20"
}

const SERVICE_STATUS_LABEL: Record<HighlightStatus, string> = {
  pending: "PENDING",
  clean: "CLEAN",
  flagged: "LOW",
  error: "ERROR",
  skipped: "SKIPPED",
  "flagged-high": "HIGH",
  "flagged-medium": "MEDIUM"
}

type HighlightStatus = BulkStatusKind | "flagged-high" | "flagged-medium"

type ServiceHighlight = {
  label: string
  status: HighlightStatus
  headline: string
  subline: string
  meta?: string
}

type Severity = "low" | "medium" | "high"

const formatDateLabel = (value: string | number | null | undefined): string | null => {
  if (value === null || value === undefined || value === "") {
    return null
  }
  const numeric = typeof value === "number" ? value : Number(value)
  const timestamp =
    typeof value === "number"
      ? value
      : Number.isFinite(numeric) && numeric > 0 && `${value}`.length <= 10
        ? numeric
        : null
  const date = timestamp
    ? new Date((timestamp > 10_000_000_000 ? timestamp : timestamp * 1000))
    : new Date(value)
  if (Number.isNaN(date.getTime())) {
    return null
  }
  return date.toISOString().split("T")[0]
}

const getServiceStatus = (entry: BulkCheckSummaryRow, serviceName: string) =>
  entry.serviceStatuses.find((service) => service.name === serviceName)

const SEVERITY_ORDER: Severity[] = ["low", "medium", "high"]

const escalateSeverity = (current: Severity, next: Severity): Severity =>
  SEVERITY_ORDER[Math.max(SEVERITY_ORDER.indexOf(current), SEVERITY_ORDER.indexOf(next))]

const deriveVirusTotalSeverity = (payload: any): Severity | null => {
  const stats = payload?.data?.attributes?.last_analysis_stats
  if (!stats) {
    return null
  }

  const malicious = Number(stats.malicious) || 0
  const suspicious = Number(stats.suspicious) || 0
  const harmless = Number(stats.harmless) || 0
  const harmlessBonus = Math.min(harmless * 0.2, 5)
  const vtScore = malicious * 3 + suspicious - harmlessBonus

  if (vtScore >= 20 || malicious >= 5) {
    return "high"
  }
  if (vtScore >= 5 || malicious > 0 || suspicious > 0) {
    return "medium"
  }
  return "low"
}

const deriveAbuseSeverity = (payload: any): Severity | null => {
  const data = payload?.data
  if (!data) {
    return null
  }

  const abuseScore = Number(data.abuseConfidenceScore) || 0
  const totalReports = Number(data.totalReports) || 0
  if (abuseScore >= 60 || totalReports >= 10) {
    return "high"
  }
  if (abuseScore >= 20 || totalReports > 0) {
    return "medium"
  }
  return "low"
}

const applyServiceSeverity = (base: BulkStatusKind, severity: Severity | null): HighlightStatus => {
  if (!severity || ["pending", "error", "skipped"].includes(base)) {
    return base
  }
  if (severity === "high") {
    return "flagged-high"
  }
  if (severity === "medium") {
    return "flagged-medium"
  }
  return base
}

const extractProxyCheckDetails = (
  entry: BulkCheckSummaryRow
): { proxyPayload: any | null; proxyDetections: any | null } => {
  const proxyData = entry.result?.ProxyCheck
  if (!proxyData || typeof proxyData !== "object") {
    return { proxyPayload: null, proxyDetections: null }
  }
  const ipEntryKey = Object.keys(proxyData).find(
    (key) => key.includes(".") && typeof proxyData[key] === "object"
  )
  const proxyPayload = ipEntryKey ? proxyData[ipEntryKey] : proxyData
  const proxyDetections = proxyPayload?.detections ?? null
  return { proxyPayload, proxyDetections }
}

const isAffirmativeFlag = (value: unknown): boolean => {
  if (typeof value === "boolean") {
    return value
  }
  if (typeof value === "number") {
    return value > 0
  }
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase()
    return ["true", "yes", "y", "1", "detected"].includes(normalized)
  }
  return false
}

const buildVirusTotalHighlight = (entry: BulkCheckSummaryRow): ServiceHighlight => {
  const status = getServiceStatus(entry, "VirusTotal")
  if (!status) {
    return {
      label: "VirusTotal",
      status: "skipped",
      headline: "Not selected",
      subline: "Enable VirusTotal to enrich non-IP IOCs."
    }
  }

  const payload = entry.result?.VirusTotal
  if (payload?.error) {
    return {
      label: "VirusTotal",
      status: "error",
      headline: "Fetch failed",
      subline: typeof payload.error === "string" ? payload.error : "Unable to retrieve data"
    }
  }

  const attributes = payload?.data?.attributes
  const stats = attributes?.last_analysis_stats
  if (!stats) {
    return {
      label: "VirusTotal",
      status: status.status,
      headline: status.text,
      subline: status.status === "pending" ? "Awaiting last analysis..." : "No telemetry yet"
    }
  }

  const malicious = Number(stats.malicious) || 0
  const suspicious = Number(stats.suspicious) || 0
  const harmless = Number(stats.harmless) || 0
  const undetected = Number(stats.undetected) || 0
  const total = malicious + suspicious + harmless + undetected
  const scanDate = formatDateLabel(attributes?.last_analysis_date)

  const severityStatus = applyServiceSeverity(status.status, deriveVirusTotalSeverity(payload))

  return {
    label: "VirusTotal",
    status: severityStatus,
    headline: `${malicious} malicious • ${suspicious} suspicious`,
    subline: `${total} engines (${harmless} harmless, ${undetected} undetected)`,
    meta: scanDate ? `Last scan ${scanDate}` : undefined
  }
}

const buildAbuseHighlight = (entry: BulkCheckSummaryRow): ServiceHighlight => {
  const status = getServiceStatus(entry, "AbuseIPDB")
  if (!status) {
    return {
      label: "AbuseIPDB",
      status: "skipped",
      headline: "Not selected",
      subline: "Enable AbuseIPDB for public IP indicators."
    }
  }

  const payload = entry.result?.AbuseIPDB
  if (payload?.error) {
    return {
      label: "AbuseIPDB",
      status: "error",
      headline: "Fetch failed",
      subline: typeof payload.error === "string" ? payload.error : "Unable to retrieve data"
    }
  }

  const data = payload?.data
  if (!data) {
    return {
      label: "AbuseIPDB",
      status: status.status,
      headline: status.text,
      subline: status.status === "pending" ? "Awaiting response..." : "No reports fetched"
    }
  }

  const score = Number(data.abuseConfidenceScore) || 0
  const reports = Number(data.totalReports) || 0
  const lastReported = formatDateLabel(data.lastReportedAt)
  const location = data.countryCode ? `Country ${data.countryCode}` : "Location unknown"

  const severityStatus = applyServiceSeverity(status.status, deriveAbuseSeverity(payload))

  return {
    label: "AbuseIPDB",
    status: severityStatus,
    headline: `${score}% confidence • ${reports} reports`,
    subline: `${location}${data.isp ? ` • ISP ${data.isp}` : ""}`,
    meta: lastReported ? `Last report ${lastReported}` : undefined
  }
}

type QuickFact = {
  label: string
  value?: string
  highlight?: boolean
}

const CARD_TONE: Record<Severity, string> = {
  low: "border-socx-border-light bg-white/95 dark:border-socx-border-dark dark:bg-socx-panel/60",
  medium: "border-amber-500/50 bg-white/95 dark:border-amber-400/50 dark:bg-socx-panel/60",
  high: "border-rose-500/50 bg-white/95 dark:border-rose-400/50 dark:bg-socx-panel/60"
}

const getSeverityLevel = (entry: BulkCheckSummaryRow): Severity => {
  const vt = entry.result?.VirusTotal
  const abuse = entry.result?.AbuseIPDB
  const ipapiData = entry.result?.Ipapi?.data ?? entry.result?.Ipapi
  const { proxyPayload, proxyDetections } = extractProxyCheckDetails(entry)

  let vtLevel: Severity = deriveVirusTotalSeverity(vt) ?? "low"
  let abuseLevel: Severity = deriveAbuseSeverity(abuse) ?? "low"
  let proxyLevel: Severity = "low"
  let ipapiLevel: Severity = "low"

  if (proxyPayload || proxyDetections) {
    const parseRiskScore = (value: unknown): number => {
      if (typeof value === "number") {
        return value
      }
      if (typeof value === "string") {
        const parsed = Number(value)
        return Number.isFinite(parsed) ? parsed : 0
      }
      return 0
    }

    const rawRisk = proxyDetections?.risk ?? proxyPayload?.risk
    const riskScore = parseRiskScore(rawRisk)
    if (riskScore >= 80) {
      proxyLevel = "high"
    } else if (riskScore >= 40) {
      proxyLevel = "medium"
    }

    const applyDetection = (fields: string[], level: Severity) => {
      if (!proxyDetections) {
        return
      }
      if (fields.some((field) => isAffirmativeFlag(proxyDetections[field]))) {
        proxyLevel = escalateSeverity(proxyLevel, level)
      }
    }

    applyDetection(["tor", "compromised", "anonymous", "hosting"], "high")
    applyDetection(["vpn", "proxy", "scraper"], "medium")

    if (proxyPayload) {
      if (isAffirmativeFlag(proxyPayload.proxy)) {
        proxyLevel = escalateSeverity(proxyLevel, "medium")
      }
      if (typeof proxyPayload.type === "string") {
        const normalized = proxyPayload.type.toLowerCase()
        if (["tor", "compromised"].includes(normalized)) {
          proxyLevel = escalateSeverity(proxyLevel, "high")
        } else if (["vpn", "proxy", "hosting"].includes(normalized)) {
          proxyLevel = escalateSeverity(proxyLevel, "medium")
        }
      }
    }
  }

  if (ipapiData && typeof ipapiData === "object") {
    const escalateForFields = (fields: string[], level: Severity) => {
      if (fields.some((field) => ipapiData?.[field] === true)) {
        ipapiLevel = escalateSeverity(ipapiLevel, level)
      }
    }
    escalateForFields(["is_tor", "is_abuser"], "high")
    escalateForFields(["is_proxy", "is_vpn", "is_datacenter"], "medium")
    if (ipapiData?.vpn?.service) {
      ipapiLevel = escalateSeverity(ipapiLevel, "medium")
    }
  }

  let severity: Severity = escalateSeverity(vtLevel, abuseLevel)
  severity = escalateSeverity(severity, proxyLevel)
  severity = escalateSeverity(severity, ipapiLevel)

  const cleanNoDetections =
    entry.statusKind !== "flagged" &&
    typeof entry.statusText === "string" &&
    entry.statusText.toLowerCase().includes("no detection")

  if (severity === "low") {
    const abuseStatus = entry.serviceStatuses.find((service) => service.name === "AbuseIPDB")
    if (abuseStatus) {
      const scoreMatch = abuseStatus.text.match(/(\d+)%/)
      const reportsMatch = abuseStatus.text.match(/(\d+)\s+reports?/)
      const score = scoreMatch ? Number(scoreMatch[1]) : 0
      const reports = reportsMatch ? Number(reportsMatch[1]) : 0
      if (score >= 60 || reports >= 10) {
        severity = "high"
      } else if (score >= 20 || reports > 0) {
        severity = "medium"
      }
    }
  }

  if (severity === "low" && entry.statusKind === "flagged") {
    severity = "medium"
  }

  const hasPrimaryHigh = vtLevel === "high" || abuseLevel === "high"
  if (!hasPrimaryHigh && severity === "high") {
    severity = "medium"
  }

  if (cleanNoDetections && severity === "high") {
    severity = "medium"
  }

  return severity
}

const getBadgeClass = (entry: BulkCheckSummaryRow): string => {
  const severity = getSeverityLevel(entry)
  if (severity === "high") {
    return "bg-rose-500/25 text-rose-100"
  }
  if (severity === "medium") {
    return "bg-amber-500/25 text-amber-100"
  }
  if (entry.statusKind === "flagged") {
    return "bg-emerald-500/20 text-emerald-100"
  }
  const map: Record<BulkStatusKind, string> = {
    pending: "bg-slate-500/20 text-slate-200 dark:text-slate-100",
    clean: "bg-emerald-500/15 text-emerald-100",
    flagged: "bg-amber-500/20 text-amber-100",
    error: "bg-slate-500/25 text-slate-100",
    skipped: "bg-socx-muted/10 text-socx-muted-dark dark:text-socx-muted"
  }
  return map[entry.statusKind] ?? map.pending
}

const buildQuickFacts = (entry: BulkCheckSummaryRow): QuickFact[] => {
  const highlights: QuickFact[] = []
  const regularFacts: QuickFact[] = []
  const abuseData = entry.result?.AbuseIPDB?.data
  const ipapiData = entry.result?.Ipapi?.data ?? entry.result?.Ipapi
  const { proxyPayload, proxyDetections } = extractProxyCheckDetails(entry)

  const addFact = (label: string, value: unknown, options?: { highlight?: boolean }) => {
    if ((value === null || value === undefined || value === "" || value === "N/A") && !options?.highlight) {
      return
    }
    const payload: QuickFact = {
      label,
      ...(value !== undefined && value !== null && value !== "" && value !== "N/A"
        ? { value: String(value) }
        : {})
    }
    if (options?.highlight) {
      payload.highlight = true
      highlights.push(payload)
    } else {
      regularFacts.push(payload)
    }
  }

  addFact("Country", abuseData?.countryCode ?? ipapiData?.country_code ?? ipapiData?.country)
  addFact("ISP", abuseData?.isp ?? ipapiData?.isp)
  addFact(
    "Domain",
    abuseData?.domain ??
      entry.result?.VirusTotal?.data?.attributes?.meaningful_name ??
      entry.result?.VirusTotal?.data?.attributes?.last_https_certificate?.subject?.CN
  )

  const vpnService =
    ipapiData?.vpn?.service ??
    (ipapiData?.is_vpn === true ? "Detected" : null) ??
    (proxyDetections?.vpn === true ? "Detected" : null)
  if (vpnService) {
    addFact("VPN", vpnService, { highlight: true })
  }

  if (ipapiData?.is_tor === true || proxyDetections?.tor === true) {
    addFact("TOR", "Detected", { highlight: true })
  }

  const proxyValue = proxyPayload?.proxy ?? proxyDetections?.proxy
  if (proxyValue !== undefined) {
    addFact("Proxy", typeof proxyValue === "boolean" ? (proxyValue ? "Detected" : "Clean") : proxyValue, { highlight: true })
  }

  if (typeof proxyDetections?.risk === "number" && proxyDetections.risk > 0) {
    addFact("Risk score", proxyDetections.risk)
  }

  if (proxyPayload?.operator?.name) {
    addFact("Operator", proxyPayload.operator.name)
  }

  return [...highlights, ...regularFacts].slice(0, 4)
}

const BulkCheckUI: React.FC<BulkCheckUIProps> = ({
  textareaValue,
  onTextAreaChange,
  onFileUpload,
  selectedServices,
  onServiceToggle,
  onCheckBulk,
  onClearList,
  isLoading,
  message,
  results,
  proxyCheckEnabled,
  onExport,
  onProxyCheckToggle,
  iocTypeSummary,
  ignoredTypes,
  onTypeToggle,
  onRefreshIocs,
  dailyCounters,
  iocSummaries
}) => {
  const iocStats = useMemo(() => {
    const total = iocSummaries.length
    let flagged = 0
    let errors = 0
    let pending = 0

    for (const entry of iocSummaries) {
      const severity = getSeverityLevel(entry)
      if (severity !== "low") {
        flagged += 1
      }

      if (entry.statusKind === "error") {
        errors += 1
      } else if (entry.statusKind === "pending") {
        pending += 1
      }
    }

    const highSeverity = iocSummaries.filter((entry) => getSeverityLevel(entry) === "high").length
    const mediumSeverity = iocSummaries.filter((entry) => getSeverityLevel(entry) === "medium").length

    return { total, flagged, errors, pending, highSeverity, mediumSeverity }
  }, [iocSummaries])

  const flaggedNeutralState = useMemo(
    () => iocStats.flagged === 0 && iocStats.errors === 0 && iocStats.pending === 0,
    [iocStats.errors, iocStats.flagged, iocStats.pending]
  )

  const flaggedTone = useMemo(() => {
    if (iocStats.flagged === 0) {
      return flaggedNeutralState
        ? "bg-emerald-500/20 text-emerald-900 dark:text-emerald-100"
        : "bg-socx-cloud-soft/70 dark:bg-socx-panel/70"
    }
    if (iocStats.highSeverity > 0) {
      return "bg-rose-500/25 text-rose-900 dark:text-rose-100"
    }
    if (iocStats.mediumSeverity > 0) {
      return "bg-amber-500/20 text-amber-900 dark:text-amber-100"
    }
    return "bg-amber-500/20 text-amber-900 dark:text-amber-100"
  }, [flaggedNeutralState, iocStats.flagged, iocStats.highSeverity, iocStats.mediumSeverity])

  return (
    <div className="min-h-screen bg-socx-cloud px-4 py-6 font-inter text-socx-ink dark:bg-socx-night dark:text-white">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
        <header className="rounded-socx-lg border border-socx-border-light bg-white/90 p-6 dark:border-socx-border-dark dark:bg-socx-night-soft/80">
          <p className="text-xs font-semibold uppercase tracking-[0.4em] text-socx-muted dark:text-socx-muted-dark">
            SOCx
          </p>
          <h1 className="mt-1 text-2xl font-semibold">Bulk IOC Check</h1>
          <p className="text-sm text-socx-muted dark:text-socx-muted-dark">
            Paste any list of indicators, auto-categorize them and launch checks on your preferred services.
          </p>
        </header>

        <div className="grid gap-6 lg:grid-cols-2">
          <section className="space-y-4 rounded-socx-lg border border-socx-border-light bg-white/90 p-5 dark:border-socx-border-dark dark:bg-socx-night-soft/80">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold">IOC workspace</p>
                <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
                  Paste plain text lists, the extractor keeps unique entries.
                </p>
              </div>
              <button
                type="button"
                onClick={onRefreshIocs}
                disabled={isLoading || !textareaValue.trim()}
                className="inline-flex items-center gap-1 rounded-full border border-socx-border-light px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] text-socx-muted transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-40 dark:border-socx-border-dark">
                <ArrowPathIcon className="h-3.5 w-3.5" />
                Refresh
              </button>
            </div>
            <textarea
              className="socx-scroll h-72 w-full rounded-2xl border border-socx-border-light bg-white/95 px-4 py-3 text-sm text-socx-ink outline-none transition focus:border-socx-accent focus:ring-2 focus:ring-socx-accent/40 dark:border-socx-border-dark dark:bg-socx-panel/60 dark:text-white"
              placeholder="Paste IPs, domains, hashes, emails, URLs..."
              value={textareaValue}
              onChange={onTextAreaChange}
            />
            <div className="rounded-2xl border border-socx-border-light bg-white/80 p-4 text-sm dark:border-socx-border-dark dark:bg-socx-panel/50">
              <p className="text-xs font-semibold uppercase tracking-[0.3em] text-socx-muted dark:text-socx-muted-dark">
                Daily counters
              </p>
              <div className="mt-3 grid gap-3 sm:grid-cols-3">
                {[
                  { label: "VirusTotal", value: dailyCounters.vt },
                  { label: "AbuseIPDB", value: dailyCounters.abuse },
                  { label: "ProxyCheck", value: dailyCounters.proxy }
                ].map((counter) => (
                  <div key={counter.label} className="rounded-xl border border-dashed border-socx-border-light px-3 py-2 text-center text-sm dark:border-socx-border-dark">
                    <p className="text-xs text-socx-muted dark:text-socx-muted-dark">{counter.label}</p>
                    <p className="text-lg font-semibold">{counter.value}</p>
                  </div>
                ))}
              </div>
            </div>
          </section>

          <section className="space-y-4 rounded-socx-lg border border-socx-border-light bg-white/90 p-5 dark:border-socx-border-dark dark:bg-socx-night-soft/80">
            <div className="space-y-2">
              <label className="flex items-center gap-2 text-sm font-semibold">
                <ArrowDownTrayIcon className="h-4 w-4 text-socx-muted" />
                Upload .txt file
              </label>
              <input
                type="file"
                accept=".txt"
                onChange={onFileUpload}
                className="block w-full text-sm text-socx-muted file:mr-4 file:flex file:items-center file:gap-2 file:rounded-full file:border-0 file:bg-socx-accent file:px-4 file:py-2 file:text-sm file:font-semibold file:text-socx-ink hover:file:bg-socx-accent-strong"
              />
            </div>

            <div className="rounded-2xl border border-socx-border-light bg-white/80 p-4 dark:border-socx-border-dark dark:bg-socx-panel/50">
              <div className="flex items-center justify-between">
                <p className="text-sm font-semibold">ProxyCheck enrichment</p>
                <button
                  type="button"
                  role="switch"
                  aria-checked={proxyCheckEnabled}
                  onClick={() => onProxyCheckToggle(!proxyCheckEnabled)}
                  className={`relative inline-flex h-7 w-12 items-center rounded-full border transition ${
                    proxyCheckEnabled
                      ? "border-socx-accent bg-socx-accent/80"
                      : "border-socx-border-light bg-white dark:border-socx-border-dark dark:bg-socx-panel"
                  }`}>
                  <span
                    className={`inline-block h-5 w-5 rounded-full bg-white shadow transition ${
                      proxyCheckEnabled ? "translate-x-5" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>
              <p className="mt-1 text-xs text-socx-muted dark:text-socx-muted-dark">
                ProxyCheck adds VPN/proxy classification to Abuse lookups.
              </p>
            </div>

            <div className="flex flex-col gap-2">
              <button
                type="button"
                onClick={onCheckBulk}
                disabled={isLoading}
                className="flex w-full items-center justify-center gap-2 rounded-full bg-socx-accent px-4 py-3 text-sm font-semibold text-socx-ink transition hover:bg-socx-accent-strong focus-visible:outline-none focus-visible:shadow-socx-focus disabled:cursor-not-allowed disabled:opacity-60">
                <PlayCircleIcon className="h-5 w-5" />
                {isLoading ? "Running analysis…" : "Run analysis"}
              </button>
              <div className="grid gap-2 sm:grid-cols-2">
                <button
                  type="button"
                  onClick={onClearList}
                  className="inline-flex items-center justify-center gap-2 rounded-full border border-socx-border-light px-4 py-2 text-sm font-semibold text-socx-ink transition hover:border-socx-accent hover:text-socx-accent dark:border-socx-border-dark dark:text-white">
                  <TrashIcon className="h-4 w-4" />
                  Clear list
                </button>
                <button
                  type="button"
                  onClick={() => onExport("csv")}
                  disabled={Object.keys(results).length === 0}
                  className="inline-flex items-center justify-center gap-2 rounded-full border border-socx-border-light px-4 py-2 text-sm font-semibold text-socx-ink transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-40 dark:border-socx-border-dark dark:text-white">
                  <ArrowDownTrayIcon className="h-4 w-4" />
                  Export CSV
                </button>
                <button
                  type="button"
                  onClick={() => onExport("xlsx")}
                  disabled={Object.keys(results).length === 0}
                  className="inline-flex items-center justify-center gap-2 rounded-full border border-socx-border-light px-4 py-2 text-sm font-semibold text-socx-ink transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-40 dark:border-socx-border-dark dark:text-white">
                  <ArrowDownTrayIcon className="h-4 w-4" />
                  Export Excel
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const formatted = Object.entries(results)
                      .filter(([_, result]) => {
                        const content = parseAndFormatResults(result).trim()
                        return content && content !== "-"
                      })
                      .map(([ioc, result]) => {
                        const content = parseAndFormatResults(result).trim()
                        return `## ${ioc}\n${content}\n---\n\n`
                      })
                      .join("\n")

                    if (formatted) {
                      navigator.clipboard
                        .writeText(formatted)
                        .then(() => alert("Formatted IOCs copied to clipboard!"))
                        .catch(() => alert("Error copying to clipboard."))
                    } else {
                      alert("No formatted results available to copy.")
                    }
                  }}
                  disabled={Object.keys(results).length === 0}
                  className="inline-flex items-center justify-center gap-2 rounded-full border border-socx-border-light px-4 py-2 text-sm font-semibold text-socx-ink transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-40 dark:border-socx-border-dark dark:text-white">
                  <ClipboardDocumentListIcon className="h-4 w-4" />
                  Copy formatted
                </button>
              </div>
            </div>

            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.3em] text-socx-muted dark:text-socx-muted-dark">
                Services
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                {["VirusTotal", "AbuseIPDB"].map((service) => {
                  const checked = selectedServices.includes(service)
                  return (
                    <button
                      type="button"
                      key={service}
                      onClick={(event) => onServiceToggle(service, !checked)}
                      className={`socx-chip ${checked ? "socx-chip-active" : "border-socx-border-light bg-white/90 dark:border-socx-border-dark dark:bg-socx-panel/40"}`}
                      aria-pressed={checked}>
                      {service}
                    </button>
                  )
                })}
              </div>
            </div>

            {iocTypeSummary.length > 0 && (
              <div className="space-y-3 rounded-2xl border border-socx-border-light bg-white/90 p-4 dark:border-socx-border-dark dark:bg-socx-panel/40">
                <p className="text-sm font-semibold">Detected IOC types</p>
                <div className="flex flex-wrap gap-2 text-xs">
                  {iocTypeSummary.map(({ type, count }) => (
                    <span key={type} className="rounded-full bg-socx-cloud-soft px-3 py-1 text-socx-ink dark:bg-socx-panel/60 dark:text-white">
                      {type}: {count}
                    </span>
                  ))}
                </div>
                <div className="space-y-2">
                  {iocTypeSummary.map(({ type }) => {
                    const checked = ignoredTypes.includes(type)
                    return (
                      <label key={type} className="flex cursor-pointer items-center justify-between rounded-xl border border-socx-border-light px-3 py-2 text-sm dark:border-socx-border-dark">
                        <span>{`Ignore ${type}`}</span>
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => onTypeToggle(type)}
                          className="h-4 w-4 rounded border-socx-border-light text-socx-accent focus:ring-socx-accent"
                        />
                      </label>
                    )
                  })}
                </div>
              </div>
            )}
          </section>
        </div>

        {message && (
          <div className="rounded-socx-lg border border-socx-border-light bg-socx-cloud-soft/60 px-4 py-3 text-sm text-socx-ink dark:border-socx-border-dark dark:bg-socx-panel/50 dark:text-white">
            {message}
          </div>
        )}

        <section className="space-y-5">
          <div className="rounded-3xl border border-socx-border-light bg-gradient-to-br from-white via-white to-socx-cloud-soft/70 p-6 shadow-sm dark:border-socx-border-dark dark:from-socx-panel/60 dark:via-socx-panel/40 dark:to-socx-night-soft/60">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.3em] text-socx-muted dark:text-socx-muted-dark">
                  IOC results
                </p>
                <h2 className="text-xl font-semibold">Realtime intelligence matrix</h2>
              </div>
              <span className="text-xs text-socx-muted dark:text-socx-muted-dark">
                {iocSummaries.length} tracked IOC{iocSummaries.length === 1 ? "" : "s"}
              </span>
            </div>
            <div className="mt-4 grid gap-3 text-sm sm:grid-cols-4">
              {[
                {
                  label: "Total",
                  value: iocStats.total,
                  tone: "bg-socx-cloud-soft/70 dark:bg-socx-panel/70"
                },
                {
                  label: "Flagged",
                  value: iocStats.flagged,
                  tone: flaggedTone
                },
                {
                  label: "Errors",
                  value: iocStats.errors,
                  tone:
                    iocStats.errors > 0
                      ? "bg-slate-500/20 text-slate-900 dark:text-slate-100"
                      : "bg-socx-cloud-soft/70 dark:bg-socx-panel/70"
                },
                {
                  label: "Pending",
                  value: iocStats.pending,
                  tone:
                    iocStats.pending > 0
                      ? "bg-sky-500/20 text-sky-900 dark:text-sky-100"
                      : "bg-socx-cloud-soft/70 dark:bg-socx-panel/70"
                }
              ].map((item) => (
                <div
                  key={item.label}
                  className={`rounded-2xl px-4 py-3 text-center font-semibold text-socx-ink dark:text-white ${item.tone}`}>
                  <p className="text-xs uppercase tracking-[0.2em] text-socx-muted dark:text-socx-muted-dark">
                    {item.label}
                  </p>
                  <p className="text-2xl">{item.value}</p>
                </div>
              ))}
            </div>
          </div>

          {iocSummaries.length === 0 ? (
            <p className="rounded-2xl border border-dashed border-socx-border-light bg-white/60 px-4 py-3 text-sm text-socx-muted dark:border-socx-border-dark dark:bg-socx-panel/40 dark:text-socx-muted-dark">
              Paste IOCs in the workspace to start tracking their status across services.
            </p>
          ) : (
            <div className="grid gap-4 md:grid-cols-2">
              {iocSummaries.map((entry) => {
                const severity = getSeverityLevel(entry)
                const badgeClass = getBadgeClass(entry)
                const formatted = entry.result ? parseAndFormatResults(entry.result) : ""
                const vtHighlight = buildVirusTotalHighlight(entry)
                const abuseHighlight = buildAbuseHighlight(entry)
                const quickFacts = buildQuickFacts(entry)
                const cardTone = CARD_TONE[severity]
                const flaggedServiceText = entry.serviceStatuses.find((service) => service.status === "flagged")?.text
                const displayStatusText =
                  entry.statusKind === "flagged"
                    ? flaggedServiceText ?? (severity === "high" ? "High risk indicator" : "Suspicious activity")
                    : entry.statusText

                return (
                  <div
                    key={entry.ioc}
                    className={`rounded-3xl border p-5 shadow-sm transition hover:shadow-lg ${cardTone}`}>
                    <div className="flex flex-wrap items-center justify-between gap-4">
                      <div className="min-w-0">
                        <p className="text-xs uppercase tracking-[0.2em] text-socx-muted dark:text-socx-muted-dark">
                          {entry.displayType}
                        </p>
                        <h3 className="text-lg font-semibold break-words">{entry.ioc}</h3>
                      </div>
                      <span className={`rounded-full px-4 py-1 text-xs font-semibold ${badgeClass}`}>
                        {displayStatusText}
                      </span>
                    </div>
                    {entry.isPending && (
                      <p className="mt-1 text-xs text-amber-500">Services still running for this IOC…</p>
                    )}

                    <div className="mt-4 grid gap-4 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
                      <div className="rounded-2xl border border-socx-border-light bg-socx-cloud-soft/40 px-4 py-3 dark:border-socx-border-dark dark:bg-socx-panel/50">
                        <div className="flex items-center justify-between gap-2">
                          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-socx-muted dark:text-socx-muted-dark">
                            Raw intel
                          </p>
                          <button
                            type="button"
                            onClick={() => {
                              if (!formatted) {
                                return
                              }
                              if (!navigator?.clipboard?.writeText) {
                                alert("Clipboard access is not available.")
                                return
                              }
                              navigator.clipboard
                                .writeText(formatted)
                                .catch(() => alert("Unable to copy raw intel."))
                            }}
                            disabled={!formatted}
                            className="inline-flex items-center gap-1 rounded-full border border-socx-border-light px-2.5 py-1 text-[11px] font-semibold text-socx-muted transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-50 dark:border-socx-border-dark">
                            <ClipboardDocumentListIcon className="h-3.5 w-3.5" />
                            Copy
                          </button>
                        </div>
                        <pre className="socx-scroll mt-2 whitespace-pre-wrap break-words break-all rounded-xl bg-white/70 px-3 py-2 text-[11px] text-socx-ink dark:bg-socx-panel/70 dark:text-white">
                          {formatted || "No structured intel yet."}
                        </pre>
                      </div>

                      <div className="space-y-3">
                        <div className="space-y-3">
                          {[vtHighlight, abuseHighlight].map((highlight) => (
                            <div
                              key={`${entry.ioc}-${highlight.label}`}
                              className={`rounded-2xl border ${SERVICE_CARD_TONE[highlight.status]} p-4`}>
                              <div className="flex items-center justify-between text-xs uppercase tracking-[0.2em] text-socx-muted dark:text-socx-muted-dark">
                                <span>{highlight.label}</span>
                                <span
                                  className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${SERVICE_STATUS_PILL[highlight.status]}`}>
                                  {SERVICE_STATUS_LABEL[highlight.status]}
                                </span>
                              </div>
                              <p className="mt-2 text-sm font-semibold">{highlight.headline}</p>
                              <p className="text-xs text-socx-muted dark:text-socx-muted-dark">{highlight.subline}</p>
                              {highlight.meta && (
                                <p className="mt-1 text-[11px] text-socx-muted dark:text-socx-muted-dark">{highlight.meta}</p>
                              )}
                            </div>
                          ))}
                        </div>

                        <div className="rounded-2xl border border-dashed border-socx-border-light px-4 py-3 dark:border-socx-border-dark">
                          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-socx-muted dark:text-socx-muted-dark">
                            Quick facts
                          </p>
                          {quickFacts.length > 0 ? (
                            <div className="mt-2 flex flex-wrap gap-2 text-xs">
                              {quickFacts.map((fact, index) => {
                                const highlight = fact.highlight === true
                                return (
                                  <span
                                    key={`${entry.ioc}-${fact.label}-${index}`}
                                    title={highlight && fact.value ? fact.value : undefined}
                                    className={`rounded-full px-3 py-1 ${
                                      highlight
                                        ? "bg-amber-400/30 text-amber-900 dark:bg-amber-400/20 dark:text-amber-100"
                                        : "bg-socx-cloud-soft text-socx-ink dark:bg-socx-panel/70 dark:text-white"
                                    }`}>
                                    {highlight ? (
                                      fact.label
                                    ) : (
                                      <>
                                        <span className="font-semibold">{fact.label}:</span> {fact.value}
                                      </>
                                    )}
                                  </span>
                                )
                              })}
                            </div>
                          ) : (
                            <p className="mt-2 text-xs text-socx-muted dark:text-socx-muted-dark">
                              No enrichment available yet.
                            </p>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </section>
      </div>
    </div>
  )
}

export default BulkCheckUI
