import {
  ArrowDownTrayIcon,
  ArrowPathIcon,
  ClipboardDocumentListIcon,
  PlayCircleIcon,
  ShieldExclamationIcon,
  StopCircleIcon,
  TrashIcon
} from "@heroicons/react/24/outline"
import React, { useMemo, useState } from "react"

import { writeIntelClipboardText } from "../utility/clipboard"
import {
  classifyIntelTextLine,
  getNvdCve,
  getNvdCvss,
  type IntelTone
} from "../utility/intelFormatting"
import {
  formatIOCClipboardEntry,
  parseAndFormatResults
} from "../utility/utils"
import type { BulkCheckSummaryRow, BulkStatusKind } from "./bulk-check.types"
import {
  applyServiceSeverity,
  deriveAbuseSeverity,
  deriveNvdSeverity,
  deriveVirusTotalSeverity,
  extractProxyCheckDetails,
  getSeverityLevel,
  getVerdict,
  isAffirmativeFlag,
  VERDICT_LABEL,
  type BulkVerdict,
  type Severity
} from "./bulk-verdict"

interface BulkCheckUIProps {
  textareaValue: string
  onTextAreaChange: (e: React.ChangeEvent<HTMLTextAreaElement>) => void
  onFileUpload: (e: React.ChangeEvent<HTMLInputElement>) => void
  onFileDrop: (files: FileList | null) => void
  selectedServices: string[]
  onServiceToggle: (service: string, checked: boolean) => void
  onCheckBulk: () => void
  onCancelCheck: () => void
  onRetryFailed: () => void
  failedCount: number
  isCancelling: boolean
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
    nvd: number
    proxy: number
  }
  iocSummaries: BulkCheckSummaryRow[]
}

const SERVICE_STATUS_PILL: Record<HighlightStatus, string> = {
  pending: "bg-slate-500/20 text-slate-100",
  clean: "bg-emerald-500/15 text-emerald-100",
  flagged: "bg-amber-500/15 text-amber-100",
  error: "bg-slate-500/20 text-slate-100",
  skipped:
    "bg-socx-cloud-soft/70 text-socx-muted dark:bg-socx-panel/50 dark:text-socx-muted-dark",
  "flagged-high": "bg-rose-500/30 text-rose-50",
  "flagged-medium": "bg-amber-500/30 text-amber-50"
}

const SERVICE_CARD_TONE: Record<HighlightStatus, string> = {
  pending:
    "border-slate-500/30 bg-slate-500/5 dark:border-slate-400/40 dark:bg-socx-panel/40",
  clean:
    "border-emerald-500/30 bg-emerald-500/5 dark:border-emerald-400/30 dark:bg-emerald-500/10",
  flagged:
    "border-amber-500/30 bg-amber-500/5 dark:border-amber-400/40 dark:bg-amber-500/10",
  error:
    "border-slate-500/40 bg-slate-500/10 dark:border-slate-400/40 dark:bg-slate-700/30",
  skipped:
    "border-socx-border-light bg-socx-cloud-soft/50 dark:border-socx-border-dark dark:bg-socx-panel/40",
  "flagged-high":
    "border-rose-500/40 bg-rose-500/10 dark:border-rose-400/40 dark:bg-rose-500/20",
  "flagged-medium":
    "border-amber-500/40 bg-amber-500/10 dark:border-amber-400/40 dark:bg-amber-500/20"
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
}

const getServiceStatus = (entry: BulkCheckSummaryRow, serviceName: string) =>
  entry.serviceStatuses.find((service) => service.name === serviceName)

const VERDICT_FILTERS: (BulkVerdict | "all")[] = [
  "all",
  "malicious",
  "suspicious",
  "clean",
  "error",
  "pending",
  "skipped"
]

const VERDICT_BADGE: Record<BulkVerdict, string> = {
  malicious: "bg-rose-500/25 text-rose-900 dark:text-rose-100",
  suspicious: "bg-amber-500/25 text-amber-900 dark:text-amber-100",
  clean: "bg-emerald-500/20 text-emerald-900 dark:text-emerald-100",
  pending: "bg-sky-500/20 text-sky-900 dark:text-sky-100",
  error: "bg-slate-500/25 text-slate-900 dark:text-slate-100",
  skipped:
    "bg-socx-cloud-soft/80 text-socx-muted dark:bg-socx-panel/60 dark:text-socx-muted-dark"
}

const INTEL_TEXT_TONE: Record<IntelTone, string> = {
  danger: "text-rose-700 dark:text-rose-300",
  warning: "text-amber-700 dark:text-amber-300",
  success: "text-emerald-700 dark:text-emerald-300",
  neutral: "text-socx-ink dark:text-white"
}

const INTEL_PILL_TONE: Record<IntelTone, string> = {
  danger: "bg-rose-500/15 text-rose-800 dark:bg-rose-500/20 dark:text-rose-200",
  warning:
    "bg-amber-400/20 text-amber-900 dark:bg-amber-400/15 dark:text-amber-100",
  success:
    "bg-emerald-500/15 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-200",
  neutral:
    "bg-socx-cloud-soft text-socx-ink dark:bg-socx-panel/70 dark:text-white"
}

const buildVirusTotalHighlight = (
  entry: BulkCheckSummaryRow
): ServiceHighlight => {
  const status = getServiceStatus(entry, "VirusTotal")
  if (!status) {
    return {
      label: "VirusTotal",
      status: "skipped",
      headline: "Not selected"
    }
  }

  const payload = entry.result?.VirusTotal
  if (payload?.error) {
    return {
      label: "VirusTotal",
      status: "error",
      headline:
        typeof payload.error === "string" ? payload.error : "Fetch failed"
    }
  }

  const attributes = payload?.data?.attributes
  const stats = attributes?.last_analysis_stats
  if (!stats) {
    return {
      label: "VirusTotal",
      status: status.status,
      headline:
        status.status === "pending" ? "Awaiting last analysis..." : status.text
    }
  }

  const malicious = Number(stats.malicious) || 0
  const suspicious = Number(stats.suspicious) || 0

  const severityStatus = applyServiceSeverity(
    status.status,
    deriveVirusTotalSeverity(payload)
  )

  return {
    label: "VirusTotal",
    status: severityStatus,
    headline: `${malicious} malicious • ${suspicious} suspicious`
  }
}

const buildAbuseHighlight = (entry: BulkCheckSummaryRow): ServiceHighlight => {
  const status = getServiceStatus(entry, "AbuseIPDB")
  if (!status) {
    return {
      label: "AbuseIPDB",
      status: "skipped",
      headline: "Not selected"
    }
  }

  const payload = entry.result?.AbuseIPDB
  if (payload?.error) {
    return {
      label: "AbuseIPDB",
      status: "error",
      headline:
        typeof payload.error === "string" ? payload.error : "Fetch failed"
    }
  }

  const data = payload?.data
  if (!data) {
    return {
      label: "AbuseIPDB",
      status: status.status,
      headline:
        status.status === "pending" ? "Awaiting response..." : status.text
    }
  }

  const score = Number(data.abuseConfidenceScore) || 0
  const reports = Number(data.totalReports) || 0

  const severityStatus = applyServiceSeverity(
    status.status,
    deriveAbuseSeverity(payload)
  )

  return {
    label: "AbuseIPDB",
    status: severityStatus,
    headline: `${score}% confidence • ${reports} reports`
  }
}

const buildNvdHighlight = (entry: BulkCheckSummaryRow): ServiceHighlight => {
  const status = getServiceStatus(entry, "NVD")
  if (!status) {
    return { label: "NVD", status: "skipped", headline: "Not selected" }
  }
  const payload = entry.result?.NVD
  if (payload?.error) {
    return {
      label: "NVD",
      status: "error",
      headline:
        typeof payload.error === "string" ? payload.error : "Fetch failed"
    }
  }
  const cve = getNvdCve(payload)
  const cvss = getNvdCvss(payload)
  if (!cve) {
    return {
      label: "NVD",
      status: status.status,
      headline:
        status.status === "pending" ? "Awaiting CVE data..." : status.text
    }
  }
  const headline = cvss
    ? `CVSS ${cvss.score.toFixed(1)} ${cvss.severity || "unrated"}${cve.cisaExploitAdd ? " • CISA KEV" : ""}`
    : `${cve.vulnStatus || "Record found"}${cve.cisaExploitAdd ? " • CISA KEV" : ""}`
  return {
    label: "NVD",
    status: applyServiceSeverity(status.status, deriveNvdSeverity(payload)),
    headline
  }
}

type QuickFact = {
  label: string
  value?: string
  tone?: IntelTone
}

const CARD_TONE: Record<Severity, string> = {
  low: "border-socx-border-light bg-white/95 dark:border-socx-border-dark dark:bg-socx-panel/60",
  medium:
    "border-amber-500/50 bg-white/95 dark:border-amber-400/50 dark:bg-socx-panel/60",
  high: "border-rose-500/50 bg-white/95 dark:border-rose-400/50 dark:bg-socx-panel/60"
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
  const nvdData = entry.result?.NVD
  const nvdCve = getNvdCve(nvdData)
  const nvdCvss = getNvdCvss(nvdData)
  const ipapiData = entry.result?.Ipapi?.data ?? entry.result?.Ipapi
  const { proxyPayload, proxyDetections } = extractProxyCheckDetails(entry)

  const addFact = (
    label: string,
    value: unknown,
    options?: { tone?: IntelTone }
  ) => {
    if (
      value === null ||
      value === undefined ||
      value === "" ||
      value === "N/A"
    ) {
      return
    }
    const payload: QuickFact = {
      label,
      ...(value !== undefined &&
      value !== null &&
      value !== "" &&
      value !== "N/A"
        ? { value: String(value) }
        : {})
    }
    if (options?.tone && options.tone !== "neutral") {
      payload.tone = options.tone
      highlights.push(payload)
    } else {
      payload.tone = options?.tone ?? "neutral"
      regularFacts.push(payload)
    }
  }

  if (nvdCve) {
    addFact(
      "CVSS",
      nvdCvss
        ? `${nvdCvss.score.toFixed(1)} ${nvdCvss.severity || "unrated"}`
        : null,
      {
        tone:
          (nvdCvss?.score ?? 0) >= 7
            ? "danger"
            : (nvdCvss?.score ?? 0) >= 4
              ? "warning"
              : "neutral"
      }
    )
    addFact("Status", nvdCve.vulnStatus)
    if (nvdCve.cisaExploitAdd) {
      addFact("CISA KEV", `Since ${nvdCve.cisaExploitAdd}`, { tone: "danger" })
    }
  }

  addFact(
    "Country",
    abuseData?.countryCode ?? ipapiData?.country_code ?? ipapiData?.country
  )
  addFact("ISP", abuseData?.isp ?? ipapiData?.isp)
  addFact(
    "Domain",
    abuseData?.domain ??
      entry.result?.VirusTotal?.data?.attributes?.meaningful_name ??
      entry.result?.VirusTotal?.data?.attributes?.last_https_certificate
        ?.subject?.CN
  )

  const vpnService =
    ipapiData?.vpn?.service ??
    (ipapiData?.is_vpn === true ? "Detected" : null) ??
    (proxyDetections?.vpn === true ? "Detected" : null)
  if (vpnService) {
    addFact("VPN", vpnService, { tone: "warning" })
  }

  if (ipapiData?.is_tor === true || proxyDetections?.tor === true) {
    addFact("TOR", "Detected", { tone: "warning" })
  }

  const proxyValue = proxyPayload?.proxy ?? proxyDetections?.proxy
  if (proxyValue !== undefined) {
    const proxyDetected = isAffirmativeFlag(proxyValue)
    addFact(
      "Proxy",
      typeof proxyValue === "boolean"
        ? proxyValue
          ? "Detected"
          : "Not detected"
        : proxyValue,
      { tone: proxyDetected ? "warning" : "success" }
    )
  }

  if (abuseData?.isWhitelisted === true) {
    addFact("Whitelisted", "Yes", { tone: "success" })
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
  onFileDrop,
  selectedServices,
  onServiceToggle,
  onCheckBulk,
  onCancelCheck,
  onRetryFailed,
  failedCount,
  isCancelling,
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
  const [verdictFilter, setVerdictFilter] = useState<BulkVerdict | "all">("all")
  const [isDraggingFile, setIsDraggingFile] = useState(false)

  const verdictByIoc = useMemo(() => {
    const map = new Map<string, BulkVerdict>()
    iocSummaries.forEach((entry) => map.set(entry.ioc, getVerdict(entry)))
    return map
  }, [iocSummaries])

  const verdictCounts = useMemo(() => {
    const counts: Record<BulkVerdict, number> = {
      malicious: 0,
      suspicious: 0,
      clean: 0,
      pending: 0,
      error: 0,
      skipped: 0
    }
    verdictByIoc.forEach((verdict) => {
      counts[verdict] += 1
    })
    return counts
  }, [verdictByIoc])

  const visibleSummaries = useMemo(
    () =>
      verdictFilter === "all"
        ? iocSummaries
        : iocSummaries.filter(
            (entry) => verdictByIoc.get(entry.ioc) === verdictFilter
          ),
    [iocSummaries, verdictByIoc, verdictFilter]
  )

  const maliciousSummaries = useMemo(
    () =>
      iocSummaries.filter((entry) => {
        const verdict = verdictByIoc.get(entry.ioc)
        return verdict === "malicious" || verdict === "suspicious"
      }),
    [iocSummaries, verdictByIoc]
  )

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

    const highSeverity = iocSummaries.filter(
      (entry) => getSeverityLevel(entry) === "high"
    ).length
    const mediumSeverity = iocSummaries.filter(
      (entry) => getSeverityLevel(entry) === "medium"
    ).length

    return { total, flagged, errors, pending, highSeverity, mediumSeverity }
  }, [iocSummaries])

  const flaggedNeutralState = useMemo(
    () =>
      iocStats.flagged === 0 && iocStats.errors === 0 && iocStats.pending === 0,
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
  }, [
    flaggedNeutralState,
    iocStats.flagged,
    iocStats.highSeverity,
    iocStats.mediumSeverity
  ])

  return (
    <div className="min-h-screen bg-socx-cloud px-4 py-6 font-inter text-socx-ink dark:bg-socx-night dark:text-white">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
        <header className="rounded-socx-lg border border-socx-border-light bg-white/90 p-6 dark:border-socx-border-dark dark:bg-socx-night-soft/80">
          <p className="text-xs font-semibold uppercase tracking-[0.4em] text-socx-muted dark:text-socx-muted-dark">
            SOCx
          </p>
          <h1 className="mt-1 text-2xl font-semibold">Bulk IOC Check</h1>
          <p className="text-sm text-socx-muted dark:text-socx-muted-dark">
            Paste any list of indicators, auto-categorize them and launch checks
            on your preferred services.
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
            <div
              onDragOver={(event) => {
                event.preventDefault()
                setIsDraggingFile(true)
              }}
              onDragLeave={(event) => {
                event.preventDefault()
                setIsDraggingFile(false)
              }}
              onDrop={(event) => {
                event.preventDefault()
                setIsDraggingFile(false)
                onFileDrop(event.dataTransfer?.files ?? null)
              }}
              className={`relative rounded-2xl transition ${
                isDraggingFile ? "ring-2 ring-socx-accent" : ""
              }`}>
              <textarea
                className="socx-scroll h-72 w-full rounded-2xl border border-socx-border-light bg-white/95 px-4 py-3 text-sm text-socx-ink outline-none transition focus:border-socx-accent focus:ring-2 focus:ring-socx-accent/40 dark:border-socx-border-dark dark:bg-socx-panel/60 dark:text-white"
                placeholder="Paste IPs, domains, hashes, emails, URLs, CVEs — or drop a .txt, .csv, .log or .eml file here"
                value={textareaValue}
                onChange={onTextAreaChange}
              />
              {isDraggingFile && (
                <div className="pointer-events-none absolute inset-0 flex items-center justify-center rounded-2xl bg-socx-accent/15 text-sm font-semibold text-socx-ink dark:text-white">
                  Drop the file to append its indicators
                </div>
              )}
            </div>
            <div className="rounded-2xl border border-socx-border-light bg-white/80 p-4 text-sm dark:border-socx-border-dark dark:bg-socx-panel/50">
              <p className="text-xs font-semibold uppercase tracking-[0.3em] text-socx-muted dark:text-socx-muted-dark">
                Daily counters
              </p>
              <div className="mt-3 grid gap-3 sm:grid-cols-4">
                {[
                  { label: "VirusTotal", value: dailyCounters.vt },
                  { label: "AbuseIPDB", value: dailyCounters.abuse },
                  { label: "NVD", value: dailyCounters.nvd },
                  { label: "ProxyCheck", value: dailyCounters.proxy }
                ].map((counter) => (
                  <div
                    key={counter.label}
                    className="rounded-xl border border-dashed border-socx-border-light px-3 py-2 text-center text-sm dark:border-socx-border-dark">
                    <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
                      {counter.label}
                    </p>
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
                Import a file
              </label>
              <input
                type="file"
                accept=".txt,.csv,.tsv,.log,.eml,.json,.md,text/plain"
                multiple
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
              {isLoading ? (
                <button
                  type="button"
                  onClick={onCancelCheck}
                  disabled={isCancelling}
                  className="flex w-full items-center justify-center gap-2 rounded-full border border-socx-danger px-4 py-3 text-sm font-semibold text-socx-danger transition hover:bg-socx-danger/10 focus-visible:outline-none focus-visible:shadow-socx-focus disabled:cursor-not-allowed disabled:opacity-60">
                  <StopCircleIcon className="h-5 w-5" />
                  {isCancelling ? "Cancelling…" : "Cancel analysis"}
                </button>
              ) : (
                <button
                  type="button"
                  onClick={onCheckBulk}
                  className="flex w-full items-center justify-center gap-2 rounded-full bg-socx-accent px-4 py-3 text-sm font-semibold text-socx-ink transition hover:bg-socx-accent-strong focus-visible:outline-none focus-visible:shadow-socx-focus">
                  <PlayCircleIcon className="h-5 w-5" />
                  Run analysis
                </button>
              )}
              <button
                type="button"
                onClick={onRetryFailed}
                disabled={isLoading || failedCount === 0}
                className="inline-flex w-full items-center justify-center gap-2 rounded-full border border-socx-border-light px-4 py-2 text-sm font-semibold text-socx-ink transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-40 dark:border-socx-border-dark dark:text-white">
                <ArrowPathIcon className="h-4 w-4" />
                {failedCount > 0
                  ? `Retry ${failedCount} failed IOC${failedCount === 1 ? "" : "s"}`
                  : "Retry failed"}
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
                  onClick={async () => {
                    const formatted = Object.entries(results)
                      .map(([ioc, result]) =>
                        formatIOCClipboardEntry(ioc, result)
                      )
                      .filter(Boolean)
                      .join("\n")

                    if (formatted) {
                      await writeIntelClipboardText(formatted, {
                        successMessage: "✔️ Formatted IOCs copied to clipboard"
                      })
                    } else {
                      alert("No formatted results available to copy.")
                    }
                  }}
                  disabled={Object.keys(results).length === 0}
                  className="inline-flex items-center justify-center gap-2 rounded-full border border-socx-border-light px-4 py-2 text-sm font-semibold text-socx-ink transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-40 dark:border-socx-border-dark dark:text-white">
                  <ClipboardDocumentListIcon className="h-4 w-4" />
                  Copy formatted
                </button>
                <button
                  type="button"
                  onClick={async () => {
                    // Only the indicators that carry a verdict worth escalating,
                    // ready to be pasted into a ticket.
                    const formatted = maliciousSummaries
                      .map((entry) =>
                        formatIOCClipboardEntry(entry.ioc, entry.result)
                      )
                      .filter(Boolean)
                      .join("\n")

                    if (formatted) {
                      await writeIntelClipboardText(formatted, {
                        successMessage: `✔️ ${maliciousSummaries.length} flagged IOC${
                          maliciousSummaries.length === 1 ? "" : "s"
                        } copied`
                      })
                    }
                  }}
                  disabled={maliciousSummaries.length === 0}
                  className="inline-flex items-center justify-center gap-2 rounded-full border border-rose-500/50 px-4 py-2 text-sm font-semibold text-rose-700 transition hover:border-rose-500 hover:bg-rose-500/10 disabled:cursor-not-allowed disabled:opacity-40 dark:text-rose-300">
                  <ShieldExclamationIcon className="h-4 w-4" />
                  Copy flagged
                  {maliciousSummaries.length > 0
                    ? ` (${maliciousSummaries.length})`
                    : ""}
                </button>
              </div>
            </div>

            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.3em] text-socx-muted dark:text-socx-muted-dark">
                Services
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                {["VirusTotal", "AbuseIPDB", "NVD"].map((service) => {
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
                    <span
                      key={type}
                      className="rounded-full bg-socx-cloud-soft px-3 py-1 text-socx-ink dark:bg-socx-panel/60 dark:text-white">
                      {type}: {count}
                    </span>
                  ))}
                </div>
                <div className="space-y-2">
                  {iocTypeSummary.map(({ type }) => {
                    const checked = ignoredTypes.includes(type)
                    return (
                      <label
                        key={type}
                        className="flex cursor-pointer items-center justify-between rounded-xl border border-socx-border-light px-3 py-2 text-sm dark:border-socx-border-dark">
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
                <h2 className="text-xl font-semibold">
                  Realtime intelligence matrix
                </h2>
              </div>
              <span className="text-xs text-socx-muted dark:text-socx-muted-dark">
                {iocSummaries.length} tracked IOC
                {iocSummaries.length === 1 ? "" : "s"}
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
            <div className="mt-4 flex flex-wrap items-center gap-2">
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-socx-muted dark:text-socx-muted-dark">
                Verdict
              </p>
              {VERDICT_FILTERS.map((filter) => {
                const count =
                  filter === "all" ? iocSummaries.length : verdictCounts[filter]
                const active = verdictFilter === filter
                return (
                  <button
                    type="button"
                    key={filter}
                    onClick={() => setVerdictFilter(filter)}
                    aria-pressed={active}
                    className={`socx-chip ${
                      active
                        ? "socx-chip-active"
                        : "border-socx-border-light bg-white/90 dark:border-socx-border-dark dark:bg-socx-panel/40"
                    }`}>
                    {filter === "all" ? "All" : VERDICT_LABEL[filter]} ({count})
                  </button>
                )
              })}
            </div>
          </div>

          {iocSummaries.length === 0 ? (
            <p className="rounded-2xl border border-dashed border-socx-border-light bg-white/60 px-4 py-3 text-sm text-socx-muted dark:border-socx-border-dark dark:bg-socx-panel/40 dark:text-socx-muted-dark">
              Paste IOCs in the workspace to start tracking their status across
              services.
            </p>
          ) : visibleSummaries.length === 0 ? (
            <p className="rounded-2xl border border-dashed border-socx-border-light bg-white/60 px-4 py-3 text-sm text-socx-muted dark:border-socx-border-dark dark:bg-socx-panel/40 dark:text-socx-muted-dark">
              No IOC matches the {VERDICT_LABEL[verdictFilter as BulkVerdict]}{" "}
              verdict.
            </p>
          ) : (
            <div className="grid gap-4 md:grid-cols-2">
              {visibleSummaries.map((entry) => {
                const severity = getSeverityLevel(entry)
                const verdict = verdictByIoc.get(entry.ioc) ?? "skipped"
                const badgeClass = getBadgeClass(entry)
                const formatted = entry.result
                  ? parseAndFormatResults(entry.result)
                  : ""
                const clipboardFormatted = entry.result
                  ? formatIOCClipboardEntry(entry.ioc, entry.result)
                  : ""
                const vtHighlight = buildVirusTotalHighlight(entry)
                const abuseHighlight = buildAbuseHighlight(entry)
                const nvdHighlight = buildNvdHighlight(entry)
                const quickFacts = buildQuickFacts(entry)
                const cardTone = CARD_TONE[severity]
                const flaggedServiceText = entry.serviceStatuses.find(
                  (service) => service.status === "flagged"
                )?.text
                const displayStatusText =
                  entry.statusKind === "flagged"
                    ? (flaggedServiceText ??
                      (severity === "high"
                        ? "High risk indicator"
                        : "Suspicious activity"))
                    : entry.statusText

                return (
                  <div
                    key={entry.ioc}
                    className={`rounded-3xl border p-5 shadow-sm transition hover:shadow-lg ${cardTone}`}>
                    <div className="flex flex-wrap items-center justify-between gap-4">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span
                            className={`rounded-full px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-[0.15em] ${VERDICT_BADGE[verdict]}`}>
                            {VERDICT_LABEL[verdict]}
                          </span>
                          <p className="text-xs uppercase tracking-[0.2em] text-socx-muted dark:text-socx-muted-dark">
                            {entry.displayType}
                          </p>
                        </div>
                        <h3 className="mt-1 text-lg font-semibold break-words">
                          {entry.ioc}
                        </h3>
                      </div>
                      <span
                        className={`rounded-full px-4 py-1 text-xs font-semibold ${badgeClass}`}>
                        {displayStatusText}
                      </span>
                    </div>
                    {entry.isPending && (
                      <p className="mt-1 text-xs text-amber-500">
                        Services still running for this IOC…
                      </p>
                    )}

                    <div className="mt-4 grid gap-4 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
                      <div className="rounded-2xl border border-socx-border-light bg-socx-cloud-soft/40 px-4 py-3 dark:border-socx-border-dark dark:bg-socx-panel/50">
                        <div className="flex items-center justify-between gap-2">
                          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-socx-muted dark:text-socx-muted-dark">
                            Raw intel
                          </p>
                          <button
                            type="button"
                            onClick={async () => {
                              if (!clipboardFormatted) {
                                return
                              }
                              await writeIntelClipboardText(
                                clipboardFormatted,
                                {
                                  successMessage: "✔️ Raw intelligence copied"
                                }
                              )
                            }}
                            disabled={!clipboardFormatted}
                            className="inline-flex items-center gap-1 rounded-full border border-socx-border-light px-2.5 py-1 text-[11px] font-semibold text-socx-muted transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-50 dark:border-socx-border-dark">
                            <ClipboardDocumentListIcon className="h-3.5 w-3.5" />
                            Copy
                          </button>
                        </div>
                        <pre className="socx-scroll mt-2 whitespace-pre-wrap break-words break-all rounded-xl bg-white/70 px-3 py-2 text-[11px] dark:bg-socx-panel/70">
                          {formatted ? (
                            formatted.split("\n").map((line, index) => (
                              <span
                                key={`${entry.ioc}-intel-line-${index}`}
                                className={`block ${INTEL_TEXT_TONE[classifyIntelTextLine(line)]}`}>
                                {line || " "}
                              </span>
                            ))
                          ) : (
                            <span className={INTEL_TEXT_TONE.neutral}>
                              No structured intel yet.
                            </span>
                          )}
                        </pre>
                      </div>

                      <div className="space-y-3">
                        <div className="space-y-3">
                          {[vtHighlight, abuseHighlight, nvdHighlight].map(
                            (highlight) => (
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
                                <p className="mt-2 text-sm font-semibold">
                                  {highlight.headline}
                                </p>
                              </div>
                            )
                          )}
                        </div>

                        <div className="rounded-2xl border border-dashed border-socx-border-light px-4 py-3 dark:border-socx-border-dark">
                          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-socx-muted dark:text-socx-muted-dark">
                            Quick facts
                          </p>
                          {quickFacts.length > 0 ? (
                            <div className="mt-2 flex flex-wrap gap-2 text-xs">
                              {quickFacts.map((fact, index) => {
                                const tone = fact.tone ?? "neutral"
                                return (
                                  <span
                                    key={`${entry.ioc}-${fact.label}-${index}`}
                                    className={`rounded-full px-3 py-1 ${INTEL_PILL_TONE[tone]}`}>
                                    <span className="font-semibold">
                                      {fact.label}:
                                    </span>{" "}
                                    {fact.value}
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
