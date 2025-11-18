import React from "react"
import {
  ArrowDownTrayIcon,
  ArrowPathIcon,
  ClipboardDocumentListIcon,
  PlayCircleIcon,
  TrashIcon
} from "@heroicons/react/24/outline"
import { parseAndFormatResults } from "../utility/utils"

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
}

const riskTone: Record<"low" | "medium" | "high", { border: string; badge: string; label: string }> = {
  low: {
    border: "border-emerald-500/40 bg-emerald-500/5",
    badge: "bg-emerald-500/20 text-emerald-200",
    label: "LOW"
  },
  medium: {
    border: "border-amber-500/40 bg-amber-500/5",
    badge: "bg-amber-500/20 text-amber-200",
    label: "MEDIUM"
  },
  high: {
    border: "border-rose-500/50 bg-rose-500/10",
    badge: "bg-rose-500/20 text-rose-200",
    label: "HIGH"
  }
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
  dailyCounters
}) => {
  const getRiskLevel = (result: any): "low" | "medium" | "high" => {
    const vt = result?.VirusTotal
    const abuse = result?.AbuseIPDB

    let vtLevel: "low" | "medium" | "high" = "low"
    let abuseLevel: "low" | "medium" | "high" = "low"

    if (vt) {
      const stats = vt?.data?.attributes?.last_analysis_stats || {}
      const malicious = stats?.malicious || 0
      const suspicious = stats?.suspicious || 0
      const harmless = stats?.harmless || 0
      const harmlessBonus = Math.min(harmless * 0.2, 5)
      const vtScore = malicious * 3 + suspicious - harmlessBonus

      if (vtScore >= 20) {
        vtLevel = "high"
      } else if (vtScore >= 5 || malicious > 0) {
        // Treat even single malicious verdicts as medium severity.
        vtLevel = "medium"
      }
    }

    if (abuse) {
      const abuseScore = abuse?.data?.abuseConfidenceScore || 0
      const totalReports = Number(abuse?.data?.totalReports) || 0
      if (abuseScore >= 50) {
        abuseLevel = "high"
      } else if (abuseScore >= 20 || totalReports > 0) {
        // Flag all reported IOCs as medium to make them stand out.
        abuseLevel = "medium"
      }
    }

    const levels: Array<"low" | "medium" | "high"> = ["low", "medium", "high"]
    return levels[Math.max(levels.indexOf(vtLevel), levels.indexOf(abuseLevel))]
  }

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

        {results && Object.keys(results).length > 0 && (
          <section className="space-y-4">
            <h2 className="text-xl font-semibold">Results</h2>
            <div className="grid gap-4 md:grid-cols-2">
              {Object.entries(results).map(([ioc, result]) => {
                const level = getRiskLevel(result)
                return (
                  <div
                    key={ioc}
                    className={`rounded-2xl border p-4 shadow-sm ${riskTone[level].border}`}>
                    <div className="flex items-center justify-between">
                      <p className="font-semibold">{ioc}</p>
                      <span className={`rounded-full px-3 py-1 text-xs font-semibold ${riskTone[level].badge}`}>
                        {riskTone[level].label}
                      </span>
                    </div>
                    <pre className="mt-3 whitespace-pre-wrap break-words text-xs text-socx-ink dark:text-socx-muted-dark">
                      {parseAndFormatResults(result)}
                    </pre>
                  </div>
                )
              })}
            </div>
          </section>
        )}
      </div>
    </div>
  )
}

export default BulkCheckUI
