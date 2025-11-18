import React, { useCallback, useEffect, useMemo, useState } from "react"
import { Storage } from "@plasmohq/storage"
import { sendToBackground } from "@plasmohq/messaging"
import "../styles/tailwind.css"
import {
  ArrowDownTrayIcon,
  ArrowPathIcon,
  ClipboardDocumentListIcon,
  PlayCircleIcon,
  TrashIcon
} from "@heroicons/react/24/outline"
import type { NormalizedSubnet, SubnetCheckSummaryRow } from "../utility/utils"
import {
  estimateSubnetHostCount,
  exportSubnetCheckToExcel,
  extractSubnetsFromText,
  formatHostCount,
  formatSubnetCheckClipboard,
  isPrivateIP
} from "../utility/utils"
import { ensureIsDarkMode, persistIsDarkMode } from "../utility/theme"

type SubnetCheckResult = {
  reportedCount?: number
  data?: any
  error?: string
  isPrivate?: boolean
  ipDetails?: any
}

const storage = new Storage({ area: "local" })

const PREFILL_KEY = "subnetCheckPrefill"
const INPUT_KEY = "subnetCheckInput"
const LOOKBACK_DAYS = 30

const clampConfidenceInput = (value: number): number => {
  if (!Number.isFinite(value)) {
    return 0
  }
  const rounded = Math.round(value)
  return Math.min(Math.max(rounded, 0), 100)
}

const getTodayDateString = (): string => new Date().toISOString().split("T")[0]
const getAbuseDailyKey = (): string => `Abuse_${getTodayDateString()}`

const hasClipboardAccess = (): boolean =>
  typeof navigator !== "undefined" && Boolean(navigator.clipboard?.writeText)

const applyDocumentTheme = (isDarkMode: boolean): void => {
  if (typeof document === "undefined") {
    return
  }
  document.body.className = isDarkMode ? "dark-mode" : "light-mode"
}

const readAbuseCounter = async (): Promise<number> => {
  if (typeof chrome === "undefined" || !chrome.storage?.local?.get) {
    return 0
  }

  const key = getAbuseDailyKey()
  return new Promise((resolve) => {
    chrome.storage.local.get([key], (items) => {
      const rawValue = items?.[key]
      resolve(typeof rawValue === "number" ? rawValue : 0)
    })
  })
}

const STATUS_BADGE_MAP: Record<SubnetCheckSummaryRow["statusKind"], string> = {
  flagged: "bg-amber-500/15 text-amber-100",
  error: "bg-rose-500/15 text-rose-100",
  private: "bg-slate-500/20 text-slate-200",
  clean: "bg-emerald-500/15 text-emerald-100",
  pending: "bg-socx-muted/10 text-socx-muted-dark"
}

const getStatusBadgeClass = (entry: SubnetCheckSummaryRow) =>
  STATUS_BADGE_MAP[entry.statusKind] ?? STATUS_BADGE_MAP.pending

const resolveStatusDescriptor = (
  payload: SubnetCheckResult | undefined,
  isPrivateSubnet: boolean,
  reportedCount: number,
  isLoading: boolean
): Pick<SubnetCheckSummaryRow, "statusKind" | "statusText"> => {
  if (isPrivateSubnet) {
    return {
      statusKind: "private",
      statusText: payload?.error ?? "Private subnet - not checked"
    }
  }

  if (payload?.error) {
    return {
      statusKind: "error",
      statusText: payload.error
    }
  }

  if (reportedCount > 0) {
    return {
      statusKind: "flagged",
      statusText: reportedCount === 1 ? "1 IP reported" : `${reportedCount} IPs reported`
    }
  }

  if (payload) {
    return {
      statusKind: "clean",
      statusText: "No reports"
    }
  }

  return {
    statusKind: "pending",
    statusText: isLoading ? "Pending check..." : "Awaiting check"
  }
}

const dedupeNormalizedSubnets = (entries: NormalizedSubnet[]): NormalizedSubnet[] => {
  const seen = new Set<string>()
  return entries.filter((entry) => {
    if (seen.has(entry.subnet)) {
      return false
    }
    seen.add(entry.subnet)
    return true
  })
}

const SubnetCheck = () => {
  const [textareaValue, setTextareaValue] = useState("")
  const [subnets, setSubnets] = useState<NormalizedSubnet[]>([])
  const [results, setResults] = useState<Record<string, SubnetCheckResult>>({})
  const [isLoading, setIsLoading] = useState(false)
  const [message, setMessage] = useState<string>("")
  const [isDarkMode, setIsDarkMode] = useState(true)
  const [themeLoaded, setThemeLoaded] = useState(false)
  const [confidenceMinimum, setConfidenceMinimum] = useState(0)
  const [abuseDailyCount, setAbuseDailyCount] = useState(0)

  const refreshAbuseCounter = useCallback(async () => {
    const nextCount = await readAbuseCounter()
    setAbuseDailyCount(nextCount)
  }, [])

  useEffect(() => {
    const loadInitialState = async () => {
      try {
        const [savedInput, prefill, savedConfidence, savedTheme] = await Promise.all([
          storage.get<string>(INPUT_KEY),
          storage.get<string[]>(PREFILL_KEY),
          storage.get<number>("subnetCheckConfidence"),
          ensureIsDarkMode()
        ])

        const initialList = Array.isArray(prefill) && prefill.length > 0
          ? prefill.join("\n")
          : typeof savedInput === "string"
            ? savedInput
            : ""

        if (initialList) {
          setTextareaValue(initialList)
        }

        if (Array.isArray(prefill) && prefill.length > 0) {
          await storage.remove(PREFILL_KEY)
        }

        if (typeof savedConfidence === "number") {
          setConfidenceMinimum(clampConfidenceInput(savedConfidence))
        }

        setIsDarkMode(savedTheme)
      } catch (error) {
        console.error("Failed to load initial subnet-check state:", error)
      } finally {
        setThemeLoaded(true)
      }
    }

    loadInitialState()
  }, [])

  useEffect(() => {
    storage.set(INPUT_KEY, textareaValue)
  }, [textareaValue])

  useEffect(() => {
    storage.set("subnetCheckConfidence", confidenceMinimum)
  }, [confidenceMinimum])

  useEffect(() => {
    if (!themeLoaded) {
      return
    }
    persistIsDarkMode(isDarkMode)
    applyDocumentTheme(isDarkMode)
  }, [isDarkMode, themeLoaded])

  useEffect(() => {
    refreshAbuseCounter()
  }, [refreshAbuseCounter])

  useEffect(() => {
    if (typeof chrome === "undefined" || !chrome.storage?.onChanged) {
      return
    }

    const listener: Parameters<typeof chrome.storage.onChanged.addListener>[0] = (changes, area) => {
      if (area !== "local") {
        return
      }

      if (Object.prototype.hasOwnProperty.call(changes, "isDarkMode")) {
        const next = changes.isDarkMode?.newValue
        if (typeof next === "boolean") {
          setIsDarkMode(next)
        }
      }

      const abuseKey = getAbuseDailyKey()
      if (Object.prototype.hasOwnProperty.call(changes, abuseKey)) {
        const nextCount = changes[abuseKey]?.newValue
        if (typeof nextCount === "number") {
          setAbuseDailyCount(nextCount)
        }
      }
    }

    chrome.storage.onChanged.addListener(listener)
    return () => chrome.storage.onChanged.removeListener(listener)
  }, [])

  const handleTextAreaChange = useCallback((event: React.ChangeEvent<HTMLTextAreaElement>) => {
    setTextareaValue(event.target.value)
  }, [])

  const collectUniqueSubnets = useCallback(() => {
    const parsed = extractSubnetsFromText(textareaValue)
    return dedupeNormalizedSubnets(parsed)
  }, [textareaValue])

  const handleRefreshSubnets = useCallback(() => {
    const uniqueParsed = collectUniqueSubnets()
    if (uniqueParsed.length === 0) {
      setTextareaValue("")
      setSubnets([])
      setResults({})
      setMessage("No valid subnets detected in the provided text.")
      return
    }

    const normalizedText = uniqueParsed.map((entry) => entry.subnet).join("\n")
    setTextareaValue(normalizedText)
    setSubnets([])
    setResults({})
    setMessage(`Detected ${uniqueParsed.length} unique subnet${uniqueParsed.length === 1 ? "" : "s"}.`)
  }, [collectUniqueSubnets])

  const handleFileUpload = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) {
      return
    }

    const reader = new FileReader()
    reader.onload = (loadEvent) => {
      const content = typeof loadEvent.target?.result === "string" ? loadEvent.target.result : ""
      if (!content) {
        setMessage("The selected file was empty.")
      }
      setTextareaValue(content)
    }
    reader.onerror = () => {
      setMessage("Unable to read the selected file.")
    }
    reader.readAsText(file)
    event.target.value = ""
  }, [])

  const handleClear = useCallback(() => {
    setTextareaValue("")
    setSubnets([])
    setResults({})
    setMessage("")
  }, [])

  const handleConfidenceChange = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    setConfidenceMinimum(clampConfidenceInput(Number(event.target.value)))
  }, [])

  const handleCheck = useCallback(async () => {
    const uniqueParsed = collectUniqueSubnets()
    if (uniqueParsed.length === 0) {
      setSubnets([])
      setResults({})
      setMessage("Add at least one valid subnet in the text area before running the check.")
      return
    }

    setSubnets(uniqueParsed)
    setResults({})
    setIsLoading(true)
    setMessage("Checking subnets on AbuseIPDB...")

    try {
      const body = {
        subnets: uniqueParsed.map((entry) => entry.subnet),
        maxAgeInDays: LOOKBACK_DAYS,
        confidenceMinimum: confidenceMinimum > 0 ? confidenceMinimum : undefined
      }

      const response = await sendToBackground<
        { subnets: string[]; maxAgeInDays: number; confidenceMinimum?: number },
        { results?: Record<string, SubnetCheckResult> }
      >({
        name: "check-subnet-abuse",
        body
      })

      setResults(response?.results ?? {})
      setMessage("Check completed.")
      await refreshAbuseCounter()
    } catch (error) {
      console.error("Subnet check failed:", error)
      setMessage("Unable to complete the check. Please try again.")
    } finally {
      setIsLoading(false)
    }
  }, [collectUniqueSubnets, confidenceMinimum, refreshAbuseCounter])

  const summarizedResults = useMemo<SubnetCheckSummaryRow[]>(
    () =>
      subnets.map((entry) => {
        const payload = results[entry.subnet]
        const hostCount = formatHostCount(estimateSubnetHostCount(entry.version, entry.prefix))
        const subnetData = payload?.data?.data
        const reports = Array.isArray(subnetData?.reportedAddress) ? subnetData.reportedAddress : null
        const firstReport = reports?.[0] ?? null
        const ipFallback = payload?.ipDetails?.data
        const minAddress = subnetData?.minAddress
        const maxAddress = subnetData?.maxAddress
        const reportedCount = payload?.reportedCount ?? (reports?.length ?? 0)
        const baseAddress = entry.subnet.split("/")[0] ?? ""
        const isPrivateSubnet = payload?.isPrivate ?? isPrivateIP(baseAddress)
        const { statusKind, statusText } = resolveStatusDescriptor(payload, isPrivateSubnet, reportedCount, isLoading)

        const isp = firstReport?.isp ?? subnetData?.isp ?? ipFallback?.isp ?? null
        const country = firstReport?.countryCode ?? subnetData?.countryCode ?? ipFallback?.countryCode ?? null
        const usageType = firstReport?.usageType ?? subnetData?.usageType ?? ipFallback?.usageType ?? null
        const domain = subnetData?.domain ?? firstReport?.domain ?? ipFallback?.domain ?? null

        const hostnames = Array.isArray(subnetData?.hostnames) && subnetData.hostnames.length > 0
          ? subnetData.hostnames
          : Array.isArray(firstReport?.hostnames) && firstReport.hostnames.length > 0
            ? firstReport.hostnames
            : Array.isArray(ipFallback?.hostnames) && ipFallback.hostnames.length > 0
              ? ipFallback.hostnames
              : null

        return {
          subnet: entry.subnet,
          version: entry.version,
          prefix: entry.prefix,
          hostCount,
          mostRecent: getMostRecentReport(payload?.data),
          minAddress,
          maxAddress,
          reportedCount,
          distinctIpCount: reports?.length ?? null,
          isPrivate: isPrivateSubnet,
          statusText,
          statusKind,
          error: payload?.error ?? null,
          isp,
          country,
          usageType,
          domain,
          hostnames
        }
      }),
    [isLoading, results, subnets]
  )

  const flaggedTotal = useMemo(
    () => summarizedResults.filter((entry) => entry.statusKind === "flagged").length,
    [summarizedResults]
  )

  const totalIpv4 = useMemo(() => subnets.filter((entry) => entry.version === 4).length, [subnets])
  const totalIpv6 = useMemo(() => subnets.filter((entry) => entry.version === 6).length, [subnets])

  const handleCopyResults = useCallback(async () => {
    if (summarizedResults.length === 0) {
      setMessage("There are no results to copy yet.")
      return
    }

    if (!hasClipboardAccess()) {
      setMessage("Clipboard access is not available in this context.")
      return
    }

    try {
      const payload = formatSubnetCheckClipboard(summarizedResults)
      if (!payload) {
        setMessage("There are no results to copy yet.")
        return
      }
      await navigator.clipboard.writeText(payload)
      setMessage("Subnet report copied to clipboard.")
    } catch (error) {
      console.error("Copy failed:", error)
      setMessage("Unable to copy the subnet report.")
    }
  }, [summarizedResults])

  const handleExportResults = useCallback(() => {
    if (summarizedResults.length === 0) {
      setMessage("There are no results to export yet.")
      return
    }

    try {
      exportSubnetCheckToExcel(summarizedResults)
      setMessage("Subnet report exported to Excel.")
    } catch (error) {
      console.error("Export failed:", error)
      setMessage("Unable to export the subnet report.")
    }
  }, [summarizedResults])

  return (
    <div className="min-h-screen bg-socx-cloud px-4 py-6 font-inter text-socx-ink dark:bg-socx-night dark:text-white">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
        <header className="rounded-socx-lg border border-socx-border-light bg-white/90 p-6 dark:border-socx-border-dark dark:bg-socx-night-soft/80">
          <p className="text-xs font-semibold uppercase tracking-[0.4em] text-socx-muted dark:text-socx-muted-dark">
            SOCx
          </p>
          <h1 className="mt-1 text-2xl font-semibold">Subnet Abuse Check</h1>
          <p className="text-sm text-socx-muted dark:text-socx-muted-dark">
            Launch AbuseIPDB scoped checks for IPv4/IPv6 ranges, track flagged blocks and copy actionable reports.
          </p>
        </header>

        <div className="grid gap-6 lg:grid-cols-2">
          <section className="space-y-4 rounded-socx-lg border border-socx-border-light bg-white/90 p-5 dark:border-socx-border-dark dark:bg-socx-night-soft/80">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold">Enter IPv4/IPv6 subnets</p>
                <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
                  Accepts CIDR ranges per line, will auto-normalize duplicates.
                </p>
              </div>
              <button
                type="button"
                onClick={handleRefreshSubnets}
                disabled={isLoading || !textareaValue.trim()}
                className="inline-flex items-center gap-1 rounded-full border border-socx-border-light px-3 py-1 text-xs font-semibold text-socx-muted transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-40 dark:border-socx-border-dark">
                <ArrowPathIcon className="h-4 w-4" />
                Refresh
              </button>
            </div>
            <textarea
              rows={16}
              value={textareaValue}
              onChange={handleTextAreaChange}
              placeholder={"Example: 192.168.10.0/24\n2001:db8::/48"}
              className="socx-scroll w-full rounded-2xl border border-socx-border-light bg-white/95 px-4 py-3 text-sm text-socx-ink outline-none transition focus:border-socx-accent focus:ring-2 focus:ring-socx-accent/40 dark:border-socx-border-dark dark:bg-socx-panel/60 dark:text-white"
            />

            <div className="rounded-2xl border border-socx-border-light bg-white/80 p-4 dark:border-socx-border-dark dark:bg-socx-panel/40">
              <p className="text-xs font-semibold uppercase tracking-[0.3em] text-socx-muted dark:text-socx-muted-dark">
                Summary
              </p>
              <div className="mt-3 flex flex-wrap gap-2 text-xs">
                <span className="rounded-full bg-socx-cloud-soft px-3 py-1 text-socx-ink dark:bg-socx-panel/40 dark:text-white">
                  Total {subnets.length}
                </span>
                <span className="rounded-full bg-emerald-500/20 px-3 py-1 text-emerald-100">
                  IPv4 {totalIpv4}
                </span>
                <span className="rounded-full bg-sky-500/20 px-3 py-1 text-sky-100">
                  IPv6 {totalIpv6}
                </span>
                <span className="rounded-full bg-amber-500/20 px-3 py-1 text-amber-100">
                  Flagged {flaggedTotal}
                </span>
                <span className="rounded-full bg-rose-500/20 px-3 py-1 text-rose-100">
                  AbuseIPDB today {abuseDailyCount}
                </span>
              </div>
            </div>
          </section>

          <section className="space-y-4 rounded-socx-lg border border-socx-border-light bg-white/90 p-5 dark:border-socx-border-dark dark:bg-socx-night-soft/80">
            <div className="space-y-1">
              <label className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.3em] text-socx-muted dark:text-socx-muted-dark">
                <ArrowDownTrayIcon className="h-4 w-4" />
                Upload .txt file
              </label>
              <input
                type="file"
                accept=".txt"
                onChange={handleFileUpload}
                className="block w-full text-sm text-socx-muted file:mr-4 file:rounded-full file:border-0 file:bg-socx-accent file:px-4 file:py-2 file:text-sm file:font-semibold file:text-socx-ink hover:file:bg-socx-accent-strong"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs font-semibold uppercase tracking-[0.3em] text-socx-muted dark:text-socx-muted-dark">
                Confidence minimum
              </label>
              <input
                type="number"
                min={0}
                max={100}
                value={confidenceMinimum}
                onChange={handleConfidenceChange}
                className="w-full rounded-xl border border-socx-border-light bg-white/90 px-3 py-2 text-sm text-socx-ink outline-none focus:border-socx-accent focus:ring-2 focus:ring-socx-accent/40 dark:border-socx-border-dark dark:bg-socx-panel/50 dark:text-white"
                inputMode="numeric"
              />
              <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
                Reports limited to the last {LOOKBACK_DAYS} days.
              </p>
            </div>

            <div className="grid gap-2 sm:grid-cols-2">
              <button
                type="button"
                onClick={handleCheck}
                disabled={isLoading}
                className="inline-flex items-center justify-center gap-2 rounded-full bg-socx-accent px-4 py-3 text-sm font-semibold text-socx-ink transition hover:bg-socx-accent-strong disabled:cursor-not-allowed disabled:opacity-40">
                <PlayCircleIcon className="h-5 w-5" />
                {isLoading ? "Checking…" : "Run AbuseIPDB Check"}
              </button>
              <button
                type="button"
                onClick={handleClear}
                disabled={isLoading}
                className="inline-flex items-center justify-center gap-2 rounded-full border border-socx-border-light px-4 py-3 text-sm font-semibold text-socx-ink transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-40 dark:border-socx-border-dark dark:text-white">
                <TrashIcon className="h-4 w-4" />
                Clear subnets
              </button>
              <button
                type="button"
                onClick={handleCopyResults}
                disabled={summarizedResults.length === 0}
                className="inline-flex items-center justify-center gap-2 rounded-full border border-socx-border-light px-4 py-3 text-sm font-semibold text-socx-ink transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-40 dark:border-socx-border-dark dark:text-white">
                <ClipboardDocumentListIcon className="h-4 w-4" />
                Copy report
              </button>
              <button
                type="button"
                onClick={handleExportResults}
                disabled={summarizedResults.length === 0}
                className="inline-flex items-center justify-center gap-2 rounded-full border border-socx-border-light px-4 py-3 text-sm font-semibold text-socx-ink transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-40 dark:border-socx-border-dark dark:text-white">
                <ArrowDownTrayIcon className="h-4 w-4" />
                Export Excel (.xlsx)
              </button>
            </div>

            {message && (
              <div className="rounded-2xl border border-socx-border-light bg-white/80 px-4 py-3 text-sm text-socx-ink dark:border-socx-border-dark dark:bg-socx-panel/40 dark:text-white">
                {message}
              </div>
            )}
          </section>
        </div>

        <section className="rounded-socx-lg border border-socx-border-light bg-white/90 p-5 dark:border-socx-border-dark dark:bg-socx-night-soft/80">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.3em] text-socx-muted dark:text-socx-muted-dark">
                AbuseIPDB results
              </p>
              <h2 className="text-xl font-semibold">Subnet intelligence matrix</h2>
            </div>
            <span className="text-sm text-socx-muted dark:text-socx-muted-dark">
              {summarizedResults.length} entries
            </span>
          </div>

          {subnets.length === 0 ? (
            <p className="mt-4 text-sm text-socx-muted dark:text-socx-muted-dark">
              Enter at least one subnet to start the analysis.
            </p>
          ) : (
            <div className="mt-4 overflow-x-auto">
              <table className="w-full min-w-[720px] text-left text-sm">
                <thead>
                  <tr className="text-xs uppercase tracking-[0.2em] text-socx-muted dark:text-socx-muted-dark">
                    <th className="py-3">Subnet</th>
                    <th className="py-3">Version</th>
                    <th className="py-3">Hosts</th>
                    <th className="py-3">Reported IPs</th>
                    <th className="py-3">Most recent</th>
                    <th className="py-3">Details</th>
                    <th className="py-3">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {summarizedResults.map((entry) => {
                    const badgeClass = getStatusBadgeClass(entry)
                    const hasDistinctIps = typeof entry.distinctIpCount === "number" && entry.distinctIpCount > 0
                    const hasOtherIntel = Boolean(
                      entry.country || entry.isp || entry.usageType || entry.domain || (entry.hostnames && entry.hostnames.length)
                    )
                    const hasIntel = hasDistinctIps || hasOtherIntel

                    return (
                      <tr key={entry.subnet} className="border-t border-socx-border-light dark:border-socx-border-dark">
                        <td className="py-3">
                          <p className="font-semibold">{entry.subnet}</p>
                          <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
                            {entry.minAddress && entry.maxAddress
                              ? `${entry.minAddress} → ${entry.maxAddress}`
                              : entry.version === 4
                                ? "IPv4 block"
                                : "IPv6 block"}
                          </p>
                        </td>
                        <td className="py-3">IPv{entry.version}</td>
                        <td className="py-3">{formatHostCount(entry.hostCount)}</td>
                        <td className="py-3">
                          <span
                            className={`rounded-full px-3 py-1 text-xs font-semibold ${
                              entry.reportedCount > 0 ? "bg-rose-500/20 text-rose-100" : "bg-slate-500/20 text-slate-200"
                            }`}>
                            {entry.reportedCount}
                          </span>
                        </td>
                        <td className="py-3">{entry.mostRecent ?? "—"}</td>
                        <td className="py-3 text-xs text-socx-muted dark:text-socx-muted-dark">
                          {hasDistinctIps && <div>Distinct IPs: {entry.distinctIpCount}</div>}
                          {entry.country && <div>Country: {entry.country}</div>}
                          {entry.isp && <div>ISP: {entry.isp}</div>}
                          {entry.usageType && <div>Usage: {entry.usageType}</div>}
                          {entry.domain && <div>Domain: {entry.domain}</div>}
                          {Array.isArray(entry.hostnames) && entry.hostnames.length > 0 && (
                            <div>Hostnames: {entry.hostnames.join(", ")}</div>
                          )}
                          {!hasIntel && <div>No extra intel</div>}
                        </td>
                        <td className="py-3">
                          <span className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold ${badgeClass}`}>
                            {entry.statusText}
                          </span>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </div>
  )
}

const getMostRecentReport = (payload: any): string | null => {
  const entries = payload?.data?.reportedAddress
  if (!Array.isArray(entries) || entries.length === 0) {
    return null
  }
  const timestamps = entries
    .map((entry) => entry?.mostRecentReport)
    .filter((value): value is string => Boolean(value))
    .map((value) => new Date(value))
    .filter((date) => !Number.isNaN(date.getTime()))

  if (timestamps.length === 0) {
    return null
  }

  const latest = timestamps.sort((a, b) => b.getTime() - a.getTime())[0]
  return latest.toISOString().split("T")[0]
}

export default SubnetCheck
