import React, { useCallback, useEffect, useMemo, useRef, useState } from "react"

import { sendToBackground } from "@plasmohq/messaging"
import { Storage } from "@plasmohq/storage"

import BulkCheckUI from "./BulkCheckUI"

import "../styles/tailwind.css"

import { getNvdCve, getNvdCvss } from "../utility/intelFormatting"
import { ensureIsDarkMode, persistIsDarkMode } from "../utility/theme"
import {
  exportResultsByEngine,
  exportResultsToExcel,
  extractIOCs,
  identifyIOC,
  uniqueStrings
} from "../utility/utils"
import type {
  BulkCheckSummaryRow,
  BulkServiceStatus,
  BulkStatusKind
} from "./bulk-check.types"
import { hasFailedLookup } from "./bulk-verdict"

type IOCSummary = Record<string, string[]>
type BulkCheckResults = Record<string, any>
type BulkCheckRequest = {
  iocList: string[]
  services: string[]
  includeIpapi: boolean
  includeProxyCheck: boolean
}
type BulkCheckResponse = { results?: BulkCheckResults }

const storage = new Storage({ area: "local" })

const normalizeType = (type: string | null): string => {
  if (!type) {
    return "Unknown"
  }
  return type === "Private IP" ? "IP" : type
}

const categorizeIocs = (iocs: string[]): IOCSummary => {
  return iocs.reduce<IOCSummary>((acc, ioc) => {
    const type = normalizeType(identifyIOC(ioc))
    if (!acc[type]) {
      acc[type] = []
    }
    acc[type].push(ioc)
    return acc
  }, {})
}

const filterByIgnored = (summary: IOCSummary, ignores: string[]): string[] => {
  const ignoreSet = new Set(ignores)
  return Object.entries(summary).reduce<string[]>((acc, [type, values]) => {
    if (!ignoreSet.has(type)) {
      acc.push(...values)
    }
    return acc
  }, [])
}

const buildTypeSummary = (summary: IOCSummary) =>
  Object.entries(summary)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([type, values]) => ({ type, count: values.length }))

const applyDocumentTheme = (isDark: boolean) => {
  if (typeof document === "undefined") {
    return
  }
  document.body.className = isDark ? "dark-mode" : "light-mode"
}

const canServiceHandleType = (
  service: string,
  rawType: string | null
): boolean => {
  if (!rawType) {
    return false
  }
  if (service === "AbuseIPDB") {
    return rawType === "IP"
  }
  if (service === "VirusTotal") {
    return ["IP", "Domain", "URL", "Hash"].includes(rawType)
  }
  if (service === "NVD") {
    return rawType === "CVE"
  }
  return true
}

const describeVirusTotalPayload = (payload: any): BulkServiceStatus => {
  const stats = payload?.data?.attributes?.last_analysis_stats || {}
  const malicious = Number(stats?.malicious) || 0
  const suspicious = Number(stats?.suspicious) || 0
  const harmless = Number(stats?.harmless) || 0
  const undetected = Number(stats?.undetected) || 0
  const flaggedTotal = malicious + suspicious

  if (flaggedTotal > 0) {
    return {
      name: "VirusTotal",
      status: "flagged",
      text: `${malicious} malicious • ${suspicious} suspicious`
    }
  }

  const benignSignals = harmless + undetected
  return {
    name: "VirusTotal",
    status: "clean",
    text:
      benignSignals > 0
        ? `${benignSignals} engines no detections`
        : "No detections"
  }
}

const describeAbusePayload = (payload: any): BulkServiceStatus => {
  const score = Number(payload?.data?.abuseConfidenceScore) || 0
  const reports = Number(payload?.data?.totalReports) || 0
  if (score >= 50 || reports > 0) {
    return {
      name: "AbuseIPDB",
      status: "flagged",
      text: `${score}% confidence • ${reports} reports`
    }
  }

  return {
    name: "AbuseIPDB",
    status: "clean",
    text: "No reports"
  }
}

const describeNvdPayload = (payload: any): BulkServiceStatus => {
  const cve = getNvdCve(payload)
  if (!cve) {
    return { name: "NVD", status: "error", text: "CVE not found in the NVD" }
  }
  const cvss = getNvdCvss(payload)
  const kev = Boolean(cve.cisaExploitAdd)
  const detail = cvss
    ? `CVSS ${cvss.score.toFixed(1)} ${cvss.severity || "unrated"}`
    : cve.vulnStatus || "Record found"
  return {
    name: "NVD",
    status: kev || (cvss?.score ?? 0) > 0 ? "flagged" : "clean",
    text: kev ? `${detail} • CISA KEV` : detail
  }
}

export const buildServiceStatus = (
  service: string,
  payload: Record<string, any> | undefined,
  rawType: string | null,
  isPending: boolean
): BulkServiceStatus => {
  if (payload?.cancelled) {
    return {
      name: service,
      status: "skipped",
      text: "Cancelled before dispatch"
    }
  }

  if (!canServiceHandleType(service, rawType)) {
    const text =
      service === "AbuseIPDB"
        ? "Works with public IP addresses only"
        : service === "NVD"
          ? "Works with CVE identifiers only"
          : "Type not supported for this service"
    return {
      name: service,
      status: "skipped",
      text
    }
  }

  const servicePayload = payload?.[service]
  if (!servicePayload) {
    if (isPending) {
      return {
        name: service,
        status: "pending",
        text: "Running check..."
      }
    }
    return {
      name: service,
      status: "pending",
      text: "Awaiting check"
    }
  }

  if (servicePayload?.error) {
    return {
      name: service,
      status: "error",
      text:
        typeof servicePayload.error === "string"
          ? servicePayload.error
          : "Unable to fetch data"
    }
  }

  if (service === "VirusTotal") {
    return describeVirusTotalPayload(servicePayload)
  }

  if (service === "AbuseIPDB") {
    return describeAbusePayload(servicePayload)
  }

  if (service === "NVD") {
    return describeNvdPayload(servicePayload)
  }

  return {
    name: service,
    status: "clean",
    text: "Completed"
  }
}

export const deriveRowStatus = (
  displayType: string,
  rawType: string | null,
  serviceStatuses: BulkServiceStatus[],
  hasServices: boolean,
  isPending: boolean
): Pick<BulkCheckSummaryRow, "statusKind" | "statusText"> => {
  if (!rawType || displayType === "Unknown") {
    return {
      statusKind: "error",
      statusText: "Unsupported IOC format"
    }
  }

  if (rawType === "Private IP") {
    return {
      statusKind: "skipped",
      statusText: "Private IP - not checked"
    }
  }

  if (!hasServices) {
    return {
      statusKind: "skipped",
      statusText: "Select at least one service"
    }
  }

  // A positive detection remains the primary verdict even when another
  // provider fails. The failed provider is still visible and retryable in the
  // service details, but it must not hide actionable intelligence.
  const flaggedStatus = serviceStatuses.find(
    (entry) => entry.status === "flagged"
  )
  if (flaggedStatus) {
    return {
      statusKind: "flagged",
      statusText: flaggedStatus.text
    }
  }

  const errorStatus = serviceStatuses.find((entry) => entry.status === "error")
  if (errorStatus) {
    return {
      statusKind: "error",
      statusText: errorStatus.text
    }
  }

  if (
    serviceStatuses.length > 0 &&
    serviceStatuses.every((entry) => entry.status === "skipped")
  ) {
    return {
      statusKind: "skipped",
      statusText: "Services not applicable"
    }
  }

  if (serviceStatuses.some((entry) => entry.status === "pending")) {
    return {
      statusKind: "pending",
      statusText: isPending ? "Checking..." : "Awaiting check"
    }
  }

  return {
    statusKind: "clean",
    statusText: "No detections"
  }
}

const BulkCheck = () => {
  const [textareaValue, setTextareaValue] = useState("")
  const [allIocs, setAllIocs] = useState<string[]>([])
  const [iocList, setIocList] = useState<string[]>([])
  const [iocSummary, setIocSummary] = useState<IOCSummary>({})
  const [ignoredTypes, setIgnoredTypes] = useState<string[]>([])
  const [results, setResults] = useState<BulkCheckResults>({})
  const [selectedServices, setSelectedServices] = useState<string[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [message, setMessage] = useState("")
  const [isDarkMode, setIsDarkMode] = useState(true)
  const [proxyCheckEnabled, setProxyCheckEnabled] = useState(false)
  const [themeLoaded, setThemeLoaded] = useState(false)
  const [dailyCounters, setDailyCounters] = useState({
    vt: 0,
    abuse: 0,
    nvd: 0,
    proxy: 0
  })
  const [servicesInUse, setServicesInUse] = useState<string[]>([])
  const [pendingIocs, setPendingIocs] = useState<string[]>([])
  const [isCancelling, setIsCancelling] = useState(false)
  const iocSummaryRef = useRef<IOCSummary>({})
  const cancelRef = useRef(false)
  const textareaValueRef = useRef("")

  const getCounterKeys = useCallback(() => {
    const today = new Date().toISOString().split("T")[0]
    return {
      vt: `VT_${today}`,
      abuse: `Abuse_${today}`,
      nvd: `NVD_${today}`,
      proxy: `PROXYCHECK_${today}`
    }
  }, [])

  const refreshDailyCounters = useCallback(async () => {
    if (typeof chrome === "undefined" || !chrome.storage?.local?.get) {
      return
    }
    const keys = getCounterKeys()
    const values = await new Promise<Record<string, unknown>>((resolve) => {
      chrome.storage.local.get(
        [keys.vt, keys.abuse, keys.nvd, keys.proxy],
        (items) => resolve(items)
      )
    })
    setDailyCounters({
      vt: Number(values[keys.vt]) || 0,
      abuse: Number(values[keys.abuse]) || 0,
      nvd: Number(values[keys.nvd]) || 0,
      proxy: Number(values[keys.proxy]) || 0
    })
  }, [getCounterKeys])

  const autoSelectServices = useCallback(
    (summary: IOCSummary, ignores: string[]) => {
      const ignoreSet = new Set(ignores)
      const hasIp = Boolean(summary["IP"]?.length) && !ignoreSet.has("IP")
      const hasVtType = ["Domain", "URL", "Hash"].some(
        (type) => Boolean(summary[type]?.length) && !ignoreSet.has(type)
      )
      const hasCve = Boolean(summary["CVE"]?.length) && !ignoreSet.has("CVE")

      const nextServices: string[] = []
      if (hasVtType) {
        nextServices.push("VirusTotal")
      }
      if (hasIp) {
        nextServices.push("AbuseIPDB")
      }
      if (hasCve) {
        nextServices.push("NVD")
      }

      setSelectedServices(nextServices)
    },
    []
  )

  useEffect(() => {
    iocSummaryRef.current = iocSummary
  }, [iocSummary])

  useEffect(() => {
    refreshDailyCounters()
  }, [refreshDailyCounters])

  useEffect(() => {
    if (typeof chrome === "undefined" || !chrome.storage?.onChanged) {
      return
    }
    const listener: Parameters<
      typeof chrome.storage.onChanged.addListener
    >[0] = (changes, area) => {
      if (area !== "local") {
        return
      }
      const keys = getCounterKeys()
      if (
        changes[keys.vt] ||
        changes[keys.abuse] ||
        changes[keys.nvd] ||
        changes[keys.proxy]
      ) {
        refreshDailyCounters()
      }
    }
    chrome.storage.onChanged.addListener(listener)
    return () => chrome.storage.onChanged.removeListener(listener)
  }, [getCounterKeys, refreshDailyCounters])

  const applyIgnoreFilter = useCallback(
    (ignoreList: string[], summary?: IOCSummary) => {
      const baseSummary = summary ?? iocSummaryRef.current
      const filtered = filterByIgnored(baseSummary, ignoreList)
      const deduped = uniqueStrings(filtered)
      setIocList(deduped)
      autoSelectServices(baseSummary, ignoreList)
    },
    [autoSelectServices]
  )

  const applyExtractionResult = useCallback(
    (iocs: string[]) => {
      const summary = categorizeIocs(iocs)
      iocSummaryRef.current = summary
      setIocSummary(summary)
      setIgnoredTypes([])
      applyIgnoreFilter([], summary)
    },
    [applyIgnoreFilter]
  )

  const updateIOCsFromText = useCallback(
    (text: string) => {
      const extracted = extractIOCs(text) || []
      const unique = uniqueStrings(extracted)
      setAllIocs(unique)
      applyExtractionResult(unique)
    },
    [applyExtractionResult]
  )

  // The mirrored ref keeps consecutive imports additive: several files dropped
  // together are merged without waiting for React to flush the state.
  const setWorkspaceText = useCallback(
    (text: string) => {
      textareaValueRef.current = text
      setTextareaValue(text)
      updateIOCsFromText(text)
    },
    [updateIOCsFromText]
  )

  // Imported text is appended to the workspace instead of replacing it, so a
  // second file never discards indicators that are already being triaged.
  const ingestFile = useCallback(
    (file: File | undefined | null) => {
      if (!file) {
        setMessage("Please select a text file to import.")
        return
      }

      const reader = new FileReader()
      reader.onload = (loadEvent) => {
        const text =
          typeof loadEvent.target?.result === "string"
            ? loadEvent.target.result
            : ""
        const previous = textareaValueRef.current.trim()
        setWorkspaceText(previous ? `${previous}\n${text}` : text)
        setMessage(`Imported ${file.name}.`)
      }
      reader.onerror = () => {
        setMessage("Unable to read the selected file.")
      }
      reader.readAsText(file)
    },
    [setWorkspaceText]
  )

  const handleFileDrop = useCallback(
    (files: FileList | null) => {
      if (!files || files.length === 0) {
        setMessage("Please select a text file to import.")
        return
      }
      Array.from(files).forEach((file) => ingestFile(file))
    },
    [ingestFile]
  )

  const handleFileUpload = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      handleFileDrop(event.target.files)
      event.target.value = ""
    },
    [handleFileDrop]
  )

  const handleTextAreaChange = useCallback(
    (event: React.ChangeEvent<HTMLTextAreaElement>) => {
      const value = event.target.value
      textareaValueRef.current = value
      setTextareaValue(value)
      updateIOCsFromText(value)
    },
    [updateIOCsFromText]
  )

  const handleRefreshIocs = useCallback(() => {
    const extracted = extractIOCs(textareaValue) || []
    const unique = uniqueStrings(extracted)
    const refreshedText = unique.join("\n")

    textareaValueRef.current = refreshedText
    setTextareaValue(refreshedText)
    setAllIocs(unique)
    applyExtractionResult(unique)

    if (unique.length === 0) {
      setMessage("No valid IOCs detected in the provided text.")
    } else {
      setMessage(
        `Detected ${unique.length} unique IOC${unique.length === 1 ? "" : "s"}.`
      )
    }
    refreshDailyCounters()
  }, [applyExtractionResult, refreshDailyCounters, textareaValue])

  const handleServiceToggle = useCallback(
    (service: string, checked: boolean) => {
      setSelectedServices((prev) => {
        if (checked) {
          return prev.includes(service) ? prev : [...prev, service]
        }
        return prev.filter((entry) => entry !== service)
      })
    },
    []
  )

  const handleTypeToggle = useCallback(
    (type: string) => {
      setIgnoredTypes((prev) => {
        const next = prev.includes(type)
          ? prev.filter((item) => item !== type)
          : [...prev, type]
        applyIgnoreFilter(next)
        return next
      })
    },
    [applyIgnoreFilter]
  )

  const handleExport = useCallback(
    (format: "csv" | "xlsx") => {
      if (format === "csv") {
        exportResultsByEngine(results)
      } else {
        exportResultsToExcel(results)
      }
    },
    [results]
  )

  const handleProxyCheckToggle = useCallback((value: boolean) => {
    setProxyCheckEnabled(value)
    storage.set("bulkProxyCheckEnabled", value)
  }, [])

  const handleClearList = useCallback(() => {
    textareaValueRef.current = ""
    setTextareaValue("")
    setAllIocs([])
    applyExtractionResult([])
    storage.set("bulkIOCList", [])
  }, [applyExtractionResult])

  const runCheck = useCallback(
    async (targets: string[], mode: "full" | "retry") => {
      const requestList = uniqueStrings(targets)
      if (requestList.length === 0) {
        const emptyMessage =
          mode === "retry"
            ? "There is no failed IOC to retry."
            : "Please enter at least one IOC."
        setMessage(emptyMessage)
        if (mode === "full" && typeof window !== "undefined") {
          window.alert(emptyMessage)
        }
        return
      }

      if (selectedServices.length === 0) {
        setMessage("Select at least one service to run the check.")
        if (typeof window !== "undefined") {
          window.alert("Select at least one service to run the check.")
        }
        return
      }

      const selectedCopy = [...selectedServices]
      cancelRef.current = false
      setIsCancelling(false)
      setServicesInUse(selectedCopy)
      if (mode === "retry") {
        // Only the retried indicators are reset, the rest of the run is kept.
        setResults((prev) => {
          const next = { ...prev }
          requestList.forEach((ioc) => delete next[ioc])
          return next
        })
      } else {
        setResults({})
      }
      setIsLoading(true)

      const hasVirusTotal = selectedCopy.includes("VirusTotal")
      const otherServices = selectedCopy.filter(
        (service) => service !== "VirusTotal"
      )
      const generalQueue = otherServices.length > 0 ? requestList : []
      const generalServices = otherServices

      const vtEligibleList = hasVirusTotal
        ? requestList.filter((entry) => {
            const type = identifyIOC(entry)
            return (
              Boolean(type) && ["IP", "Domain", "URL", "Hash"].includes(type)
            )
          })
        : []
      const vtQueue = hasVirusTotal ? vtEligibleList : []
      const vtEligible = vtEligibleList.length
      const vtNote =
        hasVirusTotal && vtEligible > 0
          ? ` • VirusTotal 4 req/min${vtEligible > 4 ? ` (~${Math.ceil(vtEligible / 4)} min)` : ""}`
          : ""

      const pendingTracker = new Map<string, number>()
      const immediateResults: BulkCheckResults = {}

      for (const ioc of requestList) {
        const type = identifyIOC(ioc)
        const isVtEligible =
          Boolean(type) && ["IP", "Domain", "URL", "Hash"].includes(type!)
        const vtCount = hasVirusTotal && isVtEligible ? 1 : 0
        const generalCount = generalServices.length > 0 ? 1 : 0
        const totalGroups = vtCount + generalCount
        if (totalGroups > 0) {
          pendingTracker.set(ioc, totalGroups)
        } else {
          immediateResults[ioc] = {}
        }
      }

      if (Object.keys(immediateResults).length > 0) {
        setResults((prev) => ({ ...prev, ...immediateResults }))
      }

      setPendingIocs(Array.from(pendingTracker.keys()))

      const totalIocs = requestList.length
      let completedCount = totalIocs - pendingTracker.size
      let hadFailures = false

      setMessage(
        `Bulk check in progress${vtNote} – ${completedCount}/${totalIocs}`
      )

      const updateResultsForIoc = (
        ioc: string,
        payload: Record<string, any>
      ) => {
        setResults((prev) => {
          const previous = prev[ioc] ?? {}
          return {
            ...prev,
            [ioc]: {
              ...previous,
              ...payload
            }
          }
        })
      }

      const markServiceComplete = (ioc: string) => {
        if (!pendingTracker.has(ioc)) {
          return
        }
        const remaining = (pendingTracker.get(ioc) ?? 0) - 1
        if (remaining <= 0) {
          pendingTracker.delete(ioc)
          setPendingIocs(Array.from(pendingTracker.keys()))
          completedCount += 1
          setMessage(
            `Bulk check in progress${vtNote} – ${completedCount}/${totalIocs}`
          )
        } else {
          pendingTracker.set(ioc, remaining)
        }
      }

      const runQueue = async (
        queueSource: string[],
        services: string[],
        concurrency: number
      ) => {
        if (queueSource.length === 0 || services.length === 0) {
          return
        }
        const queue = [...queueSource]
        const worker = async () => {
          while (queue.length > 0) {
            // Requests already sent cannot be recalled, but nothing new is
            // dispatched once the analyst cancels the run.
            if (cancelRef.current) {
              return
            }
            const next = queue.shift()
            if (!next) {
              return
            }
            try {
              const response = await sendToBackground<
                BulkCheckRequest,
                BulkCheckResponse
              >({
                name: "check-bulk-iocs",
                body: {
                  iocList: [next],
                  services,
                  includeIpapi: false,
                  includeProxyCheck: proxyCheckEnabled
                }
              })

              const payload = response?.results?.[next] ?? {}
              updateResultsForIoc(next, payload)
            } catch (error) {
              hadFailures = true
              console.error(
                "Bulk check failed for IOC:",
                next,
                "services:",
                services.join(", "),
                error
              )
              updateResultsForIoc(next, { error: "Error during bulk check." })
            } finally {
              markServiceComplete(next)
            }
          }
        }
        const workerCount = Math.min(Math.max(1, concurrency), queue.length)
        await Promise.all(Array.from({ length: workerCount }, () => worker()))
      }

      try {
        await Promise.all([
          runQueue(generalQueue, generalServices, 8),
          runQueue(vtQueue, hasVirusTotal ? ["VirusTotal"] : [], 4)
        ])
        if (cancelRef.current) {
          const cancelledResults: BulkCheckResults = {}
          for (const ioc of pendingTracker.keys()) {
            cancelledResults[ioc] = { cancelled: true }
          }
          if (Object.keys(cancelledResults).length > 0) {
            setResults((previous) => ({ ...previous, ...cancelledResults }))
          }
          setMessage(
            `Check cancelled – ${completedCount}/${totalIocs} completed.`
          )
        } else {
          setMessage(
            hadFailures
              ? "Check completed with some errors."
              : "Check completed!"
          )
        }
      } catch (error) {
        console.error("Bulk check failed:", error)
        setMessage("Error during bulk check.")
      } finally {
        cancelRef.current = false
        setIsCancelling(false)
        setIsLoading(false)
        setPendingIocs([])
        setServicesInUse([])
        refreshDailyCounters()
      }
    },
    [proxyCheckEnabled, refreshDailyCounters, selectedServices]
  )

  const handleCheckBulk = useCallback(
    () => runCheck(iocList, "full"),
    [iocList, runCheck]
  )

  const handleCancelCheck = useCallback(() => {
    cancelRef.current = true
    setIsCancelling(true)
    setMessage("Cancelling the remaining lookups…")
  }, [])

  const failedIocs = useMemo(
    () =>
      Object.entries(results)
        .filter(([, payload]) => hasFailedLookup(payload))
        .map(([ioc]) => ioc),
    [results]
  )

  const handleRetryFailed = useCallback(
    () => runCheck(failedIocs, "retry"),
    [failedIocs, runCheck]
  )

  useEffect(() => {
    const loadData = async () => {
      try {
        const bulk = await storage.get<string[]>("bulkIOCList")
        if (Array.isArray(bulk) && bulk.length > 0) {
          const uniqueStored = uniqueStrings(bulk)
          setAllIocs(uniqueStored)
          textareaValueRef.current = uniqueStored.join("\n")
          setTextareaValue(textareaValueRef.current)
          applyExtractionResult(uniqueStored)
        }

        const dark = await ensureIsDarkMode()
        setIsDarkMode(dark)

        const [bulkProxySetting, proxySetting, proxyKey] = await Promise.all([
          storage.get<boolean>("bulkProxyCheckEnabled"),
          storage.get<boolean>("proxyCheckEnabled"),
          storage.get<string>("proxyCheckApiKey")
        ])

        if (typeof bulkProxySetting === "boolean") {
          setProxyCheckEnabled(bulkProxySetting)
        } else {
          const hasProxyKey =
            typeof proxyKey === "string" && proxyKey.trim().length > 0
          const shouldEnableProxyCheck = proxySetting === true && hasProxyKey
          setProxyCheckEnabled(shouldEnableProxyCheck)
        }
      } catch (error) {
        console.error("Failed to load bulk-check state:", error)
      } finally {
        setThemeLoaded(true)
      }
    }

    loadData()
  }, [applyExtractionResult])

  useEffect(() => {
    storage.set("bulkIOCList", allIocs)
  }, [allIocs])

  useEffect(() => {
    if (!themeLoaded) {
      return
    }
    persistIsDarkMode(isDarkMode)
    applyDocumentTheme(isDarkMode)
  }, [isDarkMode, themeLoaded])

  useEffect(() => {
    if (typeof chrome === "undefined" || !chrome.storage?.onChanged) {
      return
    }
    const listener: Parameters<
      typeof chrome.storage.onChanged.addListener
    >[0] = (changes, area) => {
      if (
        area === "local" &&
        Object.prototype.hasOwnProperty.call(changes, "isDarkMode")
      ) {
        const next = changes.isDarkMode?.newValue
        if (typeof next === "boolean") {
          setIsDarkMode(next)
        }
      }
    }
    chrome.storage.onChanged.addListener(listener)
    return () => chrome.storage.onChanged.removeListener(listener)
  }, [])

  const activeServices = useMemo(
    () => (servicesInUse.length > 0 ? servicesInUse : selectedServices),
    [servicesInUse, selectedServices]
  )

  const iocSummaries = useMemo<BulkCheckSummaryRow[]>(() => {
    const pendingLookup = new Set(pendingIocs)
    return iocList.map((ioc) => {
      const rawType = identifyIOC(ioc)
      const displayType = normalizeType(rawType)
      const payload = results[ioc]
      const isPending = pendingLookup.has(ioc)
      const serviceStatuses = activeServices.map((service) =>
        buildServiceStatus(service, payload, rawType, isPending)
      )
      const { statusKind, statusText } = deriveRowStatus(
        displayType,
        rawType,
        serviceStatuses,
        activeServices.length > 0,
        isPending
      )

      return {
        ioc,
        displayType,
        rawType,
        serviceStatuses,
        statusKind,
        statusText,
        result: payload,
        isPending
      }
    })
  }, [activeServices, iocList, pendingIocs, results])

  const iocTypeSummary = useMemo(
    () => buildTypeSummary(iocSummary),
    [iocSummary]
  )

  return (
    <BulkCheckUI
      textareaValue={textareaValue}
      onTextAreaChange={handleTextAreaChange}
      onFileUpload={handleFileUpload}
      onFileDrop={handleFileDrop}
      selectedServices={selectedServices}
      onServiceToggle={handleServiceToggle}
      onCheckBulk={handleCheckBulk}
      onCancelCheck={handleCancelCheck}
      onRetryFailed={handleRetryFailed}
      failedCount={failedIocs.length}
      isCancelling={isCancelling}
      onClearList={handleClearList}
      isLoading={isLoading}
      message={message}
      results={results}
      isDarkMode={isDarkMode}
      proxyCheckEnabled={proxyCheckEnabled}
      onExport={handleExport}
      onProxyCheckToggle={handleProxyCheckToggle}
      iocTypeSummary={iocTypeSummary}
      ignoredTypes={ignoredTypes}
      onTypeToggle={handleTypeToggle}
      onRefreshIocs={handleRefreshIocs}
      dailyCounters={dailyCounters}
      iocSummaries={iocSummaries}
    />
  )
}

export default BulkCheck
