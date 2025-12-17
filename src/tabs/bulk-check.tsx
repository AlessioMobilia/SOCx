import React, { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { sendToBackground } from "@plasmohq/messaging"
import { Storage } from "@plasmohq/storage"

import BulkCheckUI from "./BulkCheckUI"
import "../styles/tailwind.css"
import { ensureIsDarkMode, persistIsDarkMode } from "../utility/theme"
import {
  extractIOCs,
  exportResultsByEngine,
  exportResultsToExcel,
  identifyIOC,
  uniqueStrings
} from "../utility/utils"
import type { BulkCheckSummaryRow, BulkServiceStatus, BulkStatusKind } from "./bulk-check.types"

type IOCSummary = Record<string, string[]>
type BulkCheckResults = Record<string, any>

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

const canServiceHandleType = (service: string, rawType: string | null): boolean => {
  if (!rawType) {
    return false
  }
  if (service === "AbuseIPDB") {
    return rawType === "IP"
  }
  if (service === "VirusTotal") {
    return rawType !== "MAC"
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
    text: benignSignals > 0 ? `${benignSignals} engines no detections` : "No detections"
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

const buildServiceStatus = (
  service: string,
  payload: Record<string, any> | undefined,
  rawType: string | null,
  isPending: boolean
): BulkServiceStatus => {
  if (!canServiceHandleType(service, rawType)) {
    const text =
      service === "AbuseIPDB"
        ? "Works with public IP addresses only"
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
      text: typeof servicePayload.error === "string" ? servicePayload.error : "Unable to fetch data"
    }
  }

  if (service === "VirusTotal") {
    return describeVirusTotalPayload(servicePayload)
  }

  if (service === "AbuseIPDB") {
    return describeAbusePayload(servicePayload)
  }

  return {
    name: service,
    status: "clean",
    text: "Completed"
  }
}

const deriveRowStatus = (
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

  const errorStatus = serviceStatuses.find((entry) => entry.status === "error")
  if (errorStatus) {
    return {
      statusKind: "error",
      statusText: errorStatus.text
    }
  }

  const flaggedStatus = serviceStatuses.find((entry) => entry.status === "flagged")
  if (flaggedStatus) {
    return {
      statusKind: "flagged",
      statusText: flaggedStatus.text
    }
  }

  if (serviceStatuses.length > 0 && serviceStatuses.every((entry) => entry.status === "skipped")) {
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
  const [dailyCounters, setDailyCounters] = useState({ vt: 0, abuse: 0, proxy: 0 })
  const [servicesInUse, setServicesInUse] = useState<string[]>([])
  const [pendingIocs, setPendingIocs] = useState<string[]>([])
  const iocSummaryRef = useRef<IOCSummary>({})

  const getCounterKeys = useCallback(() => {
    const today = new Date().toISOString().split("T")[0]
    return {
      vt: `VT_${today}`,
      abuse: `Abuse_${today}`,
      proxy: `PROXYCHECK_${today}`
    }
  }, [])

  const refreshDailyCounters = useCallback(async () => {
    if (typeof chrome === "undefined" || !chrome.storage?.local?.get) {
      return
    }
    const keys = getCounterKeys()
    const values = await new Promise<Record<string, number>>((resolve) => {
      chrome.storage.local.get([keys.vt, keys.abuse, keys.proxy], (items) => resolve(items))
    })
    setDailyCounters({
      vt: Number(values[keys.vt]) || 0,
      abuse: Number(values[keys.abuse]) || 0,
      proxy: Number(values[keys.proxy]) || 0
    })
  }, [getCounterKeys])

  const autoSelectServices = useCallback(
    (summary: IOCSummary, ignores: string[]) => {
      const ignoreSet = new Set(ignores)
      const hasIp = Boolean(summary["IP"]?.length) && !ignoreSet.has("IP")
      const hasOther = Object.entries(summary).some(
        ([type, values]) => type !== "IP" && values.length > 0 && !ignoreSet.has(type)
      )

      const nextServices: string[] = []
      if (hasOther) {
        nextServices.push("VirusTotal")
      }
      if (hasIp) {
        nextServices.push("AbuseIPDB")
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
    const listener: Parameters<typeof chrome.storage.onChanged.addListener>[0] = (changes, area) => {
      if (area !== "local") {
        return
      }
      const keys = getCounterKeys()
      if (changes[keys.vt] || changes[keys.abuse] || changes[keys.proxy]) {
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

  const handleFileUpload = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0]
      if (!file) {
        setMessage("Please select a .txt file to import.")
        return
      }

      const reader = new FileReader()
      reader.onload = (loadEvent) => {
        const text = typeof loadEvent.target?.result === "string" ? loadEvent.target.result : ""
        setTextareaValue(text)
        updateIOCsFromText(text)
      }
      reader.onerror = () => {
        setMessage("Unable to read the selected file.")
      }
      reader.readAsText(file)
      event.target.value = ""
    },
    [updateIOCsFromText]
  )

  const handleTextAreaChange = useCallback(
    (event: React.ChangeEvent<HTMLTextAreaElement>) => {
      const value = event.target.value
      setTextareaValue(value)
      updateIOCsFromText(value)
    },
    [updateIOCsFromText]
  )

  const handleRefreshIocs = useCallback(() => {
    const extracted = extractIOCs(textareaValue) || []
    const unique = uniqueStrings(extracted)
    const refreshedText = unique.join("\n")

    setTextareaValue(refreshedText)
    setAllIocs(unique)
    applyExtractionResult(unique)

    if (unique.length === 0) {
      setMessage("No valid IOCs detected in the provided text.")
    } else {
      setMessage(`Detected ${unique.length} unique IOC${unique.length === 1 ? "" : "s"}.`)
    }
    refreshDailyCounters()
  }, [applyExtractionResult, refreshDailyCounters, textareaValue])

  const handleServiceToggle = useCallback((service: string, checked: boolean) => {
    setSelectedServices((prev) => {
      if (checked) {
        return prev.includes(service) ? prev : [...prev, service]
      }
      return prev.filter((entry) => entry !== service)
    })
  }, [])

  const handleTypeToggle = useCallback(
    (type: string) => {
      setIgnoredTypes((prev) => {
        const next = prev.includes(type) ? prev.filter((item) => item !== type) : [...prev, type]
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
    setTextareaValue("")
    setAllIocs([])
    applyExtractionResult([])
    storage.set("bulkIOCList", [])
  }, [applyExtractionResult])

  const handleCheckBulk = useCallback(async () => {
    const requestList = uniqueStrings(iocList)
    if (requestList.length === 0) {
      setMessage("Please enter at least one IOC.")
      if (typeof window !== "undefined") {
        window.alert("Please enter at least one IOC.")
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
    setServicesInUse(selectedCopy)
    setResults({})
    setIsLoading(true)

    const hasVirusTotal = selectedCopy.includes("VirusTotal")
    const otherServices = selectedCopy.filter((service) => service !== "VirusTotal")
    const generalQueue = otherServices.length > 0 ? requestList : []
    const generalServices = otherServices

    const vtEligibleList = hasVirusTotal
      ? requestList.filter((entry) => {
          const type = identifyIOC(entry)
          return Boolean(type) && type !== "MAC"
        })
      : []
    const vtQueue = hasVirusTotal ? requestList : []
    const vtEligible = vtEligibleList.length
    const vtNote =
      hasVirusTotal && vtEligible > 0
        ? ` • VirusTotal 4 req/min${vtEligible > 4 ? ` (~${Math.ceil(vtEligible / 4)} min)` : ""}`
        : ""

    const pendingTracker = new Map<string, number>()
    const immediateResults: BulkCheckResults = {}

    for (const ioc of requestList) {
      const type = identifyIOC(ioc)
      const isVtEligible = Boolean(type) && type !== "MAC"
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

    setMessage(`Bulk check in progress${vtNote} – ${completedCount}/${totalIocs}`)

    const updateResultsForIoc = (ioc: string, payload: Record<string, any>) => {
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
        setMessage(`Bulk check in progress${vtNote} – ${completedCount}/${totalIocs}`)
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
          const next = queue.shift()
          if (!next) {
            return
          }
          try {
            const response = await sendToBackground<{ results?: BulkCheckResults }>({
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
      setMessage(hadFailures ? "Check completed with some errors." : "Check completed!")
    } catch (error) {
      console.error("Bulk check failed:", error)
      setMessage("Error during bulk check.")
    } finally {
      setIsLoading(false)
      setPendingIocs([])
      setServicesInUse([])
      refreshDailyCounters()
    }
  }, [iocList, proxyCheckEnabled, refreshDailyCounters, selectedServices])

  useEffect(() => {
    const loadData = async () => {
      try {
        const bulk = await storage.get<string[]>("bulkIOCList")
        if (Array.isArray(bulk) && bulk.length > 0) {
          const uniqueStored = uniqueStrings(bulk)
          setAllIocs(uniqueStored)
          setTextareaValue(uniqueStored.join("\n"))
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
          const hasProxyKey = typeof proxyKey === "string" && proxyKey.trim().length > 0
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
    const listener: Parameters<typeof chrome.storage.onChanged.addListener>[0] = (changes, area) => {
      if (area === "local" && Object.prototype.hasOwnProperty.call(changes, "isDarkMode")) {
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

  const iocTypeSummary = useMemo(() => buildTypeSummary(iocSummary), [iocSummary])

  return (
    <BulkCheckUI
      textareaValue={textareaValue}
      onTextAreaChange={handleTextAreaChange}
      onFileUpload={handleFileUpload}
      selectedServices={selectedServices}
      onServiceToggle={handleServiceToggle}
      onCheckBulk={handleCheckBulk}
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
