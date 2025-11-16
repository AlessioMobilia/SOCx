import React, { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { sendToBackground } from "@plasmohq/messaging"
import { Storage } from "@plasmohq/storage"

import BulkCheckUI from "./BulkCheckUI"
import "./bulk-check.css"
import { ensureIsDarkMode, persistIsDarkMode } from "../utility/theme"
import {
  extractIOCs,
  exportResultsByEngine,
  exportResultsToExcel,
  identifyIOC,
  uniqueStrings
} from "../utility/utils"

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

    setIsLoading(true)
    setMessage("Bulk check in progress...")

    try {
      const response = await sendToBackground<{ results?: BulkCheckResults }>({
        name: "check-bulk-iocs",
        body: {
          iocList: requestList,
          services: selectedServices,
          includeIpapi: false,
          includeProxyCheck: proxyCheckEnabled
        }
      })

      setResults(response?.results ?? {})
      setMessage("Check completed!")
    } catch (error) {
      console.error("Bulk check failed:", error)
      setMessage("Error during bulk check.")
    } finally {
      setIsLoading(false)
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
    />
  )
}

export default BulkCheck
