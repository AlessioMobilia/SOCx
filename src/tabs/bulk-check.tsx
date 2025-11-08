import React, { useEffect, useState } from "react"
import BulkCheckUI from "./BulkCheckUI"
import {
  extractIOCs,
  exportResultsByEngine,
  exportResultsToExcel,
  identifyIOC
} from "../utility/utils"
import "./bulk-check.css"
import { Storage } from "@plasmohq/storage"
import { sendToBackground } from "@plasmohq/messaging"

const storage = new Storage({ area: "local" })
type IOCSummary = Record<string, string[]>

const BulkCheck = () => {
  const [textareaValue, setTextareaValue] = useState("")
  const [allIocs, setAllIocs] = useState<string[]>([])
  const [iocList, setIocList] = useState<string[]>([])
  const [iocSummary, setIocSummary] = useState<IOCSummary>({})
  const [ignoredTypes, setIgnoredTypes] = useState<string[]>([])
  const [results, setResults] = useState<{ [key: string]: any }>({})
  const [selectedServices, setSelectedServices] = useState<string[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [message, setMessage] = useState("")
  const [isDarkMode, setIsDarkMode] = useState(true)

  // Load saved data
  useEffect(() => {
    const loadData = async () => {
      const bulk = await storage.get<string[]>("bulkIOCList")
      if (bulk && Array.isArray(bulk)) {
        setAllIocs(bulk)
        setTextareaValue(bulk.join("\n"))
        applyExtractionResult(bulk)
      }

      const dark = await storage.get<boolean>("isDarkMode")
      if (typeof dark === "boolean") {
        setIsDarkMode(dark)
      }
    }
    loadData()
  }, [])

  useEffect(() => {
    document.body.className = isDarkMode ? "dark-mode" : "light-mode"
  }, [isDarkMode])

  useEffect(() => {
    storage.set("bulkIOCList", allIocs)
  }, [allIocs])

  useEffect(() => {
    storage.set("isDarkMode", isDarkMode)
  }, [isDarkMode])

  const normalizeType = (type: string | null): string => {
    if (!type) return "Unknown"
    if (type === "Private IP") return "IP"
    return type
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

  const autoSelectServices = (summary: IOCSummary, ignores: string[]) => {
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
  }

  const applyIgnoreFilter = (ignoreList: string[], summary: IOCSummary = iocSummary) => {
    const filtered = filterByIgnored(summary, ignoreList)
    setIocList(filtered)
    autoSelectServices(summary, ignoreList)
  }

  const applyExtractionResult = (iocs: string[]) => {
    const summary = categorizeIocs(iocs)
    setIocSummary(summary)
    setIgnoredTypes([])
    applyIgnoreFilter([], summary)
  }

  const updateIOCsFromText = (text: string) => {
    const iocs = extractIOCs(text) || []
    setAllIocs(iocs)
    applyExtractionResult(iocs)
  }

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      const reader = new FileReader()
      reader.onload = (event) => {
        const text = event.target?.result as string
        setTextareaValue(text)
        updateIOCsFromText(text)
      }
      reader.readAsText(file)
    }
  }

const handleCheckBulk = async () => {
  if (iocList.length === 0) {
    alert("Please enter at least one IOC.")
    return
  }

  setIsLoading(true)
  setMessage("Bulk check in progress...")

  try {
    const response = await sendToBackground({
      name: "check-bulk-iocs",
      body: {
        iocList,
        services: selectedServices
      }
    })

    setResults(response.results)
    setMessage("Check completed!")
  } catch (error) {
    console.error("Bulk check failed:", error)
    setMessage("Error during bulk check.")
  } finally {
    setIsLoading(false)
  }
}

  const handleClearList = () => {
    setTextareaValue("")
    setAllIocs([])
    applyExtractionResult([])
    storage.set("bulkIOCList", [])
  }

  const handleTextAreaChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const value = e.target.value
    setTextareaValue(value)
    updateIOCsFromText(value)
  }

  const handleServiceToggle = (service: string, checked: boolean) => {
    if (checked) {
      setSelectedServices([...selectedServices, service])
    } else {
      setSelectedServices(selectedServices.filter((s) => s !== service))
    }
  }

  const toggleDarkMode = () => {
    setIsDarkMode((prev) => !prev)
  }

  const handleTypeToggle = (type: string) => {
    setIgnoredTypes((prev) => {
      const next = prev.includes(type)
        ? prev.filter((t) => t !== type)
        : [...prev, type]
      applyIgnoreFilter(next)
      return next
    })
  }

  const handleExport = (format: "csv" | "xlsx") => {
    if (format === "csv") {
      exportResultsByEngine(results)
    } else if (format === "xlsx") {
      exportResultsToExcel(results)
    }
  }

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
      onExport={handleExport}
      iocTypeSummary={Object.entries(iocSummary)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([type, values]) => ({
          type,
          count: values.length
        }))}
      ignoredTypes={ignoredTypes}
      onTypeToggle={handleTypeToggle}
    />
  )
}

export default BulkCheck
