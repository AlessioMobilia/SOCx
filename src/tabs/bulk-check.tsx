import React, { useEffect, useState } from "react"
import BulkCheckUI from "./BulkCheckUI"
import { extractIOCs } from "../utility/utils"
import { exportResultsByEngine, exportResultsToExcel } from "../utility/utils"
import "./bulk-check.css"
import { Storage } from "@plasmohq/storage"
import { sendToBackground } from "@plasmohq/messaging"

const storage = new Storage({ area: "local" })

const BulkCheck = () => {
  const [textareaValue, setTextareaValue] = useState("")
  const [iocList, setIocList] = useState<string[]>([])
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
        setIocList(bulk)
        setTextareaValue(bulk.join("\n"))
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
    storage.set("bulkIOCList", iocList)
  }, [iocList])

  useEffect(() => {
    storage.set("isDarkMode", isDarkMode)
  }, [isDarkMode])

  const updateIOCsFromText = (text: string) => {
    const iocs = extractIOCs(text)
    setIocList(iocs)
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
    setIocList([])
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
    />
  )
}

export default BulkCheck
