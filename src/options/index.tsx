// src/options/Options.tsx

import React, { useEffect, useState } from "react"
import { createRoot } from "react-dom/client"
import OptionsUI from "./OptionsUI"
import "./options.css"
import "../utility/config.css"
import "../utility/colors.css"
import { defaultServices } from "../utility/defaultServices"
import type { CustomService } from "../utility/iocTypes"
import { Storage } from "@plasmohq/storage"

const storage = new Storage({ area: "local" })



const Options = () => {
  const [settingsLoaded, setSettingsLoaded] = useState(false)
  const [virusTotalApiKey, setVirusTotalApiKey] = useState("")
  const [abuseIPDBApiKey, setAbuseIPDBApiKey] = useState("")
  const [selectedServices, setSelectedServices] = useState<{ [key: string]: string[] }>(defaultServices)
  const [customServices, setCustomServices] = useState<CustomService[]>([])
  const [isDarkMode, setIsDarkMode] = useState(true)

  // Load from storage
useEffect(() => {
  const loadSettings = async () => {
    try {
      const vtKey = await storage.get("virusTotalApiKey")
      const abKey = await storage.get("abuseIPDBApiKey")
      const selectedRaw = await storage.get("selectedServices")
      const custom = await storage.get("customServices")
      const theme = await storage.get("isDarkMode")

      if (vtKey) setVirusTotalApiKey(vtKey)
      if (abKey) setAbuseIPDBApiKey(abKey)

      // 🛠 Validate selectedServices as a plain object
      if (
        selectedRaw &&
        typeof selectedRaw === "object" &&
        !Array.isArray(selectedRaw)
      ) {
        setSelectedServices(selectedRaw)
      } else {
        console.warn("Invalid selectedServices in storage, resetting.")
        await storage.remove("selectedServices")
        setSelectedServices(defaultServices)
      }

      if (Array.isArray(custom)) setCustomServices(custom)
      if (typeof theme === "boolean") setIsDarkMode(theme)
    } catch (err) {
      console.error("Failed to load settings:", err)
      setSelectedServices(defaultServices)
    }
  }

  loadSettings()
  setSettingsLoaded(true)

}, [])


  // Auto-save
  useEffect(() => {
    if (!settingsLoaded) return
    
    storage.set("virusTotalApiKey", virusTotalApiKey)
    storage.set("abuseIPDBApiKey", abuseIPDBApiKey)
    console.log("Saving selectedServices:", selectedServices)
    storage.set("selectedServices", selectedServices)
    storage.set("customServices", customServices)
    storage.set("isDarkMode", isDarkMode)
  }, [virusTotalApiKey, abuseIPDBApiKey, selectedServices, customServices, isDarkMode])

  useEffect(() => {
    document.body.className = isDarkMode ? "dark-mode" : "light-mode"
  }, [isDarkMode])

  const handleServiceChange = (type: string, service: string) => {
    const updated = { ...selectedServices }
    if (updated[type]?.includes(service)) {
      updated[type] = updated[type].filter((s) => s !== service)
    } else {
      updated[type] = [...(updated[type] || []), service]
    }
    setSelectedServices(updated)
  }

  const handleAddCustomService = (newService: CustomService) => {
    setCustomServices((prev) => [...prev, newService])
  }

  const handleRemoveCustomService = (index: number) => {
    setCustomServices((prev) => prev.filter((_, i) => i !== index))
  }

  const handleTestKeys = async () => {
    const results: string[] = []

    const testFetch = async (
      label: string,
      url: string,
      headers: HeadersInit,
      results: string[]
    ) => {
      try {
        const res = await fetch(url, { headers })

        if (res.ok) {
          results.push(`✅ ${label}: OK`)
        } else {
          switch (res.status) {
            case 400:
              results.push(`❌ ${label}: Bad Request (400)`)
              break
            case 401:
              results.push(`❌ ${label}: Unauthorized (401)`)
              break
            case 403:
              results.push(`❌ ${label}: Forbidden (403)`)
              break
            case 404:
              results.push(`❌ ${label}: Not Found (404)`)
              break
            case 500:
              results.push(`❌ ${label}: Internal Server Error (500)`)
              break
            case 502:
              results.push(`❌ ${label}: Bad Gateway (502)`)
              break
            case 503:
              results.push(`❌ ${label}: Service Unavailable (503)`)
              break
            case 504:
              results.push(`❌ ${label}: Gateway Timeout (504)`)
              break
            default:
              results.push(`❌ ${label}: Error (${res.status})`)
              break
          }
        }
      } catch (err) {
        if (err instanceof TypeError) {
          results.push(`❌ ${label}: Network error (TypeError)`)
        } else {
          results.push(`❌ ${label}: Unknown error`)
        }
      }
    }

    if (virusTotalApiKey) {
      await testFetch("VirusTotal", "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", {
        "x-apikey": virusTotalApiKey
      }, results)
    } else {
      results.push("⚠️ VirusTotal: Key not entered")
    }

    if (abuseIPDBApiKey) {
      await testFetch("AbuseIPDB", "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8", {
        Accept: "application/json",
        Key: abuseIPDBApiKey
      }, results)
    } else {
      results.push("⚠️ AbuseIPDB: Key not entered")
    }

    alert(results.join("\n"))
  }

  return (
    <OptionsUI
      isDarkMode={isDarkMode}
      virusTotalApiKey={virusTotalApiKey}
      abuseIPDBApiKey={abuseIPDBApiKey}
      selectedServices={selectedServices}
      customServices={customServices}
      onDarkModeToggle={() => setIsDarkMode((prev) => !prev)}
      onServiceChange={handleServiceChange}
      onVirusTotalApiKeyChange={setVirusTotalApiKey}
      onAbuseIPDBApiKeyChange={setAbuseIPDBApiKey}
      onTestKeys={handleTestKeys}
      onAddCustomService={handleAddCustomService}
      onRemoveCustomService={handleRemoveCustomService}
    />
  )
}

export default Options

const root = document.getElementById("root")
if (root) {
  createRoot(root).render(<Options />)
}
