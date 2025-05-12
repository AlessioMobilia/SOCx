// src/options/Options.tsx

import React, { useEffect, useState } from "react"
import { createRoot } from "react-dom/client"
import OptionsUI from "./OptionsUI"
import "./options.css"
import "../utility/config.css"
import "../utility/colors.css"
import { defaultServices } from "../utility/defaultServices"
import type { CustomService } from "../utility/iocTypes"

const Options = () => {
  const [virusTotalApiKey, setVirusTotalApiKey] = useState("")
  const [abuseIPDBApiKey, setAbuseIPDBApiKey] = useState("")
  const [selectedServices, setSelectedServices] = useState<{ [key: string]: string[] }>(defaultServices)
  const [customServices, setCustomServices] = useState<CustomService[]>([])
  const [isDarkMode, setIsDarkMode] = useState(true)

  // Initial loading from storage
  useEffect(() => {
    chrome.storage.local.get(
      ["virusTotalApiKey", "abuseIPDBApiKey", "selectedServices", "isDarkMode", "customServices"],
      (result) => {
        if (result.virusTotalApiKey) setVirusTotalApiKey(result.virusTotalApiKey)
        if (result.abuseIPDBApiKey) setAbuseIPDBApiKey(result.abuseIPDBApiKey)
        if (result.selectedServices) setSelectedServices(result.selectedServices)
        if (result.customServices) setCustomServices(result.customServices)
        if (result.isDarkMode !== undefined) setIsDarkMode(result.isDarkMode)
      }
    )
  }, [])

  // Auto-saving
  useEffect(() => {
    chrome.storage.local.set({
      virusTotalApiKey,
      abuseIPDBApiKey,
      selectedServices,
      customServices,
      isDarkMode
    })
  }, [virusTotalApiKey, abuseIPDBApiKey, selectedServices, customServices, isDarkMode])

  // Theme
  useEffect(() => {
    document.body.className = isDarkMode ? "dark-mode" : "light-mode"
  }, [isDarkMode])

  // Standard service selection change
  const handleServiceChange = (type: string, service: string) => {
    const updated = { ...selectedServices }
    if (updated[type]?.includes(service)) {
      updated[type] = updated[type].filter((s) => s !== service)
    } else {
      updated[type] = [...(updated[type] || []), service]
    }
    setSelectedServices(updated)
  }

  // Add custom service
  const handleAddCustomService = (newService: CustomService) => {
    setCustomServices((prev) => [...prev, newService])
  }

  // Remove custom service
  const handleRemoveCustomService = (index: number) => {
    setCustomServices((prev) => prev.filter((_, i) => i !== index))
  }

  // Test API Key
  const handleTestKeys = async () => {
    const results: string[] = []

    const testFetch = async (
    label: string,
    url: string,
    headers: HeadersInit,
    results: string[]
  ) => {
    try {
      const res = await fetch(url, { headers });

      if (res.ok) {
        results.push(`✅ ${label}: OK`);
      } else {
        // Handle specific HTTP status codes with better messaging
        switch (res.status) {
          case 400:
            results.push(`❌ ${label}: Bad Request (400)`);
            break;
          case 401:
            results.push(`❌ ${label}: Unauthorized (401)`);
            break;
          case 403:
            results.push(`❌ ${label}: Forbidden (403)`);
            break;
          case 404:
            results.push(`❌ ${label}: Not Found (404)`);
            break;
          case 500:
            results.push(`❌ ${label}: Internal Server Error (500)`);
            break;
          case 502:
            results.push(`❌ ${label}: Bad Gateway (502)`);
            break;
          case 503:
            results.push(`❌ ${label}: Service Unavailable (503)`);
            break;
          case 504:
            results.push(`❌ ${label}: Gateway Timeout (504)`);
            break;
          default:
            results.push(`❌ ${label}: Error (${res.status})`);
            break;
        }
      }
    } catch (err) {
      // Improved error handling for network issues or other exceptions
      if (err instanceof TypeError) {
        // A TypeError typically indicates a network or fetch issue
        results.push(`❌ ${label}: Network error (TypeError)`);
      } else {
        // Catching other errors (e.g., unexpected issues with fetch itself)
        results.push(`❌ ${label}: Unknown error`);
      }
    }
  };


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

// Mount React
const root = document.getElementById("root")
if (root) {
  createRoot(root).render(<Options />)
}
