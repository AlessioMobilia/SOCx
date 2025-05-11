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

  // Caricamento iniziale da storage
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

  // Salvataggio automatico
  useEffect(() => {
    chrome.storage.local.set({
      virusTotalApiKey,
      abuseIPDBApiKey,
      selectedServices,
      customServices,
      isDarkMode
    })
  }, [virusTotalApiKey, abuseIPDBApiKey, selectedServices, customServices, isDarkMode])

  // Tema
  useEffect(() => {
    document.body.className = isDarkMode ? "dark-mode" : "light-mode"
  }, [isDarkMode])

  // Cambiamento selezione servizi standard
  const handleServiceChange = (type: string, service: string) => {
    const updated = { ...selectedServices }
    if (updated[type]?.includes(service)) {
      updated[type] = updated[type].filter((s) => s !== service)
    } else {
      updated[type] = [...(updated[type] || []), service]
    }
    setSelectedServices(updated)
  }

  // Aggiungi servizio personalizzato
  const handleAddCustomService = (newService: CustomService) => {
    setCustomServices((prev) => [...prev, newService])
  }

  // Rimuovi servizio personalizzato
  const handleRemoveCustomService = (index: number) => {
    setCustomServices((prev) => prev.filter((_, i) => i !== index))
  }

  // Test API Key
  const handleTestKeys = async () => {
    const results: string[] = []

    const testFetch = async (
      label: string,
      url: string,
      headers: HeadersInit
    ) => {
      try {
        const res = await fetch(url, { headers })
        results.push(
          `✅ ${label}: ${res.ok ? "OK" : `Errore (${res.status})`}`
        )
      } catch (err) {
        results.push(`❌ ${label}: Errore di rete`)
      }
    }

    if (virusTotalApiKey) {
      await testFetch("VirusTotal", "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", {
        "x-apikey": virusTotalApiKey
      })
    } else {
      results.push("⚠️ VirusTotal: Chiave non inserita")
    }

    if (abuseIPDBApiKey) {
      await testFetch("AbuseIPDB", "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8", {
        Accept: "application/json",
        Key: abuseIPDBApiKey
      })
    } else {
      results.push("⚠️ AbuseIPDB: Chiave non inserita")
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

// Monta React
const root = document.getElementById("root")
if (root) {
  createRoot(root).render(<Options />)
}
