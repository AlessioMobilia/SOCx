// src/options/Options.tsx

import React, { useCallback, useEffect, useState } from "react"
import { createRoot } from "react-dom/client"
import OptionsUI from "./OptionsUI"
import "../styles/tailwind.css"
import { defaultServices } from "../utility/defaultServices"
import type { CustomService } from "../utility/iocTypes"
import { Storage } from "@plasmohq/storage"
import { ensureIsDarkMode, persistIsDarkMode } from "../utility/theme"

const storage = new Storage({ area: "local" })



const Options = () => {
  const [settingsLoaded, setSettingsLoaded] = useState(false)
  const [virusTotalApiKey, setVirusTotalApiKey] = useState("")
  const [abuseIPDBApiKey, setAbuseIPDBApiKey] = useState("")
  const [proxyCheckApiKey, setProxyCheckApiKey] = useState("")
  const [selectedServices, setSelectedServices] = useState<{ [key: string]: string[] }>(defaultServices)
  const [customServices, setCustomServices] = useState<CustomService[]>([])
  const [isDarkMode, setIsDarkMode] = useState(true)
  const [ipapiEnabled, setIpapiEnabled] = useState(false)
  const [proxyCheckEnabled, setProxyCheckEnabled] = useState(false)
  const [floatingButtonsEnabled, setFloatingButtonsEnabled] = useState(true)
  const [dailyCounters, setDailyCounters] = useState({ vt: 0, abuse: 0, proxy: 0 })
  const notifyFloatingButtonsListeners = useCallback((enabled: boolean) => {
    if (typeof chrome === "undefined" || !chrome.runtime?.sendMessage) {
      return
    }
    try {
      chrome.runtime.sendMessage({
        type: "floating-buttons-preference-changed",
        enabled
      })
    } catch (error) {
      console.warn("Unable to broadcast floating button preference:", error)
    }
  }, [])

  const getCounterKeys = useCallback(() => {
    const today = new Date().toISOString().split("T")[0]
    return {
      vt: `VT_${today}`,
      abuse: `Abuse_${today}`,
      proxy: `PROXYCHECK_${today}`
    }
  }, [])

  const refreshDailyCounters = useCallback(async () => {
    try {
      const keys = getCounterKeys()
      const [vt, abuse, proxy] = await Promise.all([
        storage.get<number>(keys.vt),
        storage.get<number>(keys.abuse),
        storage.get<number>(keys.proxy)
      ])
      setDailyCounters({
        vt: vt ?? 0,
        abuse: abuse ?? 0,
        proxy: proxy ?? 0
      })
    } catch (error) {
      console.warn("Unable to load daily counters:", error)
      setDailyCounters({ vt: 0, abuse: 0, proxy: 0 })
    }
  }, [getCounterKeys])

  // Auto-save
  useEffect(() => {
    if (!settingsLoaded) return
    
    storage.set("virusTotalApiKey", virusTotalApiKey)
    storage.set("abuseIPDBApiKey", abuseIPDBApiKey)
    storage.set("proxyCheckApiKey", proxyCheckApiKey)
    console.log("Saving selectedServices:", selectedServices)
    storage.set("selectedServices", selectedServices)
    storage.set("customServices", customServices)
    persistIsDarkMode(isDarkMode)
    storage.set("ipapiEnrichmentEnabled", ipapiEnabled)
    storage.set("proxyCheckEnabled", proxyCheckEnabled)
    storage.set("floatingButtonsEnabled", floatingButtonsEnabled)
  }, [
    virusTotalApiKey,
    abuseIPDBApiKey,
    proxyCheckApiKey,
    selectedServices,
    customServices,
    isDarkMode,
    ipapiEnabled,
    proxyCheckEnabled,
    floatingButtonsEnabled
  ])

  useEffect(() => {
    document.body.className = isDarkMode ? "dark-mode" : "light-mode"
  }, [isDarkMode])

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

  const loadSettings = async () => {
    try {
      const vtKey = await storage.get("virusTotalApiKey")
      const abKey = await storage.get("abuseIPDBApiKey")
      const proxyKey = await storage.get("proxyCheckApiKey")
      const selectedRaw = await storage.get("selectedServices")
      const custom = await storage.get("customServices")
      const theme = await ensureIsDarkMode()
      const ipapiSetting = await storage.get("ipapiEnrichmentEnabled")
      const proxySetting = await storage.get("proxyCheckEnabled")
      const floatingButtonsSetting = await storage.get("floatingButtonsEnabled")

      if (vtKey) setVirusTotalApiKey(vtKey)
      if (abKey) setAbuseIPDBApiKey(abKey)
      if (proxyKey) setProxyCheckApiKey(proxyKey)

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
      setIsDarkMode(theme)
      const hasProxyKey = Boolean(proxyKey)
      const desiredProxy =
        typeof proxySetting === "boolean" ? proxySetting : hasProxyKey
      const nextProxyEnabled = desiredProxy && hasProxyKey
      const persistedIpapi =
        typeof ipapiSetting === "boolean" ? ipapiSetting : false
      const nextIpapiEnabled = nextProxyEnabled ? false : persistedIpapi
      setProxyCheckEnabled(nextProxyEnabled)
      setIpapiEnabled(nextIpapiEnabled)
      const shouldShowFloatingButtons =
        typeof floatingButtonsSetting === "boolean" ? floatingButtonsSetting : true
      setFloatingButtonsEnabled(shouldShowFloatingButtons)
    } catch (err) {
      console.error("Failed to load settings:", err)
      setSelectedServices(defaultServices)
    } finally {
      setSettingsLoaded(true)
    }
  }

  useEffect(() => {
    loadSettings()
  }, [])

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

    if (proxyCheckApiKey) {
      await testFetch(
        "ProxyCheck",
        `https://proxycheck.io/v3/8.8.8.8?key=${proxyCheckApiKey}&vpn=1`,
        {},
        results
      )
    } else {
      results.push("⚠️ ProxyCheck: Key not entered")
    }

    alert(results.join("\n"))
  }

  const handleProxyCheckKeyChange = (value: string) => {
    setProxyCheckApiKey(value)
    const hasKey = Boolean(value)
    setProxyCheckEnabled(hasKey)
    if (hasKey) {
      setIpapiEnabled(false)
    }
  }

  const handleIpapiToggle = (value: boolean) => {
    setIpapiEnabled(value)
    if (value) {
      setProxyCheckEnabled(false)
    }
  }

  const handleProxyCheckToggle = (value: boolean) => {
    if (value && !proxyCheckApiKey) {
      return
    }
    setProxyCheckEnabled(value)
    if (value) {
      setIpapiEnabled(false)
    }
  }

  const handleFloatingButtonsToggle = (value: boolean) => {
    setFloatingButtonsEnabled(value)
    notifyFloatingButtonsListeners(value)
  }

  return (
    <OptionsUI
      isDarkMode={isDarkMode}
      virusTotalApiKey={virusTotalApiKey}
      abuseIPDBApiKey={abuseIPDBApiKey}
      proxyCheckApiKey={proxyCheckApiKey}
      ipapiEnabled={ipapiEnabled}
      proxyCheckEnabled={proxyCheckEnabled}
      selectedServices={selectedServices}
      customServices={customServices}
      floatingButtonsEnabled={floatingButtonsEnabled}
      onDarkModeToggle={() => setIsDarkMode((prev) => !prev)}
      onServiceChange={handleServiceChange}
      onVirusTotalApiKeyChange={setVirusTotalApiKey}
      onAbuseIPDBApiKeyChange={setAbuseIPDBApiKey}
      onProxyCheckApiKeyChange={handleProxyCheckKeyChange}
      onIpapiToggle={handleIpapiToggle}
      onProxyCheckToggle={handleProxyCheckToggle}
      onFloatingButtonsToggle={handleFloatingButtonsToggle}
      onTestKeys={handleTestKeys}
      onAddCustomService={handleAddCustomService}
      onRemoveCustomService={handleRemoveCustomService}
      dailyCounters={dailyCounters}
    />
  )
}

export default Options

const root = document.getElementById("root")
if (root) {
  createRoot(root).render(<Options />)
}
