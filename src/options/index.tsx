// src/options/Options.tsx

import React, { useCallback, useEffect, useState } from "react"
import { createRoot } from "react-dom/client"

import { sendToBackground } from "@plasmohq/messaging"

import OptionsUI from "./OptionsUI"

import "../styles/tailwind.css"

import { Storage } from "@plasmohq/storage"

import {
  API_CACHE_TTL_KEY,
  DEFAULT_API_CACHE_TTL_MINUTES,
  normalizeApiCacheTtlMinutes
} from "../utility/apiCacheConfig"
import {
  resolveSelectionButtonsPreference,
  resolveServicePageCopyButtonsPreference,
  SELECTION_BUTTONS_KEY,
  SELECTION_BUTTONS_MESSAGE,
  SERVICE_PAGE_COPY_BUTTONS_KEY,
  SERVICE_PAGE_COPY_BUTTONS_MESSAGE
} from "../utility/buttonPreferences"
import {
  CLIPBOARD_SANITIZATION_KEY,
  DEFAULT_CLIPBOARD_SANITIZATION_ENABLED
} from "../utility/clipboardSanitization"
import { defaultServices } from "../utility/defaultServices"
import {
  DEFAULT_TAB_GROUPING_ENABLED,
  resolveTabGroupingPreference,
  TAB_GROUPING_KEY
} from "../utility/iocTabs"
import type { CustomService } from "../utility/iocTypes"
import {
  DEFAULT_QUERY_MENU_ENABLED,
  DEFAULT_QUERY_PALETTE_ENABLED,
  DEFAULT_QUERY_PALETTE_SCOPE,
  QUERY_MENU_ENABLED_KEY,
  QUERY_PALETTE_ENABLED_KEY,
  QUERY_PALETTE_SCOPE_KEY,
  resolveBooleanPreference,
  resolvePaletteScope,
  type PaletteScope
} from "../utility/query/paletteBridge"
import { ensureIsDarkMode, persistIsDarkMode } from "../utility/theme"

const storage = new Storage({ area: "local" })

const Options = () => {
  const [settingsLoaded, setSettingsLoaded] = useState(false)
  const [virusTotalApiKey, setVirusTotalApiKey] = useState("")
  const [abuseIPDBApiKey, setAbuseIPDBApiKey] = useState("")
  const [nvdApiKey, setNvdApiKey] = useState("")
  const [proxyCheckApiKey, setProxyCheckApiKey] = useState("")
  const [selectedServices, setSelectedServices] = useState<{
    [key: string]: string[]
  }>(defaultServices)
  const [customServices, setCustomServices] = useState<CustomService[]>([])
  const [isDarkMode, setIsDarkMode] = useState(true)
  const [ipapiEnabled, setIpapiEnabled] = useState(false)
  const [proxyCheckEnabled, setProxyCheckEnabled] = useState(false)
  const [floatingButtonsEnabled, setFloatingButtonsEnabled] = useState(true)
  const [servicePageCopyButtonsEnabled, setServicePageCopyButtonsEnabled] =
    useState(true)
  const [clipboardSanitizationEnabled, setClipboardSanitizationEnabled] =
    useState(DEFAULT_CLIPBOARD_SANITIZATION_ENABLED)
  const [tabGroupingEnabled, setTabGroupingEnabled] = useState(
    DEFAULT_TAB_GROUPING_ENABLED
  )
  const [apiCacheTtlMinutes, setApiCacheTtlMinutes] = useState(
    DEFAULT_API_CACHE_TTL_MINUTES
  )
  const [queryPaletteEnabled, setQueryPaletteEnabled] = useState(
    DEFAULT_QUERY_PALETTE_ENABLED
  )
  const [queryMenuEnabled, setQueryMenuEnabled] = useState(
    DEFAULT_QUERY_MENU_ENABLED
  )
  const [queryPaletteScope, setQueryPaletteScope] = useState<PaletteScope>(
    DEFAULT_QUERY_PALETTE_SCOPE
  )
  const [dailyCounters, setDailyCounters] = useState({
    vt: 0,
    abuse: 0,
    nvd: 0,
    proxy: 0
  })
  const [isClearingApiCache, setIsClearingApiCache] = useState(false)
  const [apiCacheStatus, setApiCacheStatus] = useState("")
  const notifyButtonPreferenceListeners = useCallback(
    (type: string, enabled: boolean) => {
      if (typeof chrome === "undefined" || !chrome.runtime?.sendMessage) {
        return
      }
      try {
        chrome.runtime.sendMessage({
          type,
          enabled
        })
      } catch (error) {
        console.warn("Unable to broadcast button preference:", error)
      }
    },
    []
  )

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
    try {
      const keys = getCounterKeys()
      const [vt, abuse, nvd, proxy] = await Promise.all([
        storage.get<number>(keys.vt),
        storage.get<number>(keys.abuse),
        storage.get<number>(keys.nvd),
        storage.get<number>(keys.proxy)
      ])
      setDailyCounters({
        vt: vt ?? 0,
        abuse: abuse ?? 0,
        nvd: nvd ?? 0,
        proxy: proxy ?? 0
      })
    } catch (error) {
      console.warn("Unable to load daily counters:", error)
      setDailyCounters({ vt: 0, abuse: 0, nvd: 0, proxy: 0 })
    }
  }, [getCounterKeys])

  // Auto-save
  useEffect(() => {
    if (!settingsLoaded) return

    storage.set("virusTotalApiKey", virusTotalApiKey)
    storage.set("abuseIPDBApiKey", abuseIPDBApiKey)
    storage.set("nvdApiKey", nvdApiKey)
    storage.set("proxyCheckApiKey", proxyCheckApiKey)
    console.log("Saving selectedServices:", selectedServices)
    storage.set("selectedServices", selectedServices)
    storage.set("customServices", customServices)
    persistIsDarkMode(isDarkMode)
    storage.set("ipapiEnrichmentEnabled", ipapiEnabled)
    storage.set("proxyCheckEnabled", proxyCheckEnabled)
    storage.set(SELECTION_BUTTONS_KEY, floatingButtonsEnabled)
    storage.set(SERVICE_PAGE_COPY_BUTTONS_KEY, servicePageCopyButtonsEnabled)
    storage.set(CLIPBOARD_SANITIZATION_KEY, clipboardSanitizationEnabled)
    storage.set(TAB_GROUPING_KEY, tabGroupingEnabled)
    storage.set(API_CACHE_TTL_KEY, apiCacheTtlMinutes)
    storage.set(QUERY_PALETTE_ENABLED_KEY, queryPaletteEnabled)
    storage.set(QUERY_MENU_ENABLED_KEY, queryMenuEnabled)
    storage.set(QUERY_PALETTE_SCOPE_KEY, queryPaletteScope)
  }, [
    virusTotalApiKey,
    abuseIPDBApiKey,
    nvdApiKey,
    proxyCheckApiKey,
    selectedServices,
    customServices,
    isDarkMode,
    ipapiEnabled,
    proxyCheckEnabled,
    floatingButtonsEnabled,
    servicePageCopyButtonsEnabled,
    clipboardSanitizationEnabled,
    tabGroupingEnabled,
    apiCacheTtlMinutes,
    queryPaletteEnabled,
    queryMenuEnabled,
    queryPaletteScope
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
      const nvdKey = await storage.get("nvdApiKey")
      const proxyKey = await storage.get("proxyCheckApiKey")
      const selectedRaw = await storage.get("selectedServices")
      const custom = await storage.get("customServices")
      const theme = await ensureIsDarkMode()
      const ipapiSetting = await storage.get("ipapiEnrichmentEnabled")
      const proxySetting = await storage.get("proxyCheckEnabled")
      const floatingButtonsSetting = await storage.get(SELECTION_BUTTONS_KEY)
      const servicePageCopyButtonsSetting = await storage.get(
        SERVICE_PAGE_COPY_BUTTONS_KEY
      )
      const clipboardSanitizationSetting = await storage.get(
        CLIPBOARD_SANITIZATION_KEY
      )
      const tabGroupingSetting = await storage.get(TAB_GROUPING_KEY)
      const apiCacheTtlSetting = await storage.get(API_CACHE_TTL_KEY)
      const paletteSetting = await storage.get(QUERY_PALETTE_ENABLED_KEY)
      const queryMenuSetting = await storage.get(QUERY_MENU_ENABLED_KEY)
      const paletteScopeSetting = await storage.get(QUERY_PALETTE_SCOPE_KEY)

      if (vtKey) setVirusTotalApiKey(vtKey)
      if (abKey) setAbuseIPDBApiKey(abKey)
      if (nvdKey) setNvdApiKey(nvdKey)
      if (proxyKey) setProxyCheckApiKey(proxyKey)

      if (
        selectedRaw &&
        typeof selectedRaw === "object" &&
        !Array.isArray(selectedRaw)
      ) {
        setSelectedServices({
          ...defaultServices,
          ...(selectedRaw as Record<string, string[]>)
        })
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
      const shouldShowFloatingButtons = resolveSelectionButtonsPreference(
        floatingButtonsSetting
      )
      setFloatingButtonsEnabled(shouldShowFloatingButtons)
      setServicePageCopyButtonsEnabled(
        resolveServicePageCopyButtonsPreference(
          servicePageCopyButtonsSetting,
          floatingButtonsSetting
        )
      )
      setClipboardSanitizationEnabled(
        typeof clipboardSanitizationSetting === "boolean"
          ? clipboardSanitizationSetting
          : DEFAULT_CLIPBOARD_SANITIZATION_ENABLED
      )
      setTabGroupingEnabled(resolveTabGroupingPreference(tabGroupingSetting))
      setApiCacheTtlMinutes(normalizeApiCacheTtlMinutes(apiCacheTtlSetting))
      setQueryPaletteEnabled(
        resolveBooleanPreference(paletteSetting, DEFAULT_QUERY_PALETTE_ENABLED)
      )
      setQueryMenuEnabled(
        resolveBooleanPreference(queryMenuSetting, DEFAULT_QUERY_MENU_ENABLED)
      )
      setQueryPaletteScope(resolvePaletteScope(paletteScopeSetting))
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
      await testFetch(
        "VirusTotal",
        "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
        {
          "x-apikey": virusTotalApiKey
        },
        results
      )
    } else {
      results.push("⚠️ VirusTotal: Key not entered")
    }

    if (abuseIPDBApiKey) {
      await testFetch(
        "AbuseIPDB",
        "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8",
        {
          Accept: "application/json",
          Key: abuseIPDBApiKey
        },
        results
      )
    } else {
      results.push("⚠️ AbuseIPDB: Key not entered")
    }

    await testFetch(
      "NVD",
      "https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=CVE-2021-44228",
      nvdApiKey ? { apiKey: nvdApiKey } : { Accept: "application/json" },
      results
    )

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
    notifyButtonPreferenceListeners(SELECTION_BUTTONS_MESSAGE, value)
  }

  const handleServicePageCopyButtonsToggle = (value: boolean) => {
    setServicePageCopyButtonsEnabled(value)
    notifyButtonPreferenceListeners(SERVICE_PAGE_COPY_BUTTONS_MESSAGE, value)
  }

  const handleClearApiCache = async () => {
    setIsClearingApiCache(true)
    setApiCacheStatus("Clearing cached responses...")
    try {
      const response = await sendToBackground<
        Record<string, never>,
        { success?: boolean }
      >({
        name: "clear-api-cache",
        body: {}
      })
      setApiCacheStatus(
        response?.success
          ? "API response cache cleared."
          : "Unable to clear the API response cache."
      )
    } catch (error) {
      console.error("Unable to clear the API response cache:", error)
      setApiCacheStatus("Unable to clear the API response cache.")
    } finally {
      setIsClearingApiCache(false)
    }
  }

  return (
    <OptionsUI
      isDarkMode={isDarkMode}
      virusTotalApiKey={virusTotalApiKey}
      abuseIPDBApiKey={abuseIPDBApiKey}
      nvdApiKey={nvdApiKey}
      proxyCheckApiKey={proxyCheckApiKey}
      ipapiEnabled={ipapiEnabled}
      proxyCheckEnabled={proxyCheckEnabled}
      selectedServices={selectedServices}
      customServices={customServices}
      floatingButtonsEnabled={floatingButtonsEnabled}
      servicePageCopyButtonsEnabled={servicePageCopyButtonsEnabled}
      clipboardSanitizationEnabled={clipboardSanitizationEnabled}
      tabGroupingEnabled={tabGroupingEnabled}
      apiCacheTtlMinutes={apiCacheTtlMinutes}
      onDarkModeToggle={() => setIsDarkMode((prev) => !prev)}
      onServiceChange={handleServiceChange}
      onVirusTotalApiKeyChange={setVirusTotalApiKey}
      onAbuseIPDBApiKeyChange={setAbuseIPDBApiKey}
      onNvdApiKeyChange={setNvdApiKey}
      onProxyCheckApiKeyChange={handleProxyCheckKeyChange}
      onIpapiToggle={handleIpapiToggle}
      onProxyCheckToggle={handleProxyCheckToggle}
      onFloatingButtonsToggle={handleFloatingButtonsToggle}
      onServicePageCopyButtonsToggle={handleServicePageCopyButtonsToggle}
      onClipboardSanitizationToggle={setClipboardSanitizationEnabled}
      onTabGroupingToggle={setTabGroupingEnabled}
      queryPaletteEnabled={queryPaletteEnabled}
      queryMenuEnabled={queryMenuEnabled}
      queryPaletteScope={queryPaletteScope}
      onQueryPaletteToggle={setQueryPaletteEnabled}
      onQueryMenuToggle={setQueryMenuEnabled}
      onQueryPaletteScopeChange={setQueryPaletteScope}
      onApiCacheTtlChange={(minutes) =>
        setApiCacheTtlMinutes(normalizeApiCacheTtlMinutes(minutes))
      }
      onClearApiCache={handleClearApiCache}
      isClearingApiCache={isClearingApiCache}
      apiCacheStatus={apiCacheStatus}
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
