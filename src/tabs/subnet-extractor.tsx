import React, { useEffect, useMemo, useState } from "react"
import { Storage } from "@plasmohq/storage"
import "../styles/tailwind.css"
import {
  ArrowDownTrayIcon,
  ArrowPathIcon,
  ClipboardDocumentListIcon,
  PaperAirplaneIcon,
  TrashIcon
} from "@heroicons/react/24/outline"
import {
  ExtractedIPMap,
  computeIPv4Subnet,
  computeIPv6Subnet,
  extractIPAddresses,
  isPrivateIP,
  uniqueStrings
} from "../utility/utils"
import { ensureIsDarkMode, persistIsDarkMode } from "../utility/theme"

type SubnetSummary = {
  subnet: string
  version: 4 | 6
  ips: string[]
  isPrivate: boolean
}

type StatusVariant = "success" | "danger" | "info" | "warning"

const storage = new Storage({ area: "local" })
const DEFAULT_IPV4_PREFIX = 24
const DEFAULT_IPV6_PREFIX = 64

const summarizeSubnets = (
  ips: ExtractedIPMap,
  ipv4Prefix: number,
  ipv6Prefix: number
): SubnetSummary[] => {
  const map = new Map<
    string,
    { subnet: string; version: 4 | 6; ips: Set<string>; isPrivate: boolean }
  >()

  ips.ipv4.forEach((ip) => {
    const subnet = computeIPv4Subnet(ip, ipv4Prefix)
    if (!subnet) {
      return
    }
    const key = `4-${subnet}`
    if (!map.has(key)) {
      map.set(key, {
        subnet,
        version: 4,
        ips: new Set(),
        isPrivate: isPrivateIP(subnet.split("/")[0] ?? "")
      })
    }
    map.get(key)!.ips.add(ip)
  })

  ips.ipv6.forEach((ip) => {
    const subnet = computeIPv6Subnet(ip, ipv6Prefix)
    if (!subnet) {
      return
    }
    const key = `6-${subnet}`
    if (!map.has(key)) {
      map.set(key, {
        subnet,
        version: 6,
        ips: new Set(),
        isPrivate: isPrivateIP(subnet.split("/")[0] ?? "")
      })
    }
    map.get(key)!.ips.add(ip)
  })

  return Array.from(map.values())
    .map((entry) => ({
      subnet: entry.subnet,
      version: entry.version,
      ips: Array.from(entry.ips).sort(),
      isPrivate: entry.isPrivate
    }))
    .sort((a, b) => {
      if (a.version !== b.version) {
        return a.version - b.version
      }
      return a.subnet.localeCompare(b.subnet, undefined, {
        numeric: true,
        sensitivity: "base"
      })
    })
}

const SubnetExtractor = () => {
  const [inputText, setInputText] = useState("")
  const [ipv4Prefix, setIpv4Prefix] = useState(DEFAULT_IPV4_PREFIX)
  const [ipv6Prefix, setIpv6Prefix] = useState(DEFAULT_IPV6_PREFIX)
  const [isDarkMode, setIsDarkMode] = useState(true)
  const [themeLoaded, setThemeLoaded] = useState(false)
  const [isProcessing, setIsProcessing] = useState(false)
  const [summary, setSummary] = useState<SubnetSummary[]>([])
  const [status, setStatus] = useState<{ variant: StatusVariant; message: string } | null>(null)
  const [totals, setTotals] = useState({ ipv4: 0, ipv6: 0 })
  const [privateTotals, setPrivateTotals] = useState({ ipv4: 0, ipv6: 0 })

  const ipv4Subnets = useMemo(
    () => summary.filter((entry) => entry.version === 4).map((entry) => entry.subnet),
    [summary]
  )
  const ipv6Subnets = useMemo(
    () => summary.filter((entry) => entry.version === 6).map((entry) => entry.subnet),
    [summary]
  )

  const ipv4SubnetIpCount = useMemo(
    () => summary.filter((entry) => entry.version === 4).reduce((acc, entry) => acc + entry.ips.length, 0),
    [summary]
  )
  const ipv6SubnetIpCount = useMemo(
    () => summary.filter((entry) => entry.version === 6).reduce((acc, entry) => acc + entry.ips.length, 0),
    [summary]
  )

  const subnetExportPayload = useMemo(() => {
    const sections: string[] = []
    if (ipv4Subnets.length > 0) {
      sections.push(`== Subnet IPv4 /${ipv4Prefix} ==\n\n${ipv4Subnets.join("\n")}`)
    }
    if (ipv6Subnets.length > 0) {
      sections.push(`== Subnet IPv6 /${ipv6Prefix} ==\n\n${ipv6Subnets.join("\n")}`)
    }
    return sections.join("\n\n").trim()
  }, [ipv4Subnets, ipv6Subnets, ipv4Prefix, ipv6Prefix])

  const hasExportableSubnets = subnetExportPayload.length > 0

  useEffect(() => {
    const loadPreferences = async () => {
      const savedInput = await storage.get<string>("subnetExtractorInput")
      const savedIpv4 = await storage.get<number>("subnetExtractorIpv4")
      const savedIpv6 = await storage.get<number>("subnetExtractorIpv6")
      const savedTheme = await ensureIsDarkMode()

      if (typeof savedInput === "string") {
        setInputText(savedInput)
      }
      if (typeof savedIpv4 === "number") {
        setIpv4Prefix(savedIpv4)
      }
      if (typeof savedIpv6 === "number") {
        setIpv6Prefix(savedIpv6)
      }
      setIsDarkMode(savedTheme)
    }

    loadPreferences().finally(() => setThemeLoaded(true))
  }, [])

  useEffect(() => {
    storage.set("subnetExtractorInput", inputText)
  }, [inputText])

  useEffect(() => {
    storage.set("subnetExtractorIpv4", ipv4Prefix)
  }, [ipv4Prefix])

  useEffect(() => {
    storage.set("subnetExtractorIpv6", ipv6Prefix)
  }, [ipv6Prefix])

  useEffect(() => {
    if (!themeLoaded) return
    persistIsDarkMode(isDarkMode)
    if (typeof document !== "undefined") {
      document.body.className = isDarkMode ? "dark-mode" : "light-mode"
    }
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
    return () => {
      chrome.storage.onChanged.removeListener(listener)
    }
  }, [])

  useEffect(() => {
    const trimmed = inputText.trim()
    if (!trimmed) {
      setIsProcessing(false)
      setSummary([])
      setTotals({ ipv4: 0, ipv6: 0 })
      setPrivateTotals({ ipv4: 0, ipv6: 0 })
      setStatus(null)
      return
    }

    setIsProcessing(true)
    setStatus({ variant: "info", message: "Extracting subnets..." })

    let cancelled = false
    const timer = setTimeout(() => {
      if (cancelled) {
        return
      }

      try {
        const ips = extractIPAddresses(trimmed)
        if (cancelled) {
          return
        }

        setTotals({ ipv4: ips.ipv4.length, ipv6: ips.ipv6.length })
        setPrivateTotals({
          ipv4: ips.ipv4.filter((ip) => isPrivateIP(ip)).length,
          ipv6: ips.ipv6.filter((ip) => isPrivateIP(ip)).length
        })

        if (ips.ipv4.length === 0 && ips.ipv6.length === 0) {
          setSummary([])
          setStatus({
            variant: "warning",
            message: "No valid IPv4 or IPv6 addresses were detected."
          })
        } else {
          const computed = summarizeSubnets(ips, ipv4Prefix, ipv6Prefix)
          setSummary(computed)
          setStatus({
            variant: "success",
            message: `Extracted ${computed.length} subnet${computed.length === 1 ? "" : "s"}.`
          })
        }
      } catch (error) {
        console.error("Subnet extraction failed:", error)
        if (!cancelled) {
          setSummary([])
          setTotals({ ipv4: 0, ipv6: 0 })
          setPrivateTotals({ ipv4: 0, ipv6: 0 })
          setStatus({
            variant: "danger",
            message: "Failed to extract subnets. Please try again."
          })
        }
      } finally {
        if (!cancelled) {
          setIsProcessing(false)
        }
      }
    }, 250)

    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [inputText, ipv4Prefix, ipv6Prefix])

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) {
      return
    }

    const reader = new FileReader()
    reader.onload = (loadEvent) => {
      const content = String(loadEvent.target?.result ?? "")
      setInputText(content)
    }
    reader.readAsText(file)
    event.target.value = ""
  }

  const handleClearInput = () => {
    setInputText("")
    setSummary([])
    setTotals({ ipv4: 0, ipv6: 0 })
    setStatus(null)
  }

  const handleIpv4PrefixChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const value = Number(event.target.value)
    const nextValue = Number.isFinite(value) ? Math.min(32, Math.max(0, value)) : DEFAULT_IPV4_PREFIX
    setIpv4Prefix(nextValue)
  }

  const handleIpv6PrefixChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const value = Number(event.target.value)
    const nextValue = Number.isFinite(value) ? Math.min(128, Math.max(0, value)) : DEFAULT_IPV6_PREFIX
    setIpv6Prefix(nextValue)
  }

  const handleRefreshInput = () => {
    const trimmed = inputText.trim()
    if (!trimmed) {
      setInputText("")
      setSummary([])
      setTotals({ ipv4: 0, ipv6: 0 })
      setStatus({ variant: "warning", message: "Add at least one IPv4 or IPv6 address before refreshing." })
      return
    }

    try {
      const ips = extractIPAddresses(trimmed)
      const uniqueIpv4 = uniqueStrings(ips.ipv4)
      const uniqueIpv6 = uniqueStrings(ips.ipv6)
      if (uniqueIpv4.length === 0 && uniqueIpv6.length === 0) {
        setInputText("")
        setSummary([])
        setTotals({ ipv4: 0, ipv6: 0 })
        setStatus({ variant: "warning", message: "No valid IPv4 or IPv6 addresses were detected." })
        return
      }

      const sections: string[] = []
      if (uniqueIpv4.length > 0) {
        sections.push(uniqueIpv4.join("\n"))
      }
      if (uniqueIpv6.length > 0) {
        sections.push(uniqueIpv6.join("\n"))
      }
      setInputText(sections.join("\n"))
      setStatus({
        variant: "success",
        message: `Detected ${uniqueIpv4.length + uniqueIpv6.length} unique IP${
          uniqueIpv4.length + uniqueIpv6.length === 1 ? "" : "s"
        }.`
      })
    } catch (error) {
      console.error("Refresh failed:", error)
      setStatus({
        variant: "danger",
        message: "Unable to refresh the input. Please try again."
      })
    }
  }

  const handleCopyAll = async () => {
    if (!hasExportableSubnets) {
      setStatus({
        variant: "warning",
        message: "There are no subnets to copy yet."
      })
      return
    }

    try {
      await navigator.clipboard.writeText(subnetExportPayload)
      setStatus({
        variant: "success",
        message: "Subnet list copied to clipboard."
      })
    } catch (error) {
      console.error("Copy failed:", error)
      setStatus({
        variant: "danger",
        message: "Unable to copy the subnet list."
      })
    }
  }

  const handleSendToSubnetCheck = async () => {
    if (summary.length === 0) {
      setStatus({ variant: "warning", message: "Extract subnets before opening the AbuseIPDB check." })
      return
    }

    try {
      const payload = summary.map((entry) => entry.subnet)
      await storage.set("subnetCheckPrefill", payload)
      const url = chrome.runtime.getURL("/tabs/subnet-check.html")
      chrome.tabs.create({ url })
      setStatus({
        variant: "success",
        message: "Subnet list sent to the AbuseIPDB checker."
      })
    } catch (error) {
      console.error("Failed to open subnet check:", error)
      setStatus({
        variant: "danger",
        message: "Unable to open the subnet check page."
      })
    }
  }

  const handleExportTxt = () => {
    if (!hasExportableSubnets) {
      setStatus({
        variant: "warning",
        message: "There are no subnets to export yet."
      })
      return
    }

    try {
      const blob = new Blob([subnetExportPayload], {
        type: "text/plain;charset=utf-8"
      })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement("a")
      anchor.href = url
      anchor.download = "subnets.txt"
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      URL.revokeObjectURL(url)
      setStatus({
        variant: "success",
        message: "Subnet list exported to subnets.txt."
      })
    } catch (error) {
      console.error("Export failed:", error)
      setStatus({
        variant: "danger",
        message: "Unable to export the subnet list."
      })
    }
  }

  const handleCopySingle = async (entry: SubnetSummary) => {
    try {
      const payload = `${entry.subnet} (IPv${entry.version})\n${entry.ips.join("\n")}`
      await navigator.clipboard.writeText(payload)
      setStatus({
        variant: "success",
        message: `${entry.subnet} copied to clipboard.`
      })
    } catch (error) {
      console.error("Copy failed:", error)
      setStatus({
        variant: "danger",
        message: "Unable to copy the selected subnet."
      })
    }
  }

  const handleCopySubnetGroup = async (family: "ipv4" | "ipv6") => {
    const list = family === "ipv4" ? ipv4Subnets : ipv6Subnets
    if (list.length === 0) {
      setStatus({
        variant: "warning",
        message: `No IPv${family === "ipv4" ? 4 : 6} subnets to copy.`
      })
      return
    }

    try {
      await navigator.clipboard.writeText(list.join("\n"))
      setStatus({
        variant: "success",
        message: `IPv${family === "ipv4" ? 4 : 6} subnet list copied.`
      })
    } catch (error) {
      console.error("Copy failed:", error)
      setStatus({
        variant: "danger",
        message: "Unable to copy the subnet list."
      })
    }
  }

  const isSubnetPrivate = (entry: SubnetSummary): boolean => {
    const base = entry.subnet.split("/")[0] ?? ""
    return isPrivateIP(base)
  }

const statusTone: Record<StatusVariant, string> = {
  success: "border-emerald-400/60 bg-emerald-500/10 text-emerald-100",
  danger: "border-rose-500/40 bg-rose-500/10 text-rose-100",
  info: "border-sky-500/40 bg-sky-500/10 text-sky-100",
  warning: "border-amber-500/50 bg-amber-500/10 text-amber-100"
}

  return (
    <div className="min-h-screen bg-socx-cloud px-4 py-6 font-inter text-socx-ink dark:bg-socx-night dark:text-white">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
        <header className="rounded-socx-lg border border-socx-border-light bg-white/90 p-6 dark:border-socx-border-dark dark:bg-socx-night-soft/80">
          <p className="text-xs font-semibold uppercase tracking-[0.4em] text-socx-muted dark:text-socx-muted-dark">
            SOCx
          </p>
          <h1 className="mt-1 text-2xl font-semibold">Subnet Extractor</h1>
          <p className="text-sm text-socx-muted dark:text-socx-muted-dark">
            Normalize large IP lists, compute IPv4/IPv6 subnets and hand over the result to AbuseIPDB.
          </p>
        </header>

        <div className="grid gap-6 lg:grid-cols-2">
          <section className="space-y-4 rounded-socx-lg border border-socx-border-light bg-white/90 p-5 dark:border-socx-border-dark dark:bg-socx-night-soft/80">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold">Paste IP addresses</p>
                <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
                  Supports raw text, defanged entries and mixed IPv4/IPv6 streams.
                </p>
              </div>
              <button
                type="button"
                onClick={handleRefreshInput}
                disabled={isProcessing || !inputText.trim()}
                className="inline-flex items-center gap-1 rounded-full border border-socx-border-light px-3 py-1 text-xs font-semibold text-socx-muted transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-40 dark:border-socx-border-dark">
                <ArrowPathIcon className="h-4 w-4" />
                Refresh
              </button>
            </div>
            <textarea
              rows={16}
              placeholder="Paste IPv4/IPv6 addresses, defanged entries, or raw text..."
              value={inputText}
              onChange={(event) => setInputText(event.target.value)}
              className="socx-scroll w-full rounded-2xl border border-socx-border-light bg-white/95 px-4 py-3 text-sm text-socx-ink outline-none transition focus:border-socx-accent focus:ring-2 focus:ring-socx-accent/40 dark:border-socx-border-dark dark:bg-socx-panel/60 dark:text-white"
            />

            <div className="space-y-4 rounded-2xl border border-socx-border-light bg-white/80 p-4 dark:border-socx-border-dark dark:bg-socx-panel/40">
              <div className="flex items-center justify-between">
                <p className="text-sm font-semibold">
                  IPv4 Subnets ({ipv4Subnets.length} networks / {ipv4SubnetIpCount} IPs)
                </p>
                <button
                  type="button"
                  onClick={() => handleCopySubnetGroup("ipv4")}
                  className="inline-flex items-center gap-1 rounded-full border border-socx-border-light px-3 py-1 text-xs font-semibold text-socx-muted transition hover:border-socx-accent hover:text-socx-accent dark:border-socx-border-dark">
                  <ClipboardDocumentListIcon className="h-4 w-4" />
                  Copy
                </button>
              </div>
              <textarea
                readOnly
                rows={4}
                value={ipv4Subnets.join("\n")}
                placeholder="No IPv4 subnets yet."
                className="socx-scroll w-full rounded-xl border border-dashed border-socx-border-light bg-transparent px-3 py-2 text-xs text-socx-ink outline-none dark:border-socx-border-dark dark:text-socx-muted-dark"
              />
              <div className="flex items-center justify-between">
                <p className="text-sm font-semibold">
                  IPv6 Subnets ({ipv6Subnets.length} networks / {ipv6SubnetIpCount} IPs)
                </p>
                <button
                  type="button"
                  onClick={() => handleCopySubnetGroup("ipv6")}
                  className="inline-flex items-center gap-1 rounded-full border border-socx-border-light px-3 py-1 text-xs font-semibold text-socx-muted transition hover:border-socx-accent hover:text-socx-accent dark:border-socx-border-dark">
                  <ClipboardDocumentListIcon className="h-4 w-4" />
                  Copy
                </button>
              </div>
              <textarea
                readOnly
                rows={4}
                value={ipv6Subnets.join("\n")}
                placeholder="No IPv6 subnets yet."
                className="socx-scroll w-full rounded-xl border border-dashed border-socx-border-light bg-transparent px-3 py-2 text-xs text-socx-ink outline-none dark:border-socx-border-dark dark:text-socx-muted-dark"
              />
            </div>
          </section>

          <section className="space-y-4 rounded-socx-lg border border-socx-border-light bg-white/90 p-5 dark:border-socx-border-dark dark:bg-socx-night-soft/80">
            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-1">
                <label className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.3em] text-socx-muted dark:text-socx-muted-dark">
                  <ArrowDownTrayIcon className="h-4 w-4" />
                  Upload .txt file
                </label>
                <input
                  type="file"
                  accept=".txt"
                  onChange={handleFileUpload}
                  className="block w-full text-sm text-socx-muted file:mr-4 file:rounded-full file:border-0 file:bg-socx-accent file:px-4 file:py-2 file:text-sm file:font-semibold file:text-socx-ink hover:file:bg-socx-accent-strong"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-semibold uppercase tracking-[0.3em] text-socx-muted dark:text-socx-muted-dark">
                  Actions
                </label>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={handleClearInput}
                    disabled={isProcessing}
                    className="inline-flex flex-1 items-center justify-center gap-1 rounded-full border border-socx-border-light px-3 py-2 text-xs font-semibold text-socx-muted transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-40 dark:border-socx-border-dark">
                    <TrashIcon className="h-4 w-4" />
                    Clear
                  </button>
                  <button
                    type="button"
                    onClick={handleCopyAll}
                    disabled={!hasExportableSubnets || isProcessing}
                    className="inline-flex flex-1 items-center justify-center gap-1 rounded-full border border-socx-border-light px-3 py-2 text-xs font-semibold text-socx-muted transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-40 dark:border-socx-border-dark">
                    <ClipboardDocumentListIcon className="h-4 w-4" />
                    Copy
                  </button>
                </div>
              </div>
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-1">
                <label className="text-xs uppercase tracking-[0.2em] text-socx-muted dark:text-socx-muted-dark">
                  IPv4 prefix
                </label>
                <input
                  type="number"
                  min={0}
                  max={32}
                  value={ipv4Prefix}
                  onChange={handleIpv4PrefixChange}
                  className="w-full rounded-xl border border-socx-border-light bg-white/90 px-3 py-2 text-sm text-socx-ink outline-none focus:border-socx-accent focus:ring-2 focus:ring-socx-accent/40 dark:border-socx-border-dark dark:bg-socx-panel/50 dark:text-white"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs uppercase tracking-[0.2em] text-socx-muted dark:text-socx-muted-dark">
                  IPv6 prefix
                </label>
                <input
                  type="number"
                  min={0}
                  max={128}
                  value={ipv6Prefix}
                  onChange={handleIpv6PrefixChange}
                  className="w-full rounded-xl border border-socx-border-light bg-white/90 px-3 py-2 text-sm text-socx-ink outline-none focus:border-socx-accent focus:ring-2 focus:ring-socx-accent/40 dark:border-socx-border-dark dark:bg-socx-panel/50 dark:text-white"
                />
              </div>
            </div>

            <div className="grid gap-2 sm:grid-cols-2">
              <button
                type="button"
                onClick={handleExportTxt}
                disabled={!hasExportableSubnets || isProcessing}
                className="inline-flex items-center justify-center gap-2 rounded-full border border-socx-border-light px-4 py-3 text-sm font-semibold text-socx-ink transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-40 dark:border-socx-border-dark dark:text-white">
                <ArrowDownTrayIcon className="h-5 w-5" />
                Export TXT
              </button>
              <button
                type="button"
                onClick={handleSendToSubnetCheck}
                disabled={!hasExportableSubnets || isProcessing}
                className="inline-flex items-center justify-center gap-2 rounded-full bg-socx-accent px-4 py-3 text-sm font-semibold text-socx-ink transition hover:bg-socx-accent-strong disabled:cursor-not-allowed disabled:opacity-40">
                <PaperAirplaneIcon className="h-5 w-5" />
                AbuseIPDB Subnet Check
              </button>
            </div>

            {status && (
              <div className={`rounded-2xl border px-4 py-3 text-sm ${statusTone[status.variant]}`}>
                {status.message}
              </div>
            )}

            <div className="rounded-2xl border border-socx-border-light bg-white/80 p-4 dark:border-socx-border-dark dark:bg-socx-panel/40">
              <p className="text-xs font-semibold uppercase tracking-[0.3em] text-socx-muted dark:text-socx-muted-dark">
                Overview
              </p>
              <div className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
                <div className="rounded-xl border border-dashed border-socx-border-light px-3 py-2 dark:border-socx-border-dark">
                  IPv4 IPs <span className="float-right font-semibold">{totals.ipv4}</span>
                </div>
                <div className="rounded-xl border border-dashed border-socx-border-light px-3 py-2 dark:border-socx-border-dark">
                  IPv6 IPs <span className="float-right font-semibold">{totals.ipv6}</span>
                </div>
                <div className="rounded-xl border border-dashed border-socx-border-light px-3 py-2 dark:border-socx-border-dark">
                  Detected subnets <span className="float-right font-semibold">{summary.length}</span>
                </div>
                <div className="rounded-xl border border-dashed border-socx-border-light px-3 py-2 dark:border-socx-border-dark">
                  Private hits <span className="float-right font-semibold">{privateTotals.ipv4 + privateTotals.ipv6}</span>
                </div>
              </div>
            </div>

            <div className="rounded-2xl border border-socx-border-light bg-white/90 p-4 dark:border-socx-border-dark dark:bg-socx-panel/50">
              <p className="text-sm font-semibold">Detected subnets</p>
              {summary.length === 0 ? (
                <p className="mt-2 text-sm text-socx-muted dark:text-socx-muted-dark">
                  No subnets yet. Paste IPs or upload a file to generate the subnet list automatically.
                </p>
              ) : (
                <div className="mt-3 space-y-3">
                  {summary.map((entry) => {
                    const isPrivate = isSubnetPrivate(entry)
                    return (
                      <div
                        key={`${entry.version}-${entry.subnet}`}
                        className={`rounded-2xl border p-4 ${isPrivate ? "border-rose-500/40 bg-rose-500/5" : "border-socx-border-light dark:border-socx-border-dark"}`}>
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="space-y-1">
                            <p className="font-semibold">{entry.subnet}</p>
                            <div className="flex flex-wrap gap-2 text-xs">
                              <span className="rounded-full bg-socx-cloud-soft px-2 py-1 text-socx-ink dark:bg-socx-panel/40 dark:text-white">
                                IPv{entry.version}
                              </span>
                              <span className="rounded-full bg-socx-cloud-soft px-2 py-1 text-socx-ink dark:bg-socx-panel/40 dark:text-white">
                                {entry.ips.length} IPs
                              </span>
                              <span
                                className={`rounded-full px-2 py-1 ${
                                  isPrivate ? "bg-rose-500/20 text-rose-200" : "bg-emerald-500/20 text-emerald-200"
                                }`}>
                                {isPrivate ? "Private" : "Public"}
                              </span>
                            </div>
                          </div>
                          <button
                            type="button"
                            onClick={() => handleCopySingle(entry)}
                            className="inline-flex items-center gap-1 rounded-full border border-socx-border-light px-3 py-1 text-xs font-semibold text-socx-muted transition hover:border-socx-accent hover:text-socx-accent dark:border-socx-border-dark">
                            <ClipboardDocumentListIcon className="h-4 w-4" />
                            Copy
                          </button>
                        </div>
                        <details className="mt-3 text-xs">
                          <summary className="cursor-pointer font-semibold text-socx-muted dark:text-socx-muted-dark">
                            Show member IPs
                          </summary>
                          <pre className="socx-scroll mt-2 whitespace-pre-wrap rounded-xl border border-dashed border-socx-border-light bg-black/5 px-3 py-2 font-mono text-[11px] text-socx-ink dark:border-socx-border-dark dark:bg-white/5 dark:text-socx-muted-dark">
                            {entry.ips.join("\n")}
                          </pre>
                        </details>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          </section>
        </div>
      </div>
    </div>
  )
}

export default SubnetExtractor
