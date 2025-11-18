import React, { useState } from "react"
import {
  MdDarkMode,
  MdLightMode,
  MdVisibility,
  MdVisibilityOff,
  MdShield,
  MdOutlineKey,
  MdAddCircle,
  MdDelete
} from "react-icons/md"
import { servicesConfig } from "../utility/servicesConfig"
import { supportedIOCTypes, type IOCType, type CustomService } from "../utility/iocTypes"
import { CheckCircleIcon } from "@heroicons/react/24/solid"

interface OptionsUIProps {
  isDarkMode: boolean
  virusTotalApiKey: string
  abuseIPDBApiKey: string
  proxyCheckApiKey: string
  ipapiEnabled: boolean
  proxyCheckEnabled: boolean
  selectedServices: { [key: string]: string[] }
  customServices: CustomService[]
  onDarkModeToggle: () => void
  onServiceChange: (type: string, service: string) => void
  onVirusTotalApiKeyChange: (val: string) => void
  onAbuseIPDBApiKeyChange: (val: string) => void
  onProxyCheckApiKeyChange: (val: string) => void
  onIpapiToggle: (value: boolean) => void
  onProxyCheckToggle: (value: boolean) => void
  onTestKeys: () => void
  onAddCustomService: (s: CustomService) => void
  onRemoveCustomService: (index: number) => void
  dailyCounters: {
    vt: number
    abuse: number
    proxy: number
  }
}

const cardClass =
  "rounded-socx-lg border border-socx-border-light bg-white/90 p-6 shadow-sm dark:border-socx-border-dark dark:bg-socx-night-soft/80"
const labelClass =
  "text-xs font-semibold uppercase tracking-[0.3em] text-socx-muted dark:text-socx-muted-dark"
const inputClass =
  "w-full rounded-lg border border-socx-border-light bg-white/85 px-4 py-2.5 text-sm text-socx-ink outline-none transition focus:border-socx-accent focus:ring-2 focus:ring-socx-accent/40 dark:border-socx-border-dark dark:bg-socx-panel/60 dark:text-white"
const chipBase =
  "socx-chip border-socx-border-light bg-socx-cloud-soft/70 text-socx-ink hover:border-socx-accent dark:border-socx-border-dark dark:bg-socx-panel/40 dark:text-white"
const chipActive = "socx-chip-active"

const OptionsUI: React.FC<OptionsUIProps> = ({
  isDarkMode,
  virusTotalApiKey,
  abuseIPDBApiKey,
  proxyCheckApiKey,
  ipapiEnabled,
  proxyCheckEnabled,
  selectedServices,
  customServices,
  onDarkModeToggle,
  onServiceChange,
  onVirusTotalApiKeyChange,
  onAbuseIPDBApiKeyChange,
  onProxyCheckApiKeyChange,
  onIpapiToggle,
  onProxyCheckToggle,
  onTestKeys,
  onAddCustomService,
  onRemoveCustomService,
  dailyCounters
}) => {
  const [showKeys, setShowKeys] = useState(false)
  const [newType, setNewType] = useState<IOCType>("IP")
  const [newName, setNewName] = useState("")
  const [newURL, setNewURL] = useState("")

  const inputType = showKeys ? "text" : "password"

  const handleIpapiToggle = () => {
    const next = !ipapiEnabled
    if (next && proxyCheckEnabled) {
      alert("Disable ProxyCheck enrichment before enabling IPAPI.")
      return
    }
    onIpapiToggle(next)
  }

  const handleProxyToggle = () => {
    const next = !proxyCheckEnabled
    if (next) {
      if (!proxyCheckApiKey) {
        alert("Enter a ProxyCheck API key first.")
        return
      }
      if (ipapiEnabled) {
        alert("Disable IPAPI enrichment before enabling ProxyCheck.")
        return
      }
    }
    onProxyCheckToggle(next)
  }

  const apiFields = [
    {
      id: "vt",
      label: "VirusTotal",
      value: virusTotalApiKey,
      placeholder: "Enter your VirusTotal API key",
      onChange: onVirusTotalApiKeyChange,
      counter: dailyCounters.vt,
      tone: "info"
    },
    {
      id: "abuse",
      label: "AbuseIPDB",
      value: abuseIPDBApiKey,
      placeholder: "Enter your AbuseIPDB API key",
      onChange: onAbuseIPDBApiKeyChange,
      counter: dailyCounters.abuse,
      tone: "danger"
    },
    {
      id: "proxy",
      label: "ProxyCheck.io",
      value: proxyCheckApiKey,
      placeholder: "Enter your ProxyCheck API key",
      onChange: onProxyCheckApiKeyChange,
      counter: dailyCounters.proxy,
      tone: "secondary"
    }
  ]

  const enrichments = [
    {
      id: "ipapi",
      label: "Enable IPAPI enrichment",
      helper: "Adds VPN/Proxy signals when Abuse checks are triggered.",
      enabled: ipapiEnabled,
      onToggle: handleIpapiToggle,
      disabled: false
    },
    {
      id: "proxycheck",
      label: "Enable ProxyCheck enrichment",
      helper: "Requires an active ProxyCheck API key.",
      enabled: proxyCheckEnabled,
      onToggle: handleProxyToggle,
      disabled: !proxyCheckApiKey && !proxyCheckEnabled
    }
  ]

  const handleAddService = () => {
    if (!newName.trim() || !newURL.includes("{ioc}")) {
      alert("Enter a valid name and a URL containing {ioc}")
      return
    }
    onAddCustomService({
      type: newType,
      name: newName.trim(),
      url: newURL.trim()
    })
    setNewName("")
    setNewURL("")
  }

  return (
    <div className="min-h-screen bg-socx-cloud px-4 py-8 text-socx-ink dark:bg-socx-night dark:text-white">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
        <header className="flex flex-col gap-4 rounded-socx-lg border border-socx-border-light bg-white/80 p-5 dark:border-socx-border-dark dark:bg-socx-night-soft/70 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.4em] text-socx-muted dark:text-socx-muted-dark">
              SOCx Control Room
            </p>
            <h1 className="mt-2 text-2xl font-semibold">Extension Settings</h1>
            <p className="text-sm text-socx-muted dark:text-socx-muted-dark">
              Manage API keys, enrichment engines and custom lookups used across the extension.
            </p>
          </div>
          <button
            type="button"
            onClick={onDarkModeToggle}
            className="inline-flex items-center gap-2 rounded-full border border-socx-border-light px-5 py-3 text-sm font-semibold text-socx-ink transition hover:border-socx-accent focus-visible:outline-none focus-visible:shadow-socx-focus dark:border-socx-border-dark dark:text-white">
            {isDarkMode ? (
              <>
                <MdLightMode /> Light mode
              </>
            ) : (
              <>
                <MdDarkMode /> Dark mode
              </>
            )}
          </button>
        </header>

        <section className={`grid gap-4 md:grid-cols-2 ${cardClass}`}>
          {apiFields.map(({ id, label, value, placeholder, onChange, counter }) => (
            <div key={id} className="space-y-2">
              <div className="flex items-center justify-between">
                <p className="text-sm font-medium">{label}</p>
                <span className="inline-flex items-center rounded-full bg-socx-cloud-soft px-2 py-1 text-[11px] font-semibold uppercase tracking-[0.2em] text-socx-muted dark:bg-socx-panel/60 dark:text-socx-muted-dark">
                  Today: {counter}
                </span>
              </div>
              <div className="relative">
                <input
                  type={inputType}
                  value={value}
                  onChange={(event) => onChange(event.target.value)}
                  placeholder={placeholder}
                  className={inputClass}
                />
                <button
                  type="button"
                  onClick={() => setShowKeys((prev) => !prev)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 rounded-full p-1.5 text-socx-muted transition hover:text-socx-accent"
                  aria-label="Toggle key visibility">
                  {showKeys ? <MdVisibilityOff /> : <MdVisibility />}
                </button>
              </div>
            </div>
          ))}
          <div className="md:col-span-2">
            <button
              type="button"
              onClick={onTestKeys}
              className="flex w-full items-center justify-center gap-2 rounded-full border border-socx-border-light bg-white/70 px-4 py-3 text-sm font-semibold text-socx-ink transition hover:border-socx-accent hover:text-socx-accent focus-visible:outline-none focus-visible:shadow-socx-focus dark:border-socx-border-dark dark:bg-socx-panel/60 dark:text-white">
              <MdOutlineKey />
              Test API keys
            </button>
          </div>
          <div className="md:col-span-2 space-y-3">
            <p className={labelClass}>Enrichments</p>
            <div className="grid gap-3 md:grid-cols-2">
              {enrichments.map(({ id, label, helper, enabled, onToggle, disabled }) => (
                <div
                  key={id}
                  className="flex items-center justify-between rounded-xl border border-socx-border-light bg-white/80 px-4 py-3 dark:border-socx-border-dark dark:bg-socx-panel/50">
                  <div>
                    <p className="text-sm font-semibold">{label}</p>
                    <p className="text-xs text-socx-muted dark:text-socx-muted-dark">{helper}</p>
                  </div>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={enabled}
                    disabled={disabled}
                    onClick={onToggle}
                    className={`relative inline-flex h-7 w-12 items-center rounded-full border transition ${
                      enabled
                        ? "border-socx-accent bg-socx-accent/90"
                        : "border-socx-border-light bg-white dark:border-socx-border-dark dark:bg-socx-panel"
                    } ${disabled ? "opacity-40 cursor-not-allowed" : ""}`}>
                    <span
                      className={`inline-block h-5 w-5 rounded-full bg-white shadow transition ${
                        enabled ? "translate-x-5" : "translate-x-1"
                      }`}
                    />
                  </button>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className={cardClass}>
          <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
            <div>
              <p className={labelClass}>Lookup grid</p>
              <h2 className="text-xl font-semibold">Enabled services per IOC type</h2>
            </div>
            <div className="flex items-center gap-2 text-xs text-socx-muted dark:text-socx-muted-dark">
              <MdShield />
              Auto-launch matrix used in Magic IOC & Bulk tools.
            </div>
          </div>
          <div className="mt-4 grid gap-4 md:grid-cols-2">
            {Object.entries(servicesConfig.availableServices).map(([type, services]) => (
              <div key={type} className="rounded-2xl border border-socx-border-light p-4 dark:border-socx-border-dark">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-semibold">{type}</p>
                  <span className="text-xs text-socx-muted dark:text-socx-muted-dark">
                    {selectedServices[type]?.length ?? 0}/{services.length} active
                  </span>
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {services.map((service) => {
                    const checked = selectedServices[type]?.includes(service)
                    return (
                      <button
                        type="button"
                        key={`${type}-${service}`}
                        onClick={() => onServiceChange(type, service)}
                        className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold transition ${
                          checked
                            ? "border-socx-accent bg-socx-accent text-socx-ink shadow-socx-focus"
                            : "border-socx-border-light bg-white/80 text-socx-ink hover:border-socx-accent dark:border-socx-border-dark dark:bg-socx-panel/40 dark:text-white"
                        }`}
                        aria-pressed={checked}>
                        <span>{service}</span>
                        <CheckCircleIcon
                          className={`h-4 w-4 ${checked ? "text-socx-ink" : "text-socx-muted dark:text-socx-muted-dark"}`}
                        />
                      </button>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className={`grid gap-4 md:grid-cols-2`}>
          <div className={cardClass}>
            <p className={labelClass}>Custom services</p>
            <h2 className="text-xl font-semibold">Add private lookups</h2>
            <p className="text-sm text-socx-muted dark:text-socx-muted-dark">
              Provide a name and URL template with the {"{ioc}"} placeholder. These appear in the Magic IOC context menu.
            </p>
            <div className="mt-4 space-y-3">
              <div className="space-y-1">
                <label className="text-xs uppercase tracking-[0.2em] text-socx-muted dark:text-socx-muted-dark">
                  IOC type
                </label>
                <select
                  value={newType}
                  onChange={(event) => setNewType(event.target.value as IOCType)}
                  className={`${inputClass} bg-white dark:bg-socx-panel/60`}>
                  {supportedIOCTypes.map((type) => (
                    <option key={type} value={type}>
                      {type}
                    </option>
                  ))}
                </select>
              </div>
              <div className="space-y-1">
                <label className="text-xs uppercase tracking-[0.2em] text-socx-muted dark:text-socx-muted-dark">
                  Service name
                </label>
                <input
                  type="text"
                  value={newName}
                  onChange={(event) => setNewName(event.target.value)}
                  placeholder="e.g., Internal Lookup"
                  className={inputClass}
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs uppercase tracking-[0.2em] text-socx-muted dark:text-socx-muted-dark">
                  URL template
                </label>
                <input
                  type="text"
                  value={newURL}
                  onChange={(event) => setNewURL(event.target.value)}
                  placeholder="https://example.local/search/{ioc}"
                  className={inputClass}
                />
              </div>
              <button
                type="button"
                onClick={handleAddService}
                className="flex w-full items-center justify-center gap-2 rounded-full bg-socx-accent px-4 py-3 text-sm font-semibold text-socx-ink transition hover:bg-socx-accent-strong focus-visible:outline-none focus-visible:shadow-socx-focus">
                <MdAddCircle />
                Add service
              </button>
            </div>
          </div>

          <div className={`${cardClass} space-y-4`}>
            <div>
              <p className={labelClass}>Configured entries</p>
              <h2 className="text-xl font-semibold">Custom lookup catalog</h2>
            </div>
            {customServices.length === 0 ? (
              <p className="text-sm text-socx-muted dark:text-socx-muted-dark">
                No custom services defined yet.
              </p>
            ) : (
              <div className="space-y-3">
                {customServices.map((service, index) => (
                  <div
                    key={`${service.name}-${index}`}
                    className="rounded-2xl border border-socx-border-light p-4 dark:border-socx-border-dark">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <p className="text-sm font-semibold">{service.name}</p>
                        <p className="text-xs text-socx-muted dark:text-socx-muted-dark">{service.type}</p>
                      </div>
                      <button
                        type="button"
                        onClick={() => onRemoveCustomService(index)}
                        className="inline-flex items-center gap-1 rounded-full border border-socx-border-light px-3 py-1 text-xs font-semibold text-socx-muted transition hover:border-socx-accent hover:text-socx-accent dark:border-socx-border-dark">
                        <MdDelete />
                        Remove
                      </button>
                    </div>
                    <p className="mt-2 break-all text-xs text-socx-muted dark:text-socx-muted-dark">{service.url}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  )
}

export default OptionsUI
