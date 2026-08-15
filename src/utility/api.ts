import { Storage } from "@plasmohq/storage"

import {
  apiRequestCoordinator,
  ApiRequestError,
  type ApiProvider
} from "./requestCoordinator"

const storage = new Storage({ area: "local" })

const parseRetryAfterMs = (response: Response): number | undefined => {
  const value = response.headers.get("Retry-After")
  if (!value) return undefined
  const seconds = Number(value)
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000)
  const retryDate = new Date(value).getTime()
  return Number.isNaN(retryDate)
    ? undefined
    : Math.max(0, retryDate - Date.now())
}

const readErrorDetails = async (response: Response): Promise<string> => {
  const headerMessage = response.headers.get("message")
  if (headerMessage) return headerMessage
  try {
    const text = await response.text()
    return text || response.statusText
  } catch {
    return response.statusText
  }
}

const fetchProviderJson = <T>({
  provider,
  cacheKey,
  url,
  init,
  counterName,
  notFoundAsNull = false,
  minimumIntervalMs
}: {
  provider: ApiProvider
  cacheKey: string
  url: string
  init: RequestInit
  counterName: string
  notFoundAsNull?: boolean
  minimumIntervalMs?: number
}): Promise<T | null> =>
  apiRequestCoordinator.run({
    provider,
    cacheKey,
    minimumIntervalMs,
    request: async () => {
      const response = await fetch(url, init)
      if (notFoundAsNull && response.status === 404) return null
      if (!response.ok) {
        const details = await readErrorDetails(response)
        throw new ApiRequestError(
          `${provider} API error (${response.status}): ${details}`,
          response.status,
          parseRetryAfterMs(response)
        )
      }
      const payload = (await response.json()) as T
      await incrementDailyCounter(counterName)
      return payload
    }
  })

const base64UrlId = (value: string): string => {
  const encodeWithBrowser = (): string | null => {
    if (typeof btoa !== "function") {
      return null
    }
    try {
      return btoa(unescape(encodeURIComponent(value)))
    } catch (err) {
      console.warn("btoa failed to encode URL, trying Buffer fallback:", err)
      return null
    }
  }

  const encodeWithBuffer = (): string | null => {
    const bufferCtor = (
      globalThis as {
        Buffer?: {
          from: (
            value: string,
            encoding: string
          ) => { toString: (enc: string) => string }
        }
      }
    ).Buffer
    if (bufferCtor?.from) {
      return bufferCtor.from(value, "utf-8").toString("base64")
    }
    return null
  }

  const encoded = encodeWithBrowser() ?? encodeWithBuffer()
  if (!encoded) {
    throw new Error("No base64 encoder available for URL processing.")
  }

  return encoded.replace(/=+$/u, "")
}

// ---------------- VIRUSTOTAL ----------------

export const checkVirusTotal = async (
  ioc: string,
  type: string
): Promise<any> => {
  const supportedTypes = ["ip", "domain", "url", "hash"]
  if (!supportedTypes.includes(type.toLowerCase())) {
    throw new Error(`Unsupported IOC type for VirusTotal: ${type}`)
  }

  const apiKey = await storage.get<string>("virusTotalApiKey")
  if (!apiKey) {
    throw new Error("VirusTotal API key not found.")
  }

  let url: string
  switch (type.toLowerCase()) {
    case "ip":
      url = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ioc)}`
      break
    case "domain":
      url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ioc)}`
      break
    case "url": {
      const vtId = base64UrlId(ioc)
      url = `https://www.virustotal.com/api/v3/urls/${vtId}`
      break
    }
    case "hash":
      url = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(ioc)}`
      break
    default:
      throw new Error(`Unsupported IOC type for VirusTotal: ${type}`)
  }

  return fetchAPIVT(url, apiKey, `${type.toLowerCase()}:${ioc}`)
}

export const fetchAPIVT = (
  url: string,
  apiKey: string,
  cacheKey = url
): Promise<any | null> =>
  fetchProviderJson({
    provider: "VirusTotal",
    cacheKey,
    url,
    init: {
      method: "GET",
      headers: {
        accept: "application/json",
        "x-apikey": apiKey
      }
    },
    counterName: "VT",
    notFoundAsNull: true
  })

// ---------------- ABUSEIPDB ----------------

export const checkAbuseIPDB = async (ioc: string): Promise<any> => {
  const apiKey = await storage.get<string>("abuseIPDBApiKey")
  if (!apiKey) {
    throw new Error("AbuseIPDB API key not found.")
  }

  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ioc)}`
  return fetchAPIAbuse(url, apiKey, `ip:${ioc}`)
}

type AbuseSubnetOptions = {
  maxAgeInDays?: number
  confidenceMinimum?: number
}

export const checkAbuseIPDBSubnet = async (
  subnet: string,
  options: AbuseSubnetOptions = {}
): Promise<any> => {
  const apiKey = await storage.get<string>("abuseIPDBApiKey")
  if (!apiKey) {
    throw new Error("AbuseIPDB API key not found.")
  }

  const url = new URL("https://api.abuseipdb.com/api/v2/check-block")
  url.searchParams.set("network", subnet)
  if (typeof options.maxAgeInDays === "number") {
    url.searchParams.set("maxAgeInDays", String(options.maxAgeInDays))
  }
  if (typeof options.confidenceMinimum === "number") {
    url.searchParams.set("confidenceMinimum", String(options.confidenceMinimum))
  }

  return fetchAPIAbuse(
    url.toString(),
    apiKey,
    `subnet:${subnet}:${options.maxAgeInDays ?? "default"}:${options.confidenceMinimum ?? "default"}`
  )
}

export const fetchAPIAbuse = (
  url: string,
  apiKey: string,
  cacheKey = url
): Promise<any> =>
  fetchProviderJson({
    provider: "AbuseIPDB",
    cacheKey,
    url,
    init: {
      method: "GET",
      headers: {
        Accept: "application/json",
        Key: apiKey
      }
    },
    counterName: "Abuse"
  })

// ---------------- NVD ----------------

export const checkNvdCve = async (ioc: string): Promise<any | null> => {
  const cveId = ioc.trim().toUpperCase()
  if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
    throw new Error(`Invalid CVE identifier: ${ioc}`)
  }

  const apiKey = (await storage.get<string>("nvdApiKey"))?.trim()
  const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0")
  url.searchParams.set("cveIds", cveId)

  const headers: Record<string, string> = { Accept: "application/json" }
  if (apiKey) headers.apiKey = apiKey

  const payload = await fetchProviderJson<any>({
    provider: "NVD",
    cacheKey: `cve:${cveId}`,
    url: url.toString(),
    init: { method: "GET", headers },
    counterName: "NVD",
    minimumIntervalMs: apiKey ? 1_000 : 6_500
  })

  return payload?.vulnerabilities?.length ? payload : null
}

// ---------------- IPAPI ----------------

export const checkIpapi = async (ioc: string): Promise<any> => {
  const url = `https://api.ipapi.is/?q=${encodeURIComponent(ioc)}`
  return fetchIpapi(url, `ip:${ioc}`)
}

const fetchIpapi = (url: string, cacheKey: string): Promise<any> =>
  fetchProviderJson({
    provider: "IPAPI",
    cacheKey,
    url,
    init: {
      method: "GET",
      headers: { Accept: "application/json" }
    },
    counterName: "IPAPI"
  })

// ---------------- PROXYCHECK ----------------

export const checkProxyCheck = async (ioc: string): Promise<any> => {
  const apiKey = await storage.get<string>("proxyCheckApiKey")
  if (!apiKey) {
    throw new Error("ProxyCheck API key not found.")
  }

  const params = new URLSearchParams({
    key: apiKey,
    vpn: "1",
    risk: "1",
    asn: "1",
    port: "1",
    seen: "1"
  })

  const url = `https://proxycheck.io/v3/${encodeURIComponent(ioc)}?${params.toString()}`
  return fetchProxyCheck(url, `ip:${ioc}`)
}

const fetchProxyCheck = (url: string, cacheKey: string): Promise<any> =>
  fetchProviderJson({
    provider: "ProxyCheck",
    cacheKey,
    url,
    init: {
      method: "GET",
      headers: { Accept: "application/json" }
    },
    counterName: "PROXYCHECK"
  })

// ---------------- COUNTERS ----------------

const getTodayDate = (): string => {
  const today = new Date()
  return today.toISOString().split("T")[0]
}

const incrementDailyCounter = async (apiName: string) => {
  await cleanOldCounters(apiName)

  const today = getTodayDate()
  const key = `${apiName}_${today}`
  const current = (await storage.get<number>(key)) || 0

  await storage.set(key, current + 1)
}

const cleanOldCounters = async (
  apiName: string,
  daysToKeep = 2
): Promise<void> => {
  const all = await storage.getAll()
  const now = Date.now()
  const threshold = daysToKeep * 86400000

  const keysToRemove: string[] = []

  for (const key in all) {
    if (key.startsWith(`${apiName}_`)) {
      const dateStr = key.slice(apiName.length + 1)
      const date = new Date(dateStr)
      if (isNaN(date.getTime()) || now - date.getTime() > threshold) {
        keysToRemove.push(key)
      }
    }
  }

  if (keysToRemove.length > 0) {
    await Promise.all(keysToRemove.map((key) => storage.remove(key)))
  }
}

export const getDailyCounters = async (): Promise<{
  [key: string]: number
}> => {
  const today = getTodayDate()
  const keys = [
    `VT_${today}`,
    `Abuse_${today}`,
    `NVD_${today}`,
    `IPAPI_${today}`,
    `PROXYCHECK_${today}`
  ]

  const counters = await Promise.all(keys.map((k) => storage.get<number>(k)))
  return {
    [keys[0]]: counters[0] || 0,
    [keys[1]]: counters[1] || 0,
    [keys[2]]: counters[2] || 0,
    [keys[3]]: counters[3] || 0,
    [keys[4]]: counters[4] || 0
  }
}
