import { Storage } from "@plasmohq/storage"

const storage = new Storage({ area: "local" })

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
    const bufferCtor = (globalThis as { Buffer?: { from: (value: string, encoding: string) => { toString: (enc: string) => string } } }).Buffer
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

export const checkVirusTotal = async (ioc: string, type: string): Promise<any> => {
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

  return fetchAPIVT(url, apiKey)
}

export const fetchAPIVT = async (url: string, apiKey: string): Promise<any | null> => {
  const response = await fetch(url, {
    method: "GET",
    headers: {
      accept: "application/json",
      "x-apikey": apiKey
    }
  })

  if (!response.ok) {
    if (response.status === 404) {
      console.warn("Hash not found on VirusTotal.")
      return null
    }

    let errorDetails = ""
    try {
      const errorJson = await response.json()
      errorDetails = JSON.stringify(errorJson, null, 2)
    } catch (e) {
      errorDetails = await response.text()
    }

    throw new Error(`API Error (${response.status}): ${response.statusText}\nDetails:\n${errorDetails}`)
  }

  await incrementDailyCounter("VT")
  return response.json()
}

// ---------------- ABUSEIPDB ----------------

export const checkAbuseIPDB = async (ioc: string): Promise<any> => {
  const apiKey = await storage.get<string>("abuseIPDBApiKey")
  if (!apiKey) {
    throw new Error("AbuseIPDB API key not found.")
  }

  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ioc)}`
  return fetchAPIAbuse(url, apiKey)
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

  return fetchAPIAbuse(url.toString(), apiKey)
}

export const fetchAPIAbuse = async (url: string, apiKey: string): Promise<any> => {
  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Key: apiKey
      }
    })

    await incrementDailyCounter("Abuse")

    if (!response.ok) {
      let errorDetails = response.statusText
      try {
        const text = await response.text()
        if (text) {
          errorDetails = text
        }
      } catch (err) {
        console.warn("Unable to read AbuseIPDB error body:", err)
      }
      throw new Error(`API Request Error (${response.status}): ${errorDetails}`)
    }

    return response.json()
  } catch (error) {
    console.error("Error during API request:", error)
    throw error
  }
}

// ---------------- IPAPI ----------------

export const checkIpapi = async (ioc: string): Promise<any> => {
  const url = `https://api.ipapi.is/?q=${encodeURIComponent(ioc)}`
  return fetchIpapi(url)
}

const fetchIpapi = async (url: string): Promise<any> => {
  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        Accept: "application/json"
      }
    })

    if (!response.ok) {
      throw new Error(`IPAPI Request Error: ${response.statusText}`)
    }

    await incrementDailyCounter("IPAPI")
    return response.json()
  } catch (error) {
    console.error("Error during IPAPI request:", error)
    throw error
  }
}

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
  return fetchProxyCheck(url)
}

const fetchProxyCheck = async (url: string): Promise<any> => {
  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        Accept: "application/json"
      }
    })

    if (!response.ok) {
      throw new Error(`ProxyCheck Request Error: ${response.statusText}`)
    }

    await incrementDailyCounter("PROXYCHECK")
    return response.json()
  } catch (error) {
    console.error("Error during ProxyCheck request:", error)
    throw error
  }
}

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

const cleanOldCounters = async (apiName: string, daysToKeep = 2): Promise<void> => {
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

export const getDailyCounters = async (): Promise<{ [key: string]: number }> => {
  const today = getTodayDate()
  const keys = [`VT_${today}`, `Abuse_${today}`, `IPAPI_${today}`, `PROXYCHECK_${today}`]

  const counters = await Promise.all(keys.map((k) => storage.get<number>(k)))
  return {
    [keys[0]]: counters[0] || 0,
    [keys[1]]: counters[1] || 0,
    [keys[2]]: counters[2] || 0,
    [keys[3]]: counters[3] || 0
  }
}
