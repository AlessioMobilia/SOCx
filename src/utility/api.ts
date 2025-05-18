import { Storage } from "@plasmohq/storage"

const storage = new Storage({ area: "local" })

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
    case "url":
      url = `https://www.virustotal.com/api/v3/urls/${encodeURIComponent(ioc)}`
      break
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

export const fetchAPIAbuse = async (url: string, apiKey: string): Promise<any> => {
  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Key: apiKey
      }
    })

    if (!response.ok) {
      throw new Error(`API Request Error: ${response.statusText}`)
    }

    await incrementDailyCounter("Abuse")
    return response.json()
  } catch (error) {
    console.error("Error during API request:", error)
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
  const keys = [`VT_${today}`, `Abuse_${today}`]

  const counters = await Promise.all(keys.map((k) => storage.get<number>(k)))
  return {
    [keys[0]]: counters[0] || 0,
    [keys[1]]: counters[1] || 0
  }
}
