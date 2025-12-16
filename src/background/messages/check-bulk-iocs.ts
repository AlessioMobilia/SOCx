// src/background/messages/check-bulk-iocs.ts
import type { PlasmoMessaging } from "@plasmohq/messaging"
import { identifyIOC, showNotification, uniqueStrings } from "../../utility/utils"
import { checkVirusTotal, checkAbuseIPDB, checkIpapi, checkProxyCheck } from "../../utility/api"
import { Storage } from "@plasmohq/storage"

console.log("[Plasmo] check-bulk-iocs handler loaded")


const storage = new Storage({ area: "local" })
const VT_LIMIT_PER_MINUTE = 4
const VT_WINDOW_MS = 60_000
let vtWindowStart = 0
let vtRequestsInWindow = 0

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

const respectVirusTotalRateLimit = async () => {
  const now = Date.now()
  if (vtWindowStart === 0 || now - vtWindowStart >= VT_WINDOW_MS) {
    vtWindowStart = now
    vtRequestsInWindow = 0
  }

  if (vtRequestsInWindow >= VT_LIMIT_PER_MINUTE) {
    const waitTime = VT_WINDOW_MS - (now - vtWindowStart)
    if (waitTime > 0) {
      await sleep(waitTime)
    }
    vtWindowStart = Date.now()
    vtRequestsInWindow = 0
  }

  vtRequestsInWindow += 1
}

const handler: PlasmoMessaging.MessageHandler = async (req, res) => {
  try {
    console.log("[Plasmo] check-bulk-iocs handler triggered")

    const { iocList, services, includeIpapi, includeProxyCheck } = req.body
    const normalizedList = Array.isArray(iocList) ? uniqueStrings(iocList) : []
    if (normalizedList.length === 0) {
      return res.send({ results: {} })
    }
    const results: Record<string, any> = {}

    const virusTotalApiKey = await storage.get<string>("virusTotalApiKey")
    const abuseIPDBApiKey = await storage.get<string>("abuseIPDBApiKey")
    const ipapiGlobal = (await storage.get<boolean>("ipapiEnrichmentEnabled")) === true
    const proxyCheckApiKey = await storage.get<string>("proxyCheckApiKey")
    const proxyCheckGlobal = (await storage.get<boolean>("proxyCheckEnabled")) === true
    const effectiveIpapi = typeof includeIpapi === "boolean" ? includeIpapi : ipapiGlobal
    const effectiveProxyCheck =
      typeof includeProxyCheck === "boolean" ? includeProxyCheck : proxyCheckGlobal

    for (const service of services) {
      if (service === "VirusTotal" && !virusTotalApiKey) {
        showNotification("Error", "Missing VirusTotal API key.")
        return res.send({ results: {} })
      }
      if (service === "AbuseIPDB" && !abuseIPDBApiKey) {
        showNotification("Error", "Missing AbuseIPDB API key.")
        return res.send({ results: {} })
      }
    }

    if (effectiveProxyCheck && !proxyCheckApiKey) {
      showNotification("Error", "ProxyCheck API key is missing.")
      return res.send({ results: {} })
    }

    const vtTasks: Promise<void>[] = []
    let warnedPrivateIp = false

    for (const ioc of normalizedList) {
      const type = identifyIOC(ioc)
      const result: Record<string, any> = {}

      if (!type) {
        result.error = "Unable to identify IOC type"
        results[ioc] = result
        continue
      }

      if (type === "Private IP" && !warnedPrivateIp) {
        showNotification("Warning", "Skipping private IP address in bulk check.")
        warnedPrivateIp = true
      }

      if (services.includes("AbuseIPDB") && type === "IP") {
        try {
          result.AbuseIPDB = await checkAbuseIPDB(ioc)
          if (effectiveIpapi) {
            try {
              result.Ipapi = await checkIpapi(ioc)
            } catch (err) {
              console.warn("IPAPI error:", err)
              result.Ipapi = { error: "Fetch failed" }
            }
          }
          if (effectiveProxyCheck) {
            try {
              result.ProxyCheck = await checkProxyCheck(ioc)
            } catch (err) {
              console.warn("ProxyCheck error:", err)
              result.ProxyCheck = { error: "Fetch failed" }
            }
          }
        } catch (err) {
          console.warn("AbuseIPDB error:", err)
          result.AbuseIPDB = { error: "Fetch failed" }
        }
      }

      if (services.includes("VirusTotal") && type !== "MAC") {
        const vtTask = (async () => {
          try {
            await respectVirusTotalRateLimit()
            result.VirusTotal = await checkVirusTotal(ioc, type)
          } catch (err) {
            console.warn("VirusTotal error:", err)
            result.VirusTotal = { error: "Fetch failed" }
          }
        })()
        vtTasks.push(vtTask)
      }

      results[ioc] = result
    }

    await Promise.all(vtTasks)

    res.send({ results })
  } catch (err) {
    console.error("check-bulk-iocs handler crashed:", err)
    res.send({ results: {}, error: true })
  }
}


export default handler
