// src/background/messages/check-bulk-iocs.ts
import type { PlasmoMessaging } from "@plasmohq/messaging"
import { Storage } from "@plasmohq/storage"

import {
  checkAbuseIPDB,
  checkIpapi,
  checkNvdCve,
  checkProxyCheck,
  checkVirusTotal
} from "../../utility/api"
import {
  identifyIOC,
  showNotification,
  uniqueStrings
} from "../../utility/utils"

console.log("[Plasmo] check-bulk-iocs handler loaded")

const storage = new Storage({ area: "local" })
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
    const ipapiGlobal =
      (await storage.get<boolean>("ipapiEnrichmentEnabled")) === true
    const proxyCheckApiKey = await storage.get<string>("proxyCheckApiKey")
    const proxyCheckGlobal =
      (await storage.get<boolean>("proxyCheckEnabled")) === true
    const effectiveIpapi =
      typeof includeIpapi === "boolean" ? includeIpapi : ipapiGlobal
    const effectiveProxyCheck =
      typeof includeProxyCheck === "boolean"
        ? includeProxyCheck
        : proxyCheckGlobal

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
        showNotification(
          "Warning",
          "Skipping private IP address in bulk check."
        )
        warnedPrivateIp = true
      }

      if (services.includes("AbuseIPDB") && type === "IP") {
        if (!abuseIPDBApiKey) {
          result.AbuseIPDB = { error: "Missing AbuseIPDB API key" }
        } else {
          try {
            result.AbuseIPDB = await checkAbuseIPDB(ioc)
          } catch (err) {
            console.warn("AbuseIPDB error:", err)
            result.AbuseIPDB = { error: "Fetch failed" }
          }
        }

        if (effectiveIpapi) {
          try {
            result.Ipapi = await checkIpapi(ioc)
          } catch (err) {
            console.warn("IPAPI error:", err)
            result.Ipapi = { error: "Fetch failed" }
          }
        }
        if (effectiveProxyCheck) {
          if (!proxyCheckApiKey) {
            result.ProxyCheck = { error: "Missing ProxyCheck API key" }
          } else {
            try {
              result.ProxyCheck = await checkProxyCheck(ioc)
            } catch (err) {
              console.warn("ProxyCheck error:", err)
              result.ProxyCheck = { error: "Fetch failed" }
            }
          }
        }
      }

      if (
        services.includes("VirusTotal") &&
        ["IP", "Domain", "URL", "Hash"].includes(type)
      ) {
        const vtTask = (async () => {
          if (!virusTotalApiKey) {
            result.VirusTotal = { error: "Missing VirusTotal API key" }
            return
          }
          try {
            const vtData = await checkVirusTotal(ioc, type)
            result.VirusTotal = vtData ?? {
              error: "Not found on VirusTotal",
              ioc
            }
          } catch (err) {
            console.warn("VirusTotal error:", err)
            result.VirusTotal = { error: "Fetch failed" }
          }
        })()
        vtTasks.push(vtTask)
      }

      if (services.includes("NVD") && type === "CVE") {
        try {
          const nvdData = await checkNvdCve(ioc)
          result.NVD = nvdData ?? { error: "CVE not found in the NVD" }
        } catch (err) {
          console.warn("NVD error:", err)
          result.NVD = {
            error: err instanceof Error ? err.message : "Fetch failed"
          }
        }
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
