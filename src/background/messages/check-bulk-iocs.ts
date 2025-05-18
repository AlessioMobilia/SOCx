// src/background/messages/check-bulk-iocs.ts
import type { PlasmoMessaging } from "@plasmohq/messaging"
import { identifyIOC, showNotification } from "../../utility/utils"
import { checkVirusTotal, checkAbuseIPDB } from "../../utility/api"
import { Storage } from "@plasmohq/storage"

console.log("[Plasmo] check-bulk-iocs handler loaded")


const storage = new Storage({ area: "local" })

const handler: PlasmoMessaging.MessageHandler = async (req, res) => {
  try {
    console.log("[Plasmo] check-bulk-iocs handler triggered")

    const { iocList, services } = req.body
    const results: Record<string, any> = {}

    const virusTotalApiKey = await storage.get<string>("virusTotalApiKey")
    const abuseIPDBApiKey = await storage.get<string>("abuseIPDBApiKey")

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

    for (const ioc of iocList) {
      const type = identifyIOC(ioc)
      const result: Record<string, any> = {}

      if (type) {
        if (services.includes("VirusTotal") && type !== "MAC") {
          try {
            result.VirusTotal = await checkVirusTotal(ioc, type)
          } catch (err) {
            console.warn("VirusTotal error:", err)
            result.VirusTotal = { error: "Fetch failed" }
          }
        }
        if (services.includes("AbuseIPDB") && type === "IP") {
          try {
            result.AbuseIPDB = await checkAbuseIPDB(ioc)
          } catch (err) {
            console.warn("AbuseIPDB error:", err)
            result.AbuseIPDB = { error: "Fetch failed" }
          }
        } else if (type === "Private IP") {
          showNotification("Error", "Private IP, skipping analysis.")
        }
      }

      results[ioc] = result
    }

    res.send({ results })
  } catch (err) {
    console.error("check-bulk-iocs handler crashed:", err)
    res.send({ results: {}, error: true })
  }
}


export default handler
