import type { PlasmoMessaging } from "@plasmohq/messaging"
import { Storage } from "@plasmohq/storage"
import { checkAbuseIPDBSubnet, checkAbuseIPDB } from "../../utility/api"
import {
  NormalizedSubnet,
  normalizeSubnet,
  showNotification,
  isPrivateIP,
  uniqueStrings
} from "../../utility/utils"

const storage = new Storage({ area: "local" })

type RequestBody = {
  subnets: string[]
  maxAgeInDays?: number
  confidenceMinimum?: number
}

type SubnetCheckPayload = {
  data?: any
  reportedCount?: number
  error?: string
  isPrivate?: boolean
  ipDetails?: any
}

const handler: PlasmoMessaging.MessageHandler<RequestBody, { results: Record<string, SubnetCheckPayload> }> = async (
  req,
  res
) => {
  try {
    const abuseIPDBApiKey = await storage.get<string>("abuseIPDBApiKey")
    if (!abuseIPDBApiKey) {
      showNotification("Error", "Missing AbuseIPDB API key.")
      return res.send({ results: {} })
    }

    const { subnets, maxAgeInDays, confidenceMinimum } = req.body ?? {}
    const incomingSubnets = Array.isArray(subnets) ? uniqueStrings(subnets) : []
    if (incomingSubnets.length === 0) {
      return res.send({ results: {} })
    }

    const sanitizedMaxAge = typeof maxAgeInDays === "number"
      ? Math.min(Math.max(Math.round(maxAgeInDays), 1), 365)
      : undefined
    const sanitizedConfidence = typeof confidenceMinimum === "number"
      ? Math.min(Math.max(Math.round(confidenceMinimum), 0), 100)
      : undefined

    const normalized: NormalizedSubnet[] = incomingSubnets
      .map((value) => (typeof value === "string" ? normalizeSubnet(value) : null))
      .filter((value): value is NormalizedSubnet => Boolean(value))

    if (normalized.length === 0) {
      return res.send({ results: {} })
    }

    const results: Record<string, SubnetCheckPayload> = {}

    for (const entry of normalized) {
      const baseAddress = entry.subnet.split("/")[0] ?? ""
      if (isPrivateIP(baseAddress)) {
        results[entry.subnet] = {
          error: "Private subnet - not checked",
          reportedCount: 0,
          isPrivate: true
        }
        continue
      }

      if (entry.version === 4 && entry.prefix < 24) {
        results[entry.subnet] = {
          error: "IPv4 subnets must be /24 or smaller",
          reportedCount: 0
        }
        continue
      }

      try {
        const data = await checkAbuseIPDBSubnet(entry.subnet, {
          maxAgeInDays: sanitizedMaxAge,
          confidenceMinimum: sanitizedConfidence
        })
        const reported = Array.isArray(data?.data?.reportedAddress)
          ? data.data.reportedAddress.length
          : 0
        let ipDetails: any = null
        const isp = data?.data?.isp ?? data?.data?.reportedAddress?.[0]?.isp
        if (!isp) {
          const candidateIp =
            data?.data?.reportedAddress?.[0]?.ipAddress ?? data?.data?.minAddress ?? baseAddress
          if (candidateIp) {
            try {
              ipDetails = await checkAbuseIPDB(candidateIp)
            } catch (err) {
              console.warn("Fallback IP detail lookup failed:", err)
            }
          }
        }
        results[entry.subnet] = {
          data,
          reportedCount: reported,
          ipDetails
        }
      } catch (error) {
        console.warn("AbuseIPDB subnet check failed:", error)
        results[entry.subnet] = {
          error: error instanceof Error ? error.message : String(error)
        }
      }
    }

    res.send({ results })
  } catch (error) {
    console.error("check-subnet-abuse handler crashed:", error)
    res.send({ results: {}, error: true } as any)
  }
}

export default handler
