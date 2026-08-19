import { getNvdCve, getNvdCvss } from "../utility/intelFormatting"
import type { BulkCheckSummaryRow, BulkStatusKind } from "./bulk-check.types"

export type Severity = "low" | "medium" | "high"

// Single consolidated answer per indicator, shared by the result cards, the
// filters and the clipboard actions so they can never disagree.
export type BulkVerdict =
  "malicious" | "suspicious" | "clean" | "pending" | "error" | "skipped"

export const SEVERITY_ORDER: Severity[] = ["low", "medium", "high"]

export const escalateSeverity = (current: Severity, next: Severity): Severity =>
  SEVERITY_ORDER[
    Math.max(SEVERITY_ORDER.indexOf(current), SEVERITY_ORDER.indexOf(next))
  ]

export const deriveVirusTotalSeverity = (payload: any): Severity | null => {
  const stats = payload?.data?.attributes?.last_analysis_stats
  if (!stats) {
    return null
  }

  const malicious = Number(stats.malicious) || 0
  const suspicious = Number(stats.suspicious) || 0
  const harmless = Number(stats.harmless) || 0
  const harmlessBonus = Math.min(harmless * 0.2, 5)
  const vtScore = malicious * 3 + suspicious - harmlessBonus

  if (vtScore >= 20 || malicious >= 5) {
    return "high"
  }
  if (vtScore >= 5 || malicious > 0 || suspicious > 0) {
    return "medium"
  }
  return "low"
}

export const deriveAbuseSeverity = (payload: any): Severity | null => {
  const data = payload?.data
  if (!data) {
    return null
  }

  const abuseScore = Number(data.abuseConfidenceScore) || 0
  const totalReports = Number(data.totalReports) || 0
  if (abuseScore >= 60 || totalReports >= 10) {
    return "high"
  }
  if (abuseScore >= 20 || totalReports > 0) {
    return "medium"
  }
  return "low"
}

export const deriveNvdSeverity = (payload: any): Severity | null => {
  const cve = getNvdCve(payload)
  if (!cve) return null
  if (cve.cisaExploitAdd) return "high"
  const score = getNvdCvss(payload)?.score ?? 0
  if (score >= 7) return "high"
  if (score >= 4) return "medium"
  return "low"
}

export const applyServiceSeverity = (
  base: BulkStatusKind,
  severity: Severity | null
): BulkStatusKind | "flagged-high" | "flagged-medium" => {
  if (!severity || ["pending", "error", "skipped"].includes(base)) {
    return base
  }
  if (severity === "high") {
    return "flagged-high"
  }
  if (severity === "medium") {
    return "flagged-medium"
  }
  return base
}

export const extractProxyCheckDetails = (
  entry: BulkCheckSummaryRow
): { proxyPayload: any | null; proxyDetections: any | null } => {
  const proxyData = entry.result?.ProxyCheck
  if (!proxyData || typeof proxyData !== "object") {
    return { proxyPayload: null, proxyDetections: null }
  }
  const ipEntryKey = Object.keys(proxyData).find(
    (key) => key.includes(".") && typeof proxyData[key] === "object"
  )
  const proxyPayload = ipEntryKey ? proxyData[ipEntryKey] : proxyData
  const proxyDetections = proxyPayload?.detections ?? null
  return { proxyPayload, proxyDetections }
}

export const isAffirmativeFlag = (value: unknown): boolean => {
  if (typeof value === "boolean") {
    return value
  }
  if (typeof value === "number") {
    return value > 0
  }
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase()
    return ["true", "yes", "y", "1", "detected"].includes(normalized)
  }
  return false
}

export const getSeverityLevel = (entry: BulkCheckSummaryRow): Severity => {
  const vt = entry.result?.VirusTotal
  const abuse = entry.result?.AbuseIPDB
  const nvd = entry.result?.NVD
  const ipapiData = entry.result?.Ipapi?.data ?? entry.result?.Ipapi
  const { proxyPayload, proxyDetections } = extractProxyCheckDetails(entry)

  const vtLevel: Severity = deriveVirusTotalSeverity(vt) ?? "low"
  const abuseLevel: Severity = deriveAbuseSeverity(abuse) ?? "low"
  const nvdLevel: Severity = deriveNvdSeverity(nvd) ?? "low"
  let proxyLevel: Severity = "low"
  let ipapiLevel: Severity = "low"

  if (proxyPayload || proxyDetections) {
    const parseRiskScore = (value: unknown): number => {
      if (typeof value === "number") {
        return value
      }
      if (typeof value === "string") {
        const parsed = Number(value)
        return Number.isFinite(parsed) ? parsed : 0
      }
      return 0
    }

    const rawRisk = proxyDetections?.risk ?? proxyPayload?.risk
    const riskScore = parseRiskScore(rawRisk)
    if (riskScore >= 80) {
      proxyLevel = "high"
    } else if (riskScore >= 40) {
      proxyLevel = "medium"
    }

    const applyDetection = (fields: string[], level: Severity) => {
      if (!proxyDetections) {
        return
      }
      if (fields.some((field) => isAffirmativeFlag(proxyDetections[field]))) {
        proxyLevel = escalateSeverity(proxyLevel, level)
      }
    }

    applyDetection(["tor", "compromised", "anonymous", "hosting"], "high")
    applyDetection(["vpn", "proxy", "scraper"], "medium")

    if (proxyPayload) {
      if (isAffirmativeFlag(proxyPayload.proxy)) {
        proxyLevel = escalateSeverity(proxyLevel, "medium")
      }
      if (typeof proxyPayload.type === "string") {
        const normalized = proxyPayload.type.toLowerCase()
        if (["tor", "compromised"].includes(normalized)) {
          proxyLevel = escalateSeverity(proxyLevel, "high")
        } else if (["vpn", "proxy", "hosting"].includes(normalized)) {
          proxyLevel = escalateSeverity(proxyLevel, "medium")
        }
      }
    }
  }

  if (ipapiData && typeof ipapiData === "object") {
    const escalateForFields = (fields: string[], level: Severity) => {
      if (fields.some((field) => ipapiData?.[field] === true)) {
        ipapiLevel = escalateSeverity(ipapiLevel, level)
      }
    }
    escalateForFields(["is_tor", "is_abuser"], "high")
    escalateForFields(["is_proxy", "is_vpn", "is_datacenter"], "medium")
    if (ipapiData?.vpn?.service) {
      ipapiLevel = escalateSeverity(ipapiLevel, "medium")
    }
  }

  let severity: Severity = escalateSeverity(vtLevel, abuseLevel)
  severity = escalateSeverity(severity, nvdLevel)
  severity = escalateSeverity(severity, proxyLevel)
  severity = escalateSeverity(severity, ipapiLevel)

  const cleanNoDetections =
    entry.statusKind !== "flagged" &&
    typeof entry.statusText === "string" &&
    entry.statusText.toLowerCase().includes("no detection")

  if (severity === "low") {
    const abuseStatus = entry.serviceStatuses.find(
      (service) => service.name === "AbuseIPDB"
    )
    if (abuseStatus) {
      const scoreMatch = abuseStatus.text.match(/(\d+)%/)
      const reportsMatch = abuseStatus.text.match(/(\d+)\s+reports?/)
      const score = scoreMatch ? Number(scoreMatch[1]) : 0
      const reports = reportsMatch ? Number(reportsMatch[1]) : 0
      if (score >= 60 || reports >= 10) {
        severity = "high"
      } else if (score >= 20 || reports > 0) {
        severity = "medium"
      }
    }
  }

  if (severity === "low" && entry.statusKind === "flagged") {
    severity = "medium"
  }

  const hasPrimaryHigh =
    vtLevel === "high" || abuseLevel === "high" || nvdLevel === "high"
  if (!hasPrimaryHigh && severity === "high") {
    severity = "medium"
  }

  if (cleanNoDetections && severity === "high") {
    severity = "medium"
  }

  return severity
}

// A payload carries an error either at the row level or inside one of the
// provider answers; both make the indicator eligible for a retry.
export const hasFailedLookup = (payload: unknown): boolean => {
  if (!payload || typeof payload !== "object") {
    return false
  }
  const record = payload as Record<string, any>
  if (record.error) {
    return true
  }
  return Object.values(record).some(
    (value) => value && typeof value === "object" && Boolean(value.error)
  )
}

export const getVerdict = (entry: BulkCheckSummaryRow): BulkVerdict => {
  if (entry.isPending || entry.statusKind === "pending") {
    return "pending"
  }
  if (entry.statusKind === "error") {
    return "error"
  }
  if (entry.statusKind === "skipped" || !entry.result) {
    return "skipped"
  }

  const severity = getSeverityLevel(entry)
  if (severity === "high") {
    return "malicious"
  }
  if (severity === "medium") {
    return "suspicious"
  }
  return "clean"
}

export const VERDICT_LABEL: Record<BulkVerdict, string> = {
  malicious: "Malicious",
  suspicious: "Suspicious",
  clean: "Clean",
  pending: "Pending",
  error: "Error",
  skipped: "Not checked"
}
