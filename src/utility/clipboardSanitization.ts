import { Storage } from "@plasmohq/storage"

export const CLIPBOARD_SANITIZATION_KEY = "clipboardSanitizationEnabled"
export const DEFAULT_CLIPBOARD_SANITIZATION_ENABLED = true

const storage = new Storage({ area: "local" })

const URL_PATTERN = /\bhttps?:\/\/[^\s<>"']+/gi
const IPV4_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
const DOMAIN_PATTERN =
  /\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.)+(?:[a-z]{2,63})\b/gi
const IPV6_PATTERN =
  /(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:\/(?:12[0-8]|1[01]\d|\d?\d))?(?![0-9a-f:])/gi

const INTEL_FIELD_PATTERN =
  /^(\s*(?:-\s*)?(?:IOC(?:\s*\(defanged\))?|IP|Domain|Hostnames?|Network|Certificate Subject|Range|Source|Detail|Links?|References?|Description|Required action|Affected products):\s*)(.*)$/i
const REPORT_HEADING_PATTERN = /^(\s*##\s+)(.*)$/

const isValidIpv4 = (value: string): boolean =>
  value.split(".").every((octet) => Number(octet) <= 255)

const isValidIpv6 = (value: string): boolean => {
  const address = value.split("/")[0]
  try {
    return new URL(`http://[${address}]/`).hostname.length > 0
  } catch {
    return false
  }
}

const defangIndicatorValue = (value: string): string => {
  let sanitized = value.replace(URL_PATTERN, (url) =>
    url
      .replace(/^https:/i, "hxxps:")
      .replace(/^http:/i, "hxxp:")
      .replace(/\./g, "[.]")
  )

  sanitized = sanitized.replace(IPV6_PATTERN, (candidate) => {
    if (!isValidIpv6(candidate)) return candidate
    const [address, prefix] = candidate.split("/")
    return `${address.replace(/:/g, "[:]")}${prefix ? `/${prefix}` : ""}`
  })

  sanitized = sanitized.replace(IPV4_PATTERN, (candidate) =>
    isValidIpv4(candidate) ? candidate.replace(/\./g, "[.]") : candidate
  )

  return sanitized.replace(DOMAIN_PATTERN, (domain) =>
    domain.replace(/\./g, "[.]")
  )
}

const refangIndicatorValue = (value: string): string =>
  value
    .replace(/\bhxxps:\/\//gi, "https://")
    .replace(/\bhxxp:\/\//gi, "http://")
    .replace(/\[\.\]/g, ".")
    .replace(/\[:\]/g, ":")

const transformIntelFields = (
  text: string,
  transform: (value: string) => string
): string =>
  text
    .split("\n")
    .map((line) => {
      const fieldMatch = line.match(INTEL_FIELD_PATTERN)
      if (fieldMatch) {
        return `${fieldMatch[1]}${transform(fieldMatch[2])}`
      }

      const headingMatch = line.match(REPORT_HEADING_PATTERN)
      return headingMatch
        ? `${headingMatch[1]}${transform(headingMatch[2])}`
        : line
    })
    .join("\n")

export const sanitizeIntelClipboardText = (text: string): string =>
  transformIntelFields(text, defangIndicatorValue)

export const restoreIntelClipboardText = (text: string): string =>
  transformIntelFields(text, refangIndicatorValue)

export const isClipboardSanitizationEnabled = async (): Promise<boolean> => {
  try {
    const storedValue = await storage.get<boolean>(CLIPBOARD_SANITIZATION_KEY)
    return typeof storedValue === "boolean"
      ? storedValue
      : DEFAULT_CLIPBOARD_SANITIZATION_ENABLED
  } catch {
    return DEFAULT_CLIPBOARD_SANITIZATION_ENABLED
  }
}

export const prepareIntelClipboardText = async (
  text: string
): Promise<string> =>
  (await isClipboardSanitizationEnabled())
    ? sanitizeIntelClipboardText(text)
    : restoreIntelClipboardText(text)
