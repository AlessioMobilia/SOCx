// src/utils.ts
import { sendToContentScript } from "@plasmohq/messaging"
import { Storage } from "@plasmohq/storage"
import * as XLSX from "xlsx-js-style"

// Defang e Refang
export const defang = (text: string): string => {
  return text
    .replace(/https?:\/\//gi, "hxxp://")
    .replace(/\./g, "[.]");
};

export const refang = (text: string): string => {
  const normalizedText = text.trim().toLowerCase();
  return normalizedText
    .replace(/^hxxp:\/\//i, "http://")
    .replace(/^hxxps:\/\//i, "https://")
    .replace(/\[\.\]/g, ".")
    .replace(/\(\.\)/g, ".")
    .replace(/{\.}/g, ".");
};

export const isAlreadyDefanged = (text: string): boolean => {
  return /\[\.\]|hxxp:\/\/|hxxps:\/\//i.test(text);
};

export const uniqueStrings = (values: string[]): string[] => {
  const seen = new Set<string>()
  const result: string[] = []
  for (const value of values) {
    const normalized = value.trim()
    if (!normalized || seen.has(normalized)) {
      continue
    }
    seen.add(normalized)
    result.push(normalized)
  }
  return result
}

const IPV6_SEGMENT = "[0-9a-fA-F]{1,4}"
const IPV4_BYTE =
  "(25[0-5]|(2[0-4]|1?[0-9])?[0-9])"
const IPV4_ADDRESS = `(?:${IPV4_BYTE}\\.){3}${IPV4_BYTE}`
const IPV6_REGEX_PARTS = [
  `(?:${IPV6_SEGMENT}:){7}${IPV6_SEGMENT}`,
  `(?:${IPV6_SEGMENT}:){1,6}:${IPV6_SEGMENT}`,
  `(?:${IPV6_SEGMENT}:){1,5}(?::${IPV6_SEGMENT}){1,2}`,
  `(?:${IPV6_SEGMENT}:){1,4}(?::${IPV6_SEGMENT}){1,3}`,
  `(?:${IPV6_SEGMENT}:){1,3}(?::${IPV6_SEGMENT}){1,4}`,
  `(?:${IPV6_SEGMENT}:){1,2}(?::${IPV6_SEGMENT}){1,5}`,
  `${IPV6_SEGMENT}:(?::${IPV6_SEGMENT}){1,6}`,
  `:(?::${IPV6_SEGMENT}){1,7}`,
  "::",
  `(?:${IPV6_SEGMENT}:){1,4}:${IPV4_ADDRESS}`,
  `::(?:ffff(?::0{1,4}){0,1}:){0,1}${IPV4_ADDRESS}`,
  `fe80:(?::${IPV6_SEGMENT}){0,4}%[0-9a-zA-Z]{1,}`
]
export const IPV6_REGEX_SOURCE = `(?:${IPV6_REGEX_PARTS.join("|")})`
const STRICT_IPV6_REGEX = new RegExp(`^${IPV6_REGEX_SOURCE}$`, "i")


// Logic to identify the type of IOC
export const identifyIOC = (text: string): string | null => {
  // Regex to validate IP, hash, domain, URL, email, MAC address, and ASN
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
  const domainRegex = /^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
  const urlRegex = /https?:\/\/[^\s]+/;
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  const macAddressRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
  const asnRegex = /^AS\d{1,5}(?:\.\d{1,5})?$/i;

  // Check if the input is a MAC address
  if (macAddressRegex.test(text)) {
    return "MAC";
  }

  // Check if the input is an ASN
  if (asnRegex.test(text)) {
    return "ASN";
  }

  // Check if the input is an IP (IPv4 or IPv6)
  if (ipRegex.test(text) || STRICT_IPV6_REGEX.test(text)) {
    if (isPrivateIP(text)) {
      //showNotification("Error", text + " is a Private IP");
      return "Private IP";
    } else {
      return "IP";
    }
  }

  // Check if the input is a hash
  if (hashRegex.test(text)) return "Hash";

  // Check if the input is a domain
  if (domainRegex.test(text)) return "Domain";

  // Check if the input is a URL
  if (urlRegex.test(text)) return "URL";

  // Check if the input is an email
  if (emailRegex.test(text)) return "Email";

  // If it doesn't match any IoC, return null
  return null;
};



// Check if IP is private
export const isPrivateIP = (ip: string): boolean => {
  // Controlla se è un IPv4
  const isIPv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
  if (isIPv4) {
    // Dividi l'IP in parti
    const parts = ip.split(".").map(Number);
    // Verifica se l'IP ha 4 parti e che ogni parte sia un numero valido
    if (parts.length !== 4 || parts.some((part) => isNaN(part) || part < 0 || part > 255)) {
      return false;
    }
    // Controlla se l'IP è privato (IPv4)
    const [first, second] = parts;
    // Classe A: 10.0.0.0 - 10.255.255.255
    if (first === 10) return true;
    // Classe B: 172.16.0.0 - 172.31.255.255
    if (first === 172 && second >= 16 && second <= 31) return true;
    // Classe C: 192.168.0.0 - 192.168.255.255
    if (first === 192 && second === 168) return true;
    // Se non è privato
    return false;
  }

  // Controlla se è un IPv6
  // Verifica se l'indirizzo è un IPv6 valido
  if (STRICT_IPV6_REGEX.test(ip)) {
    // Controlla se l'IPv6 è privato (fc00::/7)
    const prefix = ip.substring(0, 2).toLowerCase();
    return prefix === "fc" || prefix === "fd";
  }

  // Se non è né IPv4 né IPv6
  return false;
};




export const showNotification = (title: string, message: string): void => {
  if (typeof chrome !== "undefined" && chrome.notifications?.create) {
    // ✅ Background-safe (Chrome/Firefox)
    chrome.notifications.create({
      type: "basic",
      title,
      message,
      iconUrl: chrome.runtime.getURL("assets/icon.png") // Assicurati che esista
    })
  } else if (typeof window !== "undefined" && typeof document !== "undefined") {
    // ✅ Content script / popup fallback
    showToast(`${title}: ${message}`)
  } else {
    // ✅ Fallback finale: console
    console.log(`[NOTIFY] ${title}: ${message}`)
  }
}



export const showToast = (message: string, variant: string = "primary") => {
  let container = document.getElementById("socx-toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "socx-toast-container";
    container.style.position = "fixed";
    container.style.bottom = "20px";
    container.style.right = "20px";
    container.style.zIndex = "9999";
    container.style.display = "flex";
    container.style.flexDirection = "column";
    container.style.gap = "8px";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.className = `socx-toast socx-toast--${variant}`;
  toast.setAttribute("role", "alert");
  toast.setAttribute("aria-live", "assertive");
  toast.setAttribute("aria-atomic", "true");

  toast.innerHTML = `
    <div class="socx-toast__message">${message}</div>
    <button class="socx-toast__close" aria-label="Close">&times;</button>
  `;

  const closeBtn = toast.querySelector("button");
  closeBtn?.addEventListener("click", () => toast.remove());

  container.appendChild(toast);

  setTimeout(() => {
    toast.remove();
  }, 3000);
};



const storage = new Storage({ area: "local" })

export const saveIOC = async (type: string, text: string): Promise<boolean> => {
  
  try {
    
    const history = await storage.get<any[]>("iocHistory") || []
    let iocHistory = history || [];
    // Check if the IOC is already present
    const isDuplicate = iocHistory.some(
      (ioc) => ioc.text === text && ioc.type === type
    );
    if (!isDuplicate) {
      // Add the new IOC at the beginning of the array
      iocHistory.unshift({ type, text, timestamp: new Date().toISOString() });
      // Keep only the latest 20 IOCs
      if (iocHistory.length > 20) {
        iocHistory = iocHistory.slice(0, 20);
      }
      // Save the updated history
      await storage.set("iocHistory", iocHistory); // Use chrome.storage.local
      return true;
    } else {
      return true; // The IOC is already present, but we consider the operation valid
    }
  } catch (error) {
    return false;
  }
};





export const copyToClipboard = async (text: string): Promise<void> => {
  try {
    const response = await sendToContentScript({
      name: "copy-to-clipboard",
      body: { text: text }
    })
    console.log("Response from content script:", response);

    showNotification("Done", "IOC copied to clipboard")
  } catch (err) {
    showNotification("Error", "IOC not copied to clipboard")
    //console.error("Error copying to clipboard:", err)
  }
}
  





const IOC_IPV6_REGEX = new RegExp(IPV6_REGEX_SOURCE, "gi")
const IOC_IPV4_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
const IOC_DOMAIN_REGEX = /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g
const IOC_URL_REGEX = /\bhttps?:\/\/[^\s,;\r\n]+\b/g
const IOC_MD5_REGEX = /\b[a-fA-F0-9]{32}\b/g
const IOC_SHA1_REGEX = /\b[a-fA-F0-9]{40}\b/g
const IOC_SHA256_REGEX = /\b[a-fA-F0-9]{64}\b/g
const IOC_EMAIL_REGEX = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g
const IOC_DEFANGED_URL_REGEX = /\bhxxps?:\/\/[^\s,;\r\n]+\b/g
const IOC_DEFANGED_DOMAIN_REGEX = /\b(?:[a-zA-Z0-9-]+\[\.\])+[a-zA-Z]{2,}\b/g
const IOC_DEFANGED_IP_REGEX = /\b(?:\d{1,3}\[\.\]){3}\d{1,3}\b/g
const IOC_MAC_REGEX = /\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b/g
const IOC_ASN_REGEX = /\bAS\d{1,5}(?:\.\d{1,5})?\b/gi

const COMBINED_IOC_REGEX = new RegExp(
  `(${IOC_IPV6_REGEX.source}|${IOC_IPV4_REGEX.source}|${IOC_DOMAIN_REGEX.source}|${IOC_URL_REGEX.source}|${IOC_MD5_REGEX.source}|${IOC_SHA1_REGEX.source}|${IOC_SHA256_REGEX.source}|${IOC_EMAIL_REGEX.source}|${IOC_DEFANGED_URL_REGEX.source}|${IOC_DEFANGED_DOMAIN_REGEX.source}|${IOC_DEFANGED_IP_REGEX.source}|${IOC_MAC_REGEX.source}|${IOC_ASN_REGEX.source})`,
  "gi"
)

export const extractIOCs = (text: string, refanged: boolean = true): string[] | null => {
  if (!text) {
    return null
  }

  COMBINED_IOC_REGEX.lastIndex = 0
  const matches = text.match(COMBINED_IOC_REGEX)

  if (!matches) {
    return null
  }

  const normalizedMatches = refanged
    ? matches
        .map((ioc) => refang(ioc).trim())
        .filter(Boolean)
    : matches.filter(Boolean)

  return normalizedMatches.length > 0 ? normalizedMatches : null
}

export type ExtractedIPMap = {
  ipv4: string[]
  ipv6: string[]
}

const normalizeIPv4 = (ip: string): string => {
  const parts = ip.trim().split(".")
  if (parts.length !== 4) {
    return ip.trim()
  }

  return parts
    .map((part) => {
      const parsed = Number(part)
      return Number.isFinite(parsed) ? parsed.toString() : part
    })
    .join(".")
}

const expandIPv4SegmentToHex = (segment: string): string[] | null => {
  const octets = segment.split(".").map((value) => parseInt(value, 10))
  if (octets.length !== 4 || octets.some((value) => Number.isNaN(value) || value < 0 || value > 255)) {
    return null
  }

  const high = ((octets[0] << 8) | octets[1]).toString(16)
  const low = ((octets[2] << 8) | octets[3]).toString(16)
  return [high, low]
}

const parseIPv6ToHextets = (input: string): number[] | null => {
  const address = input.trim()
  if (!address) {
    return null
  }

  const doubleColonParts = address.split("::")
  if (doubleColonParts.length > 2) {
    return null
  }

  const expandSection = (section: string): string[] | null => {
    if (!section) {
      return []
    }

    const segments = section.split(":").filter((value) => value.length > 0)
    const expanded: string[] = []

    for (const value of segments) {
      if (value.includes(".")) {
        const ipv4Parts = expandIPv4SegmentToHex(value)
        if (!ipv4Parts) {
          return null
        }
        expanded.push(...ipv4Parts)
      } else {
        expanded.push(value)
      }
    }

    return expanded
  }

  const left = expandSection(doubleColonParts[0] ?? "")
  const right = expandSection(doubleColonParts[1] ?? "")

  if (left === null || right === null) {
    return null
  }

  const missing = 8 - (left.length + right.length)
  if (missing < 0) {
    return null
  }

  const hextets = [...left, ...Array(missing).fill("0"), ...right]

  if (hextets.length !== 8) {
    return null
  }

  const numericHextets: number[] = []
  for (const chunk of hextets) {
    const value = parseInt(chunk, 16)
    if (Number.isNaN(value) || value < 0 || value > 0xffff) {
      return null
    }
    numericHextets.push(value)
  }

  return numericHextets
}

const compressIPv6FromHextets = (hextets: number[]): string => {
  const hexStrings = hextets.map((value) => value.toString(16))

  let bestStart = -1
  let bestLength = 0
  let currentStart = -1
  let currentLength = 0

  hextets.forEach((value, index) => {
    if (value === 0) {
      if (currentStart === -1) {
        currentStart = index
        currentLength = 1
      } else {
        currentLength += 1
      }
    } else {
      if (currentStart !== -1 && currentLength > bestLength) {
        bestStart = currentStart
        bestLength = currentLength
      }
      currentStart = -1
      currentLength = 0
    }
  })

  if (currentStart !== -1 && currentLength > bestLength) {
    bestStart = currentStart
    bestLength = currentLength
  }

  if (bestLength < 2) {
    bestStart = -1
  }

  const parts: string[] = []
  let index = 0

  while (index < hexStrings.length) {
    if (index === bestStart) {
      parts.push("")
      index += bestLength
      if (index >= hexStrings.length) {
        parts.push("")
      }
      continue
    }
    parts.push(hexStrings[index])
    index += 1
  }

  let result = parts.join(":")
  if (result.startsWith(":")) {
    result = ":" + result
  }
  if (result.endsWith(":")) {
    result = result + ":"
  }
  if (!result) {
    return "::"
  }
  return result.replace(/:{3,}/, "::")
}

const canonicalizeIPv6 = (ip: string): string | null => {
  const hextets = parseIPv6ToHextets(ip)
  if (!hextets) {
    return null
  }
  return compressIPv6FromHextets(hextets)
}

export const extractIPAddresses = (text: string): ExtractedIPMap => {
  const matches = extractIOCs(text) ?? []
  const ipv4Set = new Set<string>()
  const ipv6Set = new Set<string>()

  matches.forEach((ioc) => {
    const type = identifyIOC(ioc)
    if (type !== "IP" && type !== "Private IP") {
      return
    }

    if (ioc.includes(":")) {
      const normalized = canonicalizeIPv6(ioc.toLowerCase())
      if (normalized) {
        ipv6Set.add(normalized)
      }
    } else if (ioc.includes(".")) {
      ipv4Set.add(normalizeIPv4(ioc))
    }
  })

  return {
    ipv4: Array.from(ipv4Set),
    ipv6: Array.from(ipv6Set)
  }
}

export const computeIPv4Subnet = (ip: string, prefix: number): string | null => {
  const normalizedPrefix = Math.min(32, Math.max(0, prefix))
  const octets = ip.split(".").map((value) => parseInt(value, 10))
  if (octets.length !== 4 || octets.some((value) => Number.isNaN(value) || value < 0 || value > 255)) {
    return null
  }

  const ipValue =
    (octets[0] << 24) |
    (octets[1] << 16) |
    (octets[2] << 8) |
    octets[3]

  const mask = normalizedPrefix === 0 ? 0 : (~0 << (32 - normalizedPrefix)) >>> 0
  const network = ipValue & mask

  const networkOctets = [
    (network >>> 24) & 0xff,
    (network >>> 16) & 0xff,
    (network >>> 8) & 0xff,
    network & 0xff
  ]

  return `${networkOctets.join(".")}/${normalizedPrefix}`
}

const IPV6_BIT_LENGTH = 128n
const IPV6_FULL_MASK = (1n << IPV6_BIT_LENGTH) - 1n

const ipv6ToBigInt = (ip: string): bigint | null => {
  const hextets = parseIPv6ToHextets(ip)
  if (!hextets) {
    return null
  }

  return hextets.reduce((acc, value) => (acc << 16n) + BigInt(value), 0n)
}

const bigIntToIPv6 = (value: bigint): string => {
  const hextets: number[] = []
  for (let i = 0; i < 8; i += 1) {
    const shift = BigInt(7 - i) * 16n
    const chunk = Number((value >> shift) & 0xffffn)
    hextets.push(chunk)
  }
  return compressIPv6FromHextets(hextets)
}

export const computeIPv6Subnet = (ip: string, prefix: number): string | null => {
  const normalizedPrefix = Math.min(128, Math.max(0, prefix))
  const numeric = ipv6ToBigInt(ip)
  if (numeric === null) {
    return null
  }

  const hostMask = normalizedPrefix === 128 ? 0n : (1n << BigInt(128 - normalizedPrefix)) - 1n
  const networkMask = IPV6_FULL_MASK ^ hostMask
  const networkValue = numeric & networkMask
  const networkString = bigIntToIPv6(networkValue)

  return `${networkString}/${normalizedPrefix}`
}

export type NormalizedSubnet = {
  subnet: string
  version: 4 | 6
  prefix: number
}

const parsePrefix = (value: string, max: number): number | null => {
  if (!/^\d{1,3}$/.test(value.trim())) {
    return null
  }
  const parsed = Number(value)
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > max) {
    return null
  }
  return parsed
}

export const normalizeSubnet = (input: string): NormalizedSubnet | null => {
  const trimmed = input.trim()
  if (!trimmed.includes("/")) {
    return null
  }

  const [rawIp, rawPrefix] = trimmed.split("/")
  if (!rawIp || !rawPrefix) {
    return null
  }

  if (rawIp.includes(":")) {
    const prefix = parsePrefix(rawPrefix, 128)
    if (prefix === null) {
      return null
    }
    const normalized = computeIPv6Subnet(rawIp, prefix)
    if (!normalized) {
      return null
    }
    return { subnet: normalized, version: 6, prefix }
  }

  const prefix = parsePrefix(rawPrefix, 32)
  if (prefix === null) {
    return null
  }

  const normalizedIp = normalizeIPv4(rawIp)
  const normalized = computeIPv4Subnet(normalizedIp, prefix)
  if (!normalized) {
    return null
  }

  return { subnet: normalized, version: 4, prefix }
}

const IPV4_SUBNET_REGEX = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\s*\/\s*(3[0-2]|[12]?\d)\b/gi
const IPV6_SUBNET_REGEX = new RegExp(
  `${IPV6_REGEX_SOURCE}\\s*\\/\\s*(?:12[0-8]|1[01]?\\d|\\d?\\d)`,
  "gi"
)

export const extractSubnetsFromText = (text: string): NormalizedSubnet[] => {
  const payload = typeof text === "string" ? text : ""
  const matches: string[] = []

  const collectMatches = (regex: RegExp) => {
    regex.lastIndex = 0
    let match: RegExpExecArray | null
    while ((match = regex.exec(payload)) !== null) {
      matches.push(match[0].replace(/\s+/g, ""))
    }
  }

  collectMatches(IPV4_SUBNET_REGEX)
  collectMatches(IPV6_SUBNET_REGEX)

  const seen = new Set<string>()
  const result: NormalizedSubnet[] = []

  for (const segment of matches) {
    const normalized = normalizeSubnet(segment)
    if (normalized && !seen.has(normalized.subnet)) {
      seen.add(normalized.subnet)
      result.push(normalized)
    }
  }

  return result
}

const HOST_BITS = {
  4: 32n,
  6: 128n
} as const

export const estimateSubnetHostCount = (version: 4 | 6, prefix: number): bigint => {
  const totalBits = HOST_BITS[version]
  const boundedPrefix = Math.min(Math.max(prefix, 0), Number(totalBits))
  const hostBits = totalBits - BigInt(boundedPrefix)
  if (hostBits <= 0n) {
    return 1n
  }
  return 1n << hostBits
}

export const formatHostCount = (count: bigint): string => {
  const asString = count.toString()
  if (count <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return new Intl.NumberFormat().format(Number(count))
  }
  return asString.replace(/\B(?=(\d{3})+(?!\d))/g, ",")
}

export type SubnetCheckSummaryRow = {
  subnet: string
  version: 4 | 6
  prefix: number
  hostCount: string
  reportedCount: number
  distinctIpCount?: number | null
  mostRecent: string | null
  minAddress?: string
  maxAddress?: string
  isPrivate: boolean
  statusText: string
  statusKind: "pending" | "clean" | "flagged" | "error" | "private"
  error?: string | null
  isp?: string | null
  country?: string | null
  usageType?: string | null
  domain?: string | null
  hostnames?: string[] | null
}

export const formatSubnetCheckClipboard = (rows: SubnetCheckSummaryRow[]): string => {
  if (!Array.isArray(rows) || rows.length === 0) {
    return ""
  }

  const blocks = rows.map((row, index) => {
    const parts = [
      `## ${row.subnet} (IPv${row.version}/${row.prefix})`,
      `Hosts: ${row.hostCount}`,
      `Reported IPs: ${row.reportedCount}`,
      `Most Recent Report: ${row.mostRecent ?? "N/A"}`,
      `Status: ${row.statusText}`
    ]

    if (row.minAddress || row.maxAddress) {
      parts.splice(1, 0, `Range: ${row.minAddress ?? "?"} → ${row.maxAddress ?? "?"}`)
    }

    if (row.country) {
      parts.push(`Country: ${row.country}`)
    }
    if (row.isp) {
      parts.push(`ISP: ${row.isp}`)
    }
    if (row.usageType) {
      parts.push(`Usage Type: ${row.usageType}`)
    }
    if (row.domain) {
      parts.push(`Domain: ${row.domain}`)
    }
    if (row.hostnames?.length) {
      parts.push(`Hostnames: ${row.hostnames.join(", ")}`)
    }

    return parts.join("\n")
  })

  return blocks.join("\n\n")
}

export const exportSubnetCheckToExcel = (rows: SubnetCheckSummaryRow[]): void => {
  if (!Array.isArray(rows) || rows.length === 0) {
    return
  }

  const headers = [
    "Subnet",
    "Version",
    "Prefix",
    "Hosts",
    "Reported IPs",
    "Most Recent Report",
    "Min Address",
    "Max Address",
    "Status",
    "Country",
    "ISP",
    "Usage Type",
    "Domain",
    "Hostnames"
  ]

  const body = rows.map((row) => [
    row.subnet,
    `IPv${row.version}`,
    `/${row.prefix}`,
    row.hostCount,
    row.reportedCount,
    row.mostRecent ?? "N/A",
    row.minAddress ?? "",
    row.maxAddress ?? "",
    row.statusText,
    row.country ?? "",
    row.isp ?? "",
    row.usageType ?? "",
    row.domain ?? "",
    row.hostnames?.join(", ") ?? ""
  ])

  const worksheet = XLSX.utils.aoa_to_sheet([headers, ...body])
  const workbook = XLSX.utils.book_new()
  XLSX.utils.book_append_sheet(workbook, worksheet, "Subnet Check")
  const filename = `SOCx_subnets_${new Date().toISOString().split("T")[0]}.xlsx`
  XLSX.writeFile(workbook, filename)
}







/**
* Main function to format combined AbuseIPDB and VirusTotal data.
* @param data Dati combinati.
* @returns Stringa formattata.
*/
export const parseAndFormatResults = (data: any): string => {
  const lines: string[] = [];
  console.log("Data:", data);

  const ipIntelSignals = collectIpIntelSignals(data?.Ipapi, data?.ProxyCheck);
  console.log("IP Intel Signals:", ipIntelSignals);

  if (data?.AbuseIPDB?.data || ipIntelSignals.length > 0) {
    lines.push(formatAbuseIPDBData(data?.AbuseIPDB, ipIntelSignals));
    lines.push(""); // Separazione
  }

  if (data?.VirusTotal?.data) {
    lines.push(formatVirusTotalData(data.VirusTotal));
  }

  return lines.join("\n").trim();
};












export const formatAbuseIPDBData = (
  abuseData: any,
  extraSignals: string[] = []
): string => {
  const d = abuseData?.data;
  if (!d) return "";

  const toSafe = (v: unknown): string | number =>
    v === null || v === undefined || v === "" ? "N/A" : (v as any);

  const hostnames =
    Array.isArray(d?.hostnames) && d.hostnames.length > 0
      ? d.hostnames.join(", ")
      : undefined;

  const isWhitelisted =
    d?.isWhitelisted === true
      ? "Yes"
      : d?.isWhitelisted === false
      ? "No"
      : "Unknown";

  // --- campi principali ------------------------------------------------------
  const fields: Record<string, string | number> = {
    "IP:": toSafe(d?.ipAddress),
    "Abuse Score:": `${toSafe(d?.abuseConfidenceScore)}%`,
    "Total Reports:": toSafe(d?.totalReports),
    "ISP:": toSafe(d?.isp),
    "Country:": toSafe(d?.countryCode),
    "Domain:": toSafe(d?.domain),
    "Usage:": toSafe(d?.usageType),
    "Version:": d?.ipVersion === 6 ? "IPv6" : "IPv4",
    "Tor:": d?.isTor ? "Yes" : "No",
    "Whitelisted:": isWhitelisted,
    ...(hostnames ? { "Hostnames:": hostnames } : {}),
    "Last Reported:": toSafe(d?.lastReportedAt ?? "N/A"),
  };

  // --- aggiunta extraSignals come campi equivalenti --------------------------
  const normalizeAcronyms = (s: string) =>
    s
      .replace(/\bVpn\b/gi, "VPN")
      .replace(/\bTor\b/gi, "TOR")
      .replace(/\bUrl\b/gi, "URL")
      .replace(/\bIp\b/gi, "IP");

  for (const signal of extraSignals) {
    const [rawKey, rawValue] = signal.split(":").map(s => s.trim());
    const key = `${normalizeAcronyms(rawKey)}:`; // mantieni il ":"
    const value = rawValue || "";
    fields[key] = value;
  }

  // --- calcolo allineamento --------------------------------------------------
  const labelWidth = Math.max(...Object.keys(fields).map(k => k.length));

  // --- generazione righe -----------------------------------------------------
  const lines = Object.entries(fields).map(
    ([label, value]) => `- ${label.padEnd(labelWidth)} ${value}`
  );

  return lines.join("\n");
};



const formatIpapiLabel = (key: string): string => {
  return key
    .replace(/^is_/i, "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

const IPAPI_BOOLEAN_FIELDS = [
  "is_bogon",
  "is_mobile",
  "is_satellite",
  "is_crawler",
  "is_datacenter",
  "is_tor",
  "is_proxy",
  "is_vpn",
  "is_abuser"
]

export const collectIpIntelSignals = (ipapiData: any, proxyData: any): string[] => {
  const signals: string[] = []

  const payload = ipapiData?.data ?? ipapiData
  if (payload && typeof payload === "object") {
    IPAPI_BOOLEAN_FIELDS.forEach((field) => {
      if (payload[field] === true) {
        const label = formatIpapiLabel(field)
        signals.push(`${label}: true`)
      }
    })

    if (payload?.vpn?.service) {
      signals.push(`VPN Service: ${payload.vpn.service}`)
    }
  }

  if (proxyData && typeof proxyData === "object") {
    let proxyPayload = proxyData
    const ipEntryKey = Object.keys(proxyData).find(
      (key) => key.includes(".") && typeof proxyData[key] === "object"
    )
    if (ipEntryKey) {
      proxyPayload = proxyData[ipEntryKey]
    }

    const detections = proxyPayload?.detections
    const operator = proxyPayload?.operator
    const detectionOrder = [
      "proxy",
      "vpn",
      "tor",
      "hosting",
      "anonymous",
      "scraper",
      "compromised"
    ]

    detectionOrder.forEach((field) => {
      if (detections?.[field] === true) {
        const label = formatIpapiLabel(field)
        signals.push(`${label}: true`)
      }
    })

    if (typeof detections?.risk === "number" && detections.risk > 0) {
      signals.push(`Risk Score: ${detections.risk}`)
    }

    if (operator?.name) {
      signals.push(`Operator: ${operator.name}`)
    }
    if (operator?.anonymity) {
      signals.push(`Anonymity: ${operator.anonymity}`)
    }
    if (operator?.popularity) {
      signals.push(`Popularity: ${operator.popularity}`)
    }
  }

  return signals
}




export const formatVirusTotalData = (vtData: any): string => {
  const d = vtData?.data;
  if (!d?.attributes) return "";

  const attr = d.attributes;
  const stats = attr.last_analysis_stats ?? {};
  const cert = attr.last_https_certificate;
  const whois = attr.whois || "";
  const isDomain = d.type === "domain";
  const isIp = d.type === "ip_address";

  const allFields: { section: string; label: string; value: any }[] = [];

  // Base Info
  const info: Record<string, any> = {
    ...(d.id && (isDomain || isIp) && { "IOC:": d.id }),
    ...(attr.md5 && !isDomain && !isIp && { "MD5:": attr.md5 }),
    ...(attr.sha1 && !isDomain && !isIp && { "SHA1:": attr.sha1 }),
    ...(attr.sha256 && { "SHA256:": attr.sha256 }),
    ...(attr.meaningful_name && { "Name:": attr.meaningful_name }),
    ...(attr.type_description && { "Type:": attr.type_description }),
    ...(attr.size && { "Size:": `${attr.size} bytes` }),
    ...(attr.tld && isDomain && { "TLD:": attr.tld }),
    ...(attr.first_submission_date && {
      "First Submission:": new Date(attr.first_submission_date * 1000).toISOString().split("T")[0]
    }),
    ...(attr.last_analysis_date && {
      "Last Analysis:": new Date(attr.last_analysis_date * 1000).toISOString().split("T")[0]
    }),
    ...(attr.reputation !== undefined && { "Reputation:": attr.reputation }),
    ...(attr.tags && attr.tags.length > 0 && { "Tags:": attr.tags.join(", ") }),
    ...(attr.names && attr.names.length > 0 && { "File Names:": attr.names.slice(0, 5).join(", ") }),
    ...(attr.trusted_verdict?.verdict && {
      "Trusted Verdict:": `${attr.trusted_verdict.verdict} (${attr.trusted_verdict.organization || "Unknown"})`
    }),
    ...(attr.asn && { "ASN:": attr.asn }),
    ...(attr.as_owner && { "AS Owner:": attr.as_owner }),
    ...(attr.country && { "Country:": attr.country }),
    ...(attr.continent && { "Continent:": attr.continent }),
    ...(attr.network && { "Network:": attr.network }),
    ...(attr.regional_internet_registry && { "Registry:": attr.regional_internet_registry }),
  };


  Object.entries(info).forEach(([label, value]) =>
    allFields.push({ section: isDomain ? "Domain Information" : isIp ? "IP Information" : "IOC Information", label, value })
  );

  // Vendor stats
  const analysis: Record<string, any> = {
    ...(stats.malicious > 0 && { "Malicious:": stats.malicious }),
    ...(stats.suspicious > 0 && { "Suspicious:": stats.suspicious }),
    ...(stats.undetected >= 0 && { "Undetected:": stats.undetected }),
    ...(stats.harmless >= 0 && { "Harmless:": stats.harmless })
  };
  Object.entries(analysis).forEach(([label, value]) =>
    allFields.push({ section: "Vendor Analysis", label, value })
  );

  // HTTPS cert
  const certFields: Record<string, string> = {
    ...(cert?.validity?.not_after && { "Valid Until:": cert.validity.not_after }),
    ...(cert?.issuer?.CN && { "Issuer:": cert.issuer.CN })
  };
  Object.entries(certFields).forEach(([label, value]) =>
    allFields.push({ section: "HTTPS Certificate", label, value })
  );

  // Categories (solo come blocco separato)
  const categoriesBlock =
    attr.categories && Object.values(attr.categories).length > 0
      ? `Categories:\n- ${Object.values(attr.categories).join(", ")}`
      : "";

  // Whois
  const whoisBlock =
    whois && extractKeyWhoisInfo(whois).trim()
      ? `Whois Information:\n${extractKeyWhoisInfo(whois)}`
      : "";

  // 🔧 Raggruppa per sezione con label padding uniforme
  const sections: Record<string, { label: string; value: any }[]> = {};
  allFields.forEach(({ section, label, value }) => {
    if (!sections[section]) sections[section] = [];
    sections[section].push({ label, value });
  });

  const maxLabelLength = Math.max(...allFields.map(f => f.label.length));
  const lines: string[] = [];

  for (const [sectionName, fields] of Object.entries(sections)) {
    lines.push(`${sectionName}:`);
    lines.push(
      ...fields.map(({ label, value }) =>
        `- ${label.padEnd(maxLabelLength)} ${value}`
      )
    );
  }

  if (categoriesBlock) lines.push(categoriesBlock);
  if (whoisBlock) lines.push(whoisBlock);

  return lines.join("\n");
};




/**
 * Estrae tutte le CVE da un testo.
 * @param text Il testo da cui estrarre le CVE.
 * @returns Un array di stringhe contenente tutte le CVE trovate.
 */
export const extractCVEs = (text: string): string[] => {
  // Regex per trovare le CVE
  const cveRegex = /CVE-\d{4}-\d{4,}/g;

  // Esegui la regex sul testo e restituisci i risultati
  const matches = text.match(cveRegex);

  // Se non ci sono corrispondenze, restituisci un array vuoto
  return matches || [];
};

/**
 * Estrae le CVE da un testo e le restituisce formattate.
 * @param text Il testo da cui estrarre le CVE.
 * @param asCSV Se `true`, le CVE sono restituite in formato CSV (con virgolette); se `false`, sono separate da un ritorno a capo.
 * @returns Una stringa contenente le CVE formattate.
 */
export const formatCVEs = (text: string, asCSV: boolean): string => {
  // Estrae le CVE dal testo
  const cves = extractCVEs(text);

  // Restituisce le CVE formattate
  if (asCSV) {
    // Formato CSV: "CVE1","CVE2","CVE3"
    return cves.map((cve) => `"${cve}"`).join(",");
  } else {
    // Formato con ritorno a capo: CVE1\nCVE2\nCVE3
    return cves.join("\n");
  }
};





const applyConditionalFormatting = (sheet: XLSX.WorkSheet, data: any[][], columns: number[]) => {
  const getColor = (value: number): string => {
    if (value >= 30) return "#f8d7da" // High: red
    if (value >= 10) return "#fff3cd" // Medium: yellow
    return "#d4edda" // Low: green
  }

  for (let row = 1; row < data.length; row++) {
    for (const col of columns) {
      const cellAddress = XLSX.utils.encode_cell({ r: row, c: col })
      const value = Number(data[row][col])
      const cell = sheet[cellAddress]
      if (cell && !isNaN(value)) {
        cell.s = {
          fill: { fgColor: { rgb: getColor(value).replace("#", "") } }
        }
      }
    }
  }
}


// === CSV EXPORT ===
export const convertResultsToCSV = (results: { [key: string]: any }): string => {
  const rows = [["IOC", "Servizio", "Tipo", "Valore"]]

  for (const [ioc, result] of Object.entries(results)) {
    const vt = result?.VirusTotal?.data?.attributes
    const ab = result?.AbuseIPDB?.data

    if (vt) {
      const stats = vt.last_analysis_stats || {}
      rows.push([ioc, "VirusTotal", "Malicious", formatValue(stats.malicious)])
      rows.push([ioc, "VirusTotal", "Suspicious", formatValue(stats.suspicious)])
      rows.push([ioc, "VirusTotal", "Harmless", formatValue(stats.harmless)])
      rows.push([ioc, "VirusTotal", "Undetected", formatValue(stats.undetected)])

      const whois = vt.whois || ""
      const creation = extractSingleFromWhois(whois, /Created:\s*(.+)/gi, "earliest")
      const expiry = extractSingleFromWhois(whois, /Expiry Date:\s*(.+)/gi, "earliest")
      const registrar = extractSingleFromWhois(whois, /Registrar(?: Name)?:\s*(.+)/gi, "first")
      const org = extractBestOrganization(whois)

      rows.push([ioc, "VirusTotal", "WHOIS - Creation", formatValue(creation)])
      rows.push([ioc, "VirusTotal", "WHOIS - Expiry", formatValue(expiry)])
      rows.push([ioc, "VirusTotal", "WHOIS - Registrar", formatValue(registrar)])
      rows.push([ioc, "VirusTotal", "WHOIS - Organization", formatValue(org)])
    }

    if (ab) {
      rows.push([ioc, "AbuseIPDB", "Abuse Score", formatValue(ab.abuseConfidenceScore)])
      rows.push([ioc, "AbuseIPDB", "Reports", formatValue(ab.totalReports)])
      rows.push([ioc, "AbuseIPDB", "Country", formatValue(ab.countryCode)])
      rows.push([ioc, "AbuseIPDB", "ISP", formatValue(ab.isp)])
    }
  }

  return rows.map((row) => row.map((c) => `"${c}"`).join(",")).join("\n")
}

export const formatValue = (value: any, defaultValue: string = "N/A"): string => {
  if (value === 0 || value === false) return value.toString()
  return value || defaultValue
}

export const ABUSE_FIELDS = [
  "IP",
  "Abuse Score",
  "Total Reports",
  "ISP",
  "Country",
  "Domain",
  "Usage Type",
  "IP Version",
  "Is Tor",
  "Is Whitelisted",
  "Hostnames",
  "Last Reported"
]


export const VT_FIELDS = [
  "IOC",
  "MD5",
  "SHA1",
  "SHA256",
  "Name",
  "Type",
  "Size",
  "TLD",
  "First Submission",
  "Last Analysis",
  "Reputation",
  "Tags",
  "File Names",
  "Trusted Verdict",
  "ASN",
  "AS Owner",
  "Country",
  "Continent",
  "Network",
  "Registry",
  "Malicious",
  "Suspicious",
  "Harmless",
  "Undetected",
  "HTTPS Valid Until",
  "HTTPS Issuer",
  "Categories",
  "WHOIS Creation",
  "WHOIS Expiry",
  "WHOIS Registrar",
  "WHOIS Organization"
]






export const getAbuseExportFields = (abuse: any): string[] => {
  const d = abuse?.data ?? abuse
  if (!d || typeof d !== "object") return ABUSE_FIELDS.map(() => "N/A")

  const hostnames =
    Array.isArray(d.hostnames) && d.hostnames.length > 0
      ? d.hostnames.join(", ")
      : "N/A"

  const isWhitelisted =
    d.isWhitelisted === true
      ? "Yes"
      : d.isWhitelisted === false
      ? "No"
      : "Unknown"

  return [
    d.ipAddress ?? "N/A",
    `${d.abuseConfidenceScore ?? 0}%`,
    d.totalReports?.toString() ?? "0",
    d.isp ?? "N/A",
    d.countryCode ?? "N/A",
    d.domain ?? "N/A",
    d.usageType ?? "N/A",
    d.ipVersion === 6 ? "IPv6" : "IPv4",
    d.isTor ? "Yes" : "No",
    isWhitelisted,
    hostnames,
    d.lastReportedAt ?? "N/A"
  ]
}


export const getVirusTotalExportFields = (attr: any, d?: any): string[] => {
  const stats = attr?.last_analysis_stats ?? {}
  const cert = attr?.last_https_certificate ?? {}
  const categories = attr?.categories
    ? Object.values(attr.categories).join(", ")
    : "N/A"

  const whois = attr?.whois || ""

  const creationDate =
    extractSingleFromWhois(whois, /Created:\s*(.+)/gi, "earliest") ??
    extractSingleFromWhois(whois, /Creation Date:\s*(.+)/gi, "earliest") ??
    extractSingleFromWhois(whois, /Registered On:\s*(.+)/gi, "earliest")

  const expiryDate =
    extractSingleFromWhois(whois, /Expiry Date:\s*(.+)/gi, "earliest") ??
    extractSingleFromWhois(whois, /Expire Date:\s*(.+)/gi, "earliest") ??
    extractSingleFromWhois(whois, /Expires On:\s*(.+)/gi, "earliest")

  const registrar =
    extractSingleFromWhois(whois, /Registrar(?: Name)?:\s*(.+)/gi, "first") ??
    extractSingleFromWhois(whois, /Sponsoring Registrar:\s*(.+)/gi, "first")

  const organization = extractBestOrganization(whois)

  return [
    d?.id ?? "N/A",                                  // IOC
    attr.md5 ?? "N/A",
    attr.sha1 ?? "N/A",
    attr.sha256 ?? "N/A",
    attr.meaningful_name ?? "N/A",
    attr.type_description ?? "N/A",
    attr.size?.toString() ?? "N/A",
    attr.tld ?? "N/A",
    attr.first_submission_date
      ? new Date(attr.first_submission_date * 1000).toISOString().split("T")[0]
      : "N/A",
    attr.last_analysis_date
      ? new Date(attr.last_analysis_date * 1000).toISOString().split("T")[0]
      : "N/A",
    attr.reputation?.toString() ?? "N/A",
    attr.tags?.join(", ") ?? "N/A",
    attr.names?.slice(0, 5).join(", ") ?? "N/A",
    attr.trusted_verdict?.verdict
      ? `${attr.trusted_verdict.verdict} (${attr.trusted_verdict.organization || "Unknown"})`
      : "N/A",
    attr.asn ?? "N/A",
    attr.as_owner ?? "N/A",
    attr.country ?? "N/A",
    attr.continent ?? "N/A",
    attr.network ?? "N/A",
    attr.regional_internet_registry ?? "N/A",
    stats.malicious?.toString() ?? "0",
    stats.suspicious?.toString() ?? "0",
    stats.harmless?.toString() ?? "0",
    stats.undetected?.toString() ?? "0",
    cert.validity?.not_after ?? "N/A",
    cert.issuer?.CN ?? "N/A",
    categories,
    creationDate ?? "N/A",
    expiryDate ?? "N/A",
    registrar ?? "N/A",
    organization ?? "N/A"
  ]
}




export const exportResultsByEngine = (results: { [key: string]: any }) => {
  const vtRows = [["IOC", ...VT_FIELDS.slice(1)]]
  const abuseRows = [["IOC", ...ABUSE_FIELDS]]

  for (const [ioc, result] of Object.entries(results)) {
    const vtData = result?.VirusTotal?.data
    const vtAttr = vtData?.attributes
    if (vtAttr) {
      vtRows.push([ioc, ...getVirusTotalExportFields(vtAttr, vtData)])
    }

    const abuse = result?.AbuseIPDB?.data
    if (abuse) {
      abuseRows.push([ioc, ...getAbuseExportFields(abuse)])
    }
  }

  if (vtRows.length > 1) downloadCSV(vtRows, "VirusTotal_IOC_Results")
  if (abuseRows.length > 1) downloadCSV(abuseRows, "AbuseIPDB_IOC_Results")
}

// Funzione per eseguire l'escape dei valori CSV
const escape = (value: any): string => {
  const str = String(value ?? "N/A")
  return `"${str.replace(/"/g, '""').replace(/\r?\n/g, " ")}"`
}

// Funzione per scaricare il CSV
const downloadCSV = (rows: any[][], filename: string, delimiter: string = ",") => {
  const escape = (value: any): string => {
    const str = String(value ?? "N/A")
    return `"${str.replace(/"/g, '""').replace(/\r?\n/g, " ")}"`
  }

  if (rows.length < 2) return // Niente da esportare se ci sono solo intestazioni

  const headers = rows[0]
  const dataRows = rows.slice(1)

  // Trova colonne non vuote (almeno un valore non vuoto e diverso da "N/A")
  const nonEmptyColumnIndices = headers.map((_, colIdx) =>
    dataRows.some(row => {
      const val = row[colIdx]
      return val !== "" && val !== null && val !== undefined && val !== "N/A"
    })
  )

  // Filtra colonne vuote
  const filteredRows = rows.map(row =>
    row.filter((_, colIdx) => nonEmptyColumnIndices[colIdx])
  )

  const csv = filteredRows.map((row) => row.map(escape).join(delimiter)).join("\n")
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" })
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  const date = new Date().toISOString().split("T")[0]
  a.href = url
  a.download = `${filename}_${date}.csv`
  a.click()
  URL.revokeObjectURL(url)
}



export const exportResultsToExcel = (results: { [key: string]: any }) => {
  const vtSheetData: (string | number)[][] = [["IOC", ...VT_FIELDS]]
  const abuseSheetData: (string | number)[][] = [["IOC", ...ABUSE_FIELDS]]

  for (const [ioc, result] of Object.entries(results)) {
    const vt = result?.VirusTotal?.data?.attributes
    if (vt) {
      vtSheetData.push([ioc, ...getVirusTotalExportFields(vt)])
    }
    const abuse = result?.AbuseIPDB?.data
    if (abuse) {
      abuseSheetData.push([ioc, ...getAbuseExportFields(abuse)])
    }
  }

  const workbook = XLSX.utils.book_new()

  const cleanSheet = (data: (string | number)[][]) => {
    if (data.length < 2) return null

    const headers = data[0]
    const rows = data.slice(1)

    const nonEmptyCols = headers.map((_, colIdx) =>
      rows.some(row => {
        const val = row[colIdx]
        return val !== "" && val !== null && val !== undefined && val !== "N/A"
      })
    )

    return data.map(row => row.filter((_, i) => nonEmptyCols[i]))
  }

  const cleanedVt = cleanSheet(vtSheetData)
  const cleanedAbuse = cleanSheet(abuseSheetData)

  if (cleanedVt?.length > 1) {
    const vtSheet = XLSX.utils.aoa_to_sheet(cleanedVt)
    XLSX.utils.book_append_sheet(workbook, vtSheet, "VirusTotal")
  }

  if (cleanedAbuse?.length > 1) {
    const abuseSheet = XLSX.utils.aoa_to_sheet(cleanedAbuse)
    XLSX.utils.book_append_sheet(workbook, abuseSheet, "AbuseIPDB")
  }

  XLSX.writeFile(workbook, `SOCx_IOC_Report_${new Date().toISOString().split("T")[0]}.xlsx`)
}



export const extractSingleFromWhois = (
  whois: string,
  regex: RegExp,
  strategy: "first" | "earliest" = "first"
): string | null => {
  const matches = [...whois.matchAll(regex)]
    .map((m) => (m[1] ? m[1].trim() : null))
    .filter((v): v is string => !!v);

  if (matches.length === 0) return null;

  const normalizeDate = (dateStr: string) =>
    /^\d{4}-\d{2}-\d{2}/.test(dateStr) ? dateStr.slice(0, 10) : dateStr;

  if (strategy === "earliest") {
    const validDates = matches
      .map(normalizeDate)
      .map((d) => new Date(d))
      .filter((d) => !isNaN(d.getTime()))
      .sort((a, b) => a.getTime() - b.getTime());

    return validDates.length > 0 ? validDates[0].toISOString().split("T")[0] : null;
  }

  const first = normalizeDate(matches[0]);
  return first;
};


// Extracts key information from the whois field
const extractKeyWhoisInfo = (whois: string): string => {
  if (!whois) return "No information available.";

  const extractMultiple = (regex: RegExp): string[] => {
    const matches = [...whois.matchAll(regex)];
    return matches.map((m) => m[1].trim());
  };

  const dedup = (arr: string[]) =>
    Array.from(new Set(arr.map((s) => s.trim())));

  const lines: string[] = [];

  // ✅ Prendi solo la data di creazione più vecchia
  const creationDate = extractSingleFromWhois(
    whois,
    /(?:Creation Date|Created On|Created|Domain Registration Date)[^:\w]?[:\s]*([0-9]{4}-[0-9]{2}-[0-9]{2}(?:[T\s][0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|\+\d{4})?)?)/gi,
    "earliest"
  );

  if (creationDate) {
    lines.push("Creation Date:");
    lines.push(`  - ${creationDate}`);
  }

  const orgs = dedup(extractMultiple(/(?:Registrant Organization|Sponsoring Organization|Organization|Org(?:Name|-name))[^:\w]?[:\s]*(.+)/gi));

  if (orgs.length > 0) {
    lines.push("Organization:");
    orgs.forEach((o) => lines.push(`  - ${o}`));
  }

  return lines.length > 0
    ? lines.join("\n")
    : "No key information found in the Whois record.";
};


export const extractBestOrganization = (whois: string): string => {
  const matches = [...whois.matchAll(/Organization:\s*(.+)/gi)]
    .map((m) => (m[1] ? m[1].trim() : null))
    .filter((v): v is string => !!v)

  const preferred = matches.find(
    (org) =>
      !/registrar|markmonitor|limited|llc/i.test(org) &&
      !org.toLowerCase().includes("privacy")
  )

  return preferred ?? matches[0] ?? "N/A"
}










// Funzione per inviare un messaggio al content script format-selection
export const formatAndCopySelection = async (tabId: number, frameId: number): Promise<void> => {
  try {
    const response = await chrome.tabs.sendMessage(tabId, {
      name: "format-selection",
    }, { frameId });

    const formattedText = response?.formatted;
    console.log("Response:", response);

    if (typeof formattedText === "string" && formattedText.trim() !== "" && response?.success) {
      console.log("Formatted text to copy:", formattedText);
      await copyToClipboard(formattedText);
    } else {
      showNotification("Nothing to copy", "No formatted text received.");
    }
  } catch (error) {
    showNotification("Error", "Could not format or copy selection.");
    console.error("formatAndCopySelection error:", error);
  }
};

export function formatSelectedText(lastValidSelection: Selection): string {
  console.log("Formatting selected text:", lastValidSelection);
  if (!lastValidSelection || lastValidSelection.rangeCount === 0) return "";

  const range = lastValidSelection.getRangeAt(0);
  const fragment = range.cloneContents();
  const rawSelectionText =
    (typeof lastValidSelection.toString === "function" ? lastValidSelection.toString() : "") ||
    fragment.textContent ||
    "";

  const div = document.createElement("div");
  div.appendChild(fragment);
  console.log("Selected HTML before cleanup:", div.innerHTML);

  // Pulizia del contenuto
  cleanContent(div);

  console.log("Selected HTML after cleanup:", div.innerHTML);
  const orderedBlocks: string[] = [];
  const seenBlocks = new Set<string>();
  const seenCanonicalBlocks = new Set<string>();
  const seenAggressiveBlocks = new Set<string>(); // tenuto per futura estensione, ma non usato nel check

  const appendBlock = (block: string | string[] | null, label: string) => {
    if (!block) return;

    const values = Array.isArray(block) ? block : [block];

    values.forEach((value) => {
      const normalized = normalizeOutputBlock(value);
      if (!normalized) return;

      const canonical = canonicalizeOutputBlock(normalized);
      // deduplica meno aggressiva: niente aggressiveCanonical nel check
      if (seenBlocks.has(normalized) || seenCanonicalBlocks.has(canonical)) {
        return;
      }

      console.log(`Dati ${label} estratti:`, normalized);
      seenBlocks.add(normalized);
      seenCanonicalBlocks.add(canonical);

      // mantengo comunque il calcolo aggressivo per uso futuro/debug
      const aggressive = aggressiveCanonicalizeOutputBlock(normalized);
      if (aggressive) {
        seenAggressiveBlocks.add(aggressive);
      }

      orderedBlocks.push(normalized);
    });
  };

  // Ordine estrattori
  appendBlock(extractJsonBlocks(div), "JSON");
  appendBlock(extractSplunkKeyValue(div), "Splunk");
  appendBlock(extractGridcellKeyValue(div), "gridcell");
  appendBlock(extractTableLikeData(div), "table-like");
  appendBlock(extractGridTable(div), "grid-table");
  appendBlock(extractMultiElementTable(div), "multi-table");
  appendBlock(extractListBlocks(div), "lists");
  appendBlock(extractAnchorValueRows(div), "anchor value");
  appendBlock(extractInlineRowKeyValue(div), "inline key-value");
  appendBlock(extractPairDivKeyValue(div), "div key-value");
  appendBlock(extractDtDdKeyValue(div), "dt/dl");
  appendBlock(extractLabelKeyValue(div), "label key-value");
  appendBlock(extractSpanKeyValue(div), "span key-value");

  // Estrattore testuale "nuovo"
  const strictTextKeyValue = extractTextKeyValue(div);
  appendBlock(strictTextKeyValue, "text key-value");

  if (!strictTextKeyValue) {
    // versione più permissiva
    appendBlock(
      extractTextKeyValue(div, { removeNodes: false, allowSimpleLines: true }),
      "loose text key-value"
    );

    // fallback legacy (versione vecchia semplificata)
    appendBlock(legacyExtractTextKeyValue(div), "legacy text key-value");
  }

  const remainingText = extractRemainingText(div);
  appendBlock(remainingText, strictTextKeyValue ? "remaining text (fallback)" : "remaining text");

  if (orderedBlocks.length === 0) {
    const fallback = normalizeOutputBlock(rawSelectionText || div.textContent || "");
    if (fallback) {
      orderedBlocks.push(fallback);
    }
  }

  const finalText = orderedBlocks.join("\n\n").trim();
  console.log("Final formatted text:", finalText);
  return finalText;
}

// ============================================================================
// Normalizzazione e deduplica
// ============================================================================

const JSON_ATTRIBUTE_CANDIDATES = ["data-json", "data-clipboard-text", "data-raw", "data-payload", "data-copy-text"];
const JSON_SELECTOR_CANDIDATES = ["pre", "code", "textarea", "[data-json]", "[data-testid*='json']", "[data-component*='json']", "[class*='json']"];

function normalizeOutputBlock(value: string): string {
  if (!value) return "";

  const replaced = value.replace(/\u00A0/g, " ").replace(/\r/g, "");
  const trimmed = replaced.trim();

  if (trimmed.startsWith("```") && trimmed.endsWith("```")) {
    return trimmed;
  }

  const lines = replaced
    .split("\n")
    .map((line) => line.replace(/\t/g, "    ").replace(/[ ]+$/g, ""));
  const filtered = lines.filter((line, index, array) => {
    if (line.trim() !== "") return true;
    const previous = array[index - 1];
    return previous && previous.trim() !== "";
  });

  return filtered.join("\n").trim();
}

function canonicalizeOutputBlock(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";

  const isCodeFence = /^```/.test(trimmed) && /```$/.test(trimmed);
  if (isCodeFence) return trimmed;

  return trimmed
    .replace(/\s+/g, " ")
    .replace(/\s+([.,;:])/g, "$1")
    .toLowerCase();
}

function aggressiveCanonicalizeOutputBlock(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";

  if (/^```/.test(trimmed) && /```$/.test(trimmed)) {
    return trimmed.toLowerCase();
  }

  return trimmed.replace(/\s+/g, "").toLowerCase();
}

// ============================================================================
// Estrazione JSON
// ============================================================================

function extractJsonBlocks(container: HTMLElement): string[] | null {
  const candidates = new Set<string>();

  const tryAddCandidate = (value?: string | null) => {
    if (!value) return;
    const trimmed = value.trim();
    if (!trimmed || trimmed.length < 2) return;
    if (looksLikeJsonStructure(trimmed)) {
      candidates.add(trimmed);
    }
  };

  tryAddCandidate(container.textContent);

  JSON_SELECTOR_CANDIDATES.forEach((selector) => {
    container.querySelectorAll<HTMLElement>(selector).forEach((el) => {
      tryAddCandidate(el.textContent);
    });
  });

  container.querySelectorAll<HTMLElement>("*").forEach((el) => {
    JSON_ATTRIBUTE_CANDIDATES.forEach((attr) => {
      if (el.hasAttribute(attr)) {
        tryAddCandidate(el.getAttribute(attr));
      }
    });
  });

  const formattedBlocks: string[] = [];
  candidates.forEach((candidate) => {
    const parsedBlocks = parseJsonFromSource(candidate);
    parsedBlocks.forEach((block) => formattedBlocks.push(block));
  });

  return formattedBlocks.length > 0 ? formattedBlocks : null;
}

function looksLikeJsonStructure(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return false;
  const startsWith = trimmed[0];
  const endsWith = trimmed[trimmed.length - 1];
  return (startsWith === "{" && endsWith === "}") || (startsWith === "[" && endsWith === "]");
}

function parseJsonFromSource(source: string): string[] {
  const trimmed = source.trim();
  const blocks: string[] = [];

  if (looksLikeJsonStructure(trimmed)) {
    const parsed = safeParseJsonString(trimmed);
    if (parsed !== null) {
      blocks.push(formatJsonBlock(parsed));
      return blocks;
    }
  }

  const lines = trimmed
    .split(/\r?\n+/)
    .map((line) => line.trim())
    .filter(Boolean);

  let parsedLine = false;
  lines.forEach((line) => {
    if (!looksLikeJsonStructure(line)) return;
    const parsed = safeParseJsonString(line);
    if (parsed !== null) {
      parsedLine = true;
      blocks.push(formatJsonBlock(parsed));
    }
  });
  if (parsedLine) return blocks;

  const looseBlocks = extractLooseJsonBlocks(trimmed);
  looseBlocks.forEach((block) => {
    const parsed = safeParseJsonString(block);
    if (parsed !== null) {
      blocks.push(formatJsonBlock(parsed));
    }
  });

  return blocks;
}

function extractLooseJsonBlocks(text: string): string[] {
  const blocks: string[] = [];
  let inString: string | null = null;
  let escaped = false;
  let start = -1;
  const stack: string[] = [];

  for (let i = 0; i < text.length; i++) {
    const char = text[i];

    if (inString) {
      if (char === "\\" && !escaped) {
        escaped = true;
        continue;
      }
      if (char === inString && !escaped) {
        inString = null;
      } else {
        escaped = false;
      }
      continue;
    }

    if (char === '"' || char === "'") {
      inString = char;
      escaped = false;
      continue;
    }

    if (char === "{" || char === "[") {
      if (stack.length === 0) {
        start = i;
      }
      stack.push(char === "{" ? "}" : "]");
    } else if ((char === "}" || char === "]") && stack.length > 0) {
      const expected = stack.pop();
      if (expected === char && stack.length === 0 && start !== -1) {
        const block = text.slice(start, i + 1).trim();
        if (looksLikeJsonStructure(block)) {
          blocks.push(block);
        }
        start = -1;
      }
    }
  }

  return blocks;
}

function safeParseJsonString(value: string): unknown {
  const attempts = new Set<string>();
  attempts.add(value);
  attempts.add(removeTrailingCommas(value));
  attempts.add(normalizeSingleQuotes(value));
  attempts.add(quoteUnquotedJsonKeys(value));
  attempts.add(quoteUnquotedJsonKeys(removeTrailingCommas(value)));
  attempts.add(quoteUnquotedJsonKeys(normalizeSingleQuotes(value)));
  attempts.add(
    quoteUnquotedJsonKeys(removeTrailingCommas(normalizeSingleQuotes(value)))
  );

  for (const attempt of attempts) {
    try {
      return JSON.parse(attempt);
    } catch {
      continue;
    }
  }

  return null;
}

function removeTrailingCommas(value: string): string {
  return value.replace(/,\s*([}\]])/g, "$1");
}

function normalizeSingleQuotes(value: string): string {
  if (!/'/.test(value)) return value;

  const convert = (match: string, prefix: string, content: string) => {
    const escaped = content.replace(/"/g, '\\"');
    return `${prefix}"${escaped}"`;
  };

  return value
    .replace(/([{\[,]\s*)'([^'\\]*(?:\\.[^'\\]*)*)'(?=\s*:)/g, convert)
    .replace(/(:\s*)'([^'\\]*(?:\\.[^'\\]*)*)'(?=\s*([,}\]]))/g, convert)
    .replace(/([[\s,])'([^'\\]*(?:\\.[^'\\]*)*)'(?=\s*([,\]]))/g, convert);
}

function quoteUnquotedJsonKeys(value: string): string {
  return value.replace(/([{,]\s*)([A-Za-z0-9_\-]+)\s*:(?!\/\/)/g, '$1"$2":');
}

function formatJsonBlock(value: unknown): string {
  return `\`\`\`json\n${JSON.stringify(value, null, 2)}\n\`\`\``;
}

// ============================================================================
// Liste
// ============================================================================

function extractListBlocks(container: HTMLElement): string | null {
  const lines: string[] = [];
  const lists = container.querySelectorAll("ul, ol");

  lists.forEach((list) => {
    if (!container.contains(list)) return;

    const children = Array.from(list.children).filter(
      (child): child is HTMLElement => child.tagName.toLowerCase() === "li"
    );

    if (children.length === 0) return;

    const isOrdered = list.tagName.toLowerCase() === "ol";
    let index = 1;

    children.forEach((child) => {
      const text = child.textContent?.replace(/\s+/g, " ").trim();
      if (!text) return;
      lines.push(isOrdered ? `${index}. ${text}` : `- ${text}`);
      index += 1;
    });

    list.remove();
  });

  return lines.length > 0 ? lines.join("\n") : null;
}

// ============================================================================
// Pulizia contenuto
// ============================================================================

function cleanContent(container: HTMLElement): void {
  // Elementi da rimuovere (contenuti invisibili o superflui)
  const selectorsToRemove = [
    "img",
    "svg",
    "select",
    "input[type='checkbox']",
    "script",
    "style",
    "noscript",
    "template",
    "iframe",
    "object",
    "embed",
  ];
  selectorsToRemove.forEach((selector) => {
    const elements = container.querySelectorAll(selector);
    elements.forEach((el) => el.remove());
  });

  // Rimuovi elementi hidden (con attributo hidden o stile display: none)
  // e gestisci aria-hidden solo se non c'è testo significativo
  container.querySelectorAll<HTMLElement>("*").forEach((el) => {
    const hasHiddenAttr = el.hasAttribute("hidden");
    const isDisplayNone = getComputedStyle(el).display === "none";
    const isAriaHidden = el.getAttribute("aria-hidden") === "true";
    const hasVisibleText = !!el.textContent?.trim();

    if (hasHiddenAttr || isDisplayNone || (isAriaHidden && !hasVisibleText)) {
      el.remove();
    }
  });

  // Rimuovi elementi tooltip (id o class con 'tooltip', case-insensitive)
  container.querySelectorAll<HTMLElement>("*").forEach((el) => {
    const id = el.id?.toLowerCase() || "";
    const className = (el.className as string | undefined)?.toLowerCase?.() || "";
    if (id.includes("tooltip") || className.includes("tooltip")) {
      el.remove();
    }
  });

  // Rimuovi elementi con class che contengono 'copy', case-insensitive
  container.querySelectorAll<HTMLElement>("*").forEach((el) => {
    const className = (el.className as string | undefined)?.toLowerCase?.() || "";
    if (className.includes("copy")) {
      el.remove();
    }
  });

  // Rimuovi tutti i tag <br>
  container.querySelectorAll("br").forEach((el) => el.remove());

  container.querySelectorAll<HTMLElement>("*").forEach((el) => {
    el.childNodes.forEach((node) => {
      if (node.nodeType === Node.TEXT_NODE) {
        node.textContent = node.textContent
          ?.replace(/\u00A0/g, " ") // Sostituisce spazi non separabili
          .replace(/[\u200B-\u200D\uFEFF]/g, " ") // Caratteri invisibili
          .replace(/\s+/g, " ") // Spazi multipli in uno solo
          .trim();
      }
    });

    // Rimuovi anche &nbsp; come entità HTML
    if (el.innerHTML.includes("&nbsp;")) {
      el.innerHTML = el.innerHTML.replace(/&nbsp;/g, " ");
    }
  });

  // Rimuovi <td>, <tr>, <th> vuoti
  container.querySelectorAll<HTMLElement>("td, tr, th").forEach((el) => {
    const text = el.textContent?.replace(/[\u00A0\u200B-\u200D\uFEFF\t\r\n ]/g, "").trim();
    if (!text) {
      el.remove();
    }
  });

  // Rimuovi elementi con solo testo =, :, [-], [+] o singole parentesi
  container.querySelectorAll<HTMLElement>("*").forEach((el) => {
    const text = el.textContent?.trim() || "";
    if (
      /^[:=]+$/.test(text) ||
      /^\[\-\]$/.test(text) ||
      /^\[\+\]$/.test(text) ||
      /^[\(\)\[\]\{\}]$/.test(text)
    ) {
      el.remove();
    }
  });

  // Rimuovi elementi con attributi icona
  container.querySelectorAll<HTMLElement>("*").forEach((el) => {
    if (
      el.hasAttribute("data-icon-name") ||
      el.hasAttribute("data-icon") ||
      el.hasAttribute("jscollapse") ||
      el.hasAttribute("jsexpands")
    ) {
      el.remove();
    } else {
      const iconDescendant = el.querySelector(
        ":scope > [data-icon-name], :scope > [data-icon], :scope > svg"
      );
      if (iconDescendant) {
        iconDescendant.remove();
      }
    }
  });

  // Rimuovi solo i tag <i> che sembrano icone
  container.querySelectorAll<HTMLElement>("i").forEach((el) => {
    const className = (el.className as string | undefined)?.toLowerCase?.() || "";
    if (
      className.includes("fa") ||
      className.includes("fa-icon") ||
      className.includes("dropdown") ||
      className.includes("ms-layer")
    ) {
      el.remove();
    }
  });

  // Rimuovi attributi indesiderati
  const attributesToRemove = [
    "style",
    "onclick",
    "onmouseover",
    "onerror",
    "onload",
    "onmouseout",
    "onmouseenter",
    "onmouseleave",
  ];
  container.querySelectorAll<HTMLElement>("*").forEach((el) => {
    attributesToRemove.forEach((attr) => el.removeAttribute(attr));
  });

  // Bottoni vuoti
  container.querySelectorAll<HTMLButtonElement>("button").forEach((el) => {
    if (el.textContent?.trim() === "") {
      el.remove();
    }
  });
}

// ============================================================================
// Tabelle & grid
// ============================================================================

function extractTableLikeData(container: HTMLElement): string | null {
  const keyValuePairs: string[][] = [];
  const trElements = container.querySelectorAll("tr");

  trElements.forEach((tr) => {
    const cells = Array.from(tr.querySelectorAll("td, th")).map(
      (cell) => cell.textContent?.trim() || ""
    );

    if (cells.length === 2) {
      const [key, value] = cells;
      if (key && value) {
        keyValuePairs.push([key, value]);
      }
      tr.remove();
    }
  });

  if (keyValuePairs.length === 0) return null;

  return formatKeyValue(keyValuePairs);
}

function extractGridcellKeyValue(container: HTMLElement): string | null {
  const keyValuePairs: string[][] = [];
  const rowElements = container.querySelectorAll('[role="row"]');

  rowElements.forEach((row) => {
    if (!container.contains(row)) return;
    if (row.closest('[role="gridcell"]')) return;

    const gridcells = Array.from(row.querySelectorAll('[role="gridcell"]'));
    let extracted = false;

    // gridcell con esattamente due figli (key/value)
    for (const gridcell of gridcells) {
      const children = Array.from(gridcell.children).filter(
        (el) => el.textContent?.trim()
      );
      if (children.length === 2) {
        const key = (children[0].textContent || "").trim();
        const value = (children[1].textContent || "").trim();
        if (key && value) {
          keyValuePairs.push([key, value]);
          row.remove();
          extracted = true;
          break;
        }
      }
    }

    // gridcell separati
    if (!extracted && gridcells.length >= 2) {
      const key = (gridcells[0].textContent || "").trim();
      const value = (gridcells[1].textContent || "").trim();
      if (key && value) {
        keyValuePairs.push([key, value]);
        row.remove();
      }
    }
  });

  if (keyValuePairs.length === 0) return null;

  return formatKeyValue(keyValuePairs);
}

function extractGridTable(container: HTMLElement): string | null {
  const rows: string[][] = [];
  const rowElements = container.querySelectorAll('[role="row"]');

  rowElements.forEach((rowEl) => {
    if (!container.contains(rowEl)) return;
    if (rowEl.closest('[role="gridcell"]')) return;

    const cells = Array.from(rowEl.querySelectorAll('[role="gridcell"]')).map(
      (cell) => (cell as Element).textContent?.trim().replace(/\s+/g, " ") || ""
    );

    if (cells.length > 0 && cells.some((cell) => cell !== "")) {
      rows.push(cells);
      rowEl.remove();
    }
  });

  if (rows.length === 0) return null;

  return formatTableData(rows);
}

function extractMultiElementTable(container: HTMLElement): string | null {
  const tableRows: string[][] = [];

  const trElements = container.querySelectorAll("tr");
  trElements.forEach(tr => {
    const cells = Array.from(tr.querySelectorAll("td, th")).map(cell =>
      (cell.textContent || "").trim().replace(/\s+/g, " ")
    );

    // Aggiungi solo righe con almeno 3 colonne
    if (cells.length >= 3) {
      tableRows.push(cells);
    }

    // Rimuove la riga dal DOM
    tr.remove();
  });

  if (tableRows.length === 0) return null;

  return formatTableData(tableRows);
}


function formatKeyValue(rows: string[][]): string {
  const isSpecialCase = (text: string) => {
    return (
      /(\d{1,2}:\d{2}(:\d{2})?)/.test(text) || // orario
      /\bhttps?:\/\//.test(text) || // URL
      /\S+@\S+\.\S+/.test(text) || // email
      /\d{4}-\d{2}-\d{2}/.test(text) || // data ISO
      /\bUTC[+-]?\d{1,2}:\d{2}\b/.test(text) || // timezone
      /\/[\w\/\-:.]+/.test(text)
    );
  };

  const removeSurroundingQuotes = (text: string) => {
    if (
      (text.startsWith('"') && text.endsWith('"')) ||
      (text.startsWith("'") && text.endsWith("'"))
    ) {
      return text.slice(1, -1);
    }
    return text;
  };

  const cleanText = (text: string) =>
    text
      .replace(/[\r\n]+/g, " ")
      .replace(/\s+/g, " ")
      .trim();

  const cleanedKeys = rows
    .filter((r) => r.length === 2)
    .map(([key]) => {
      let cleanedKey = cleanText(key);
      if (!isSpecialCase(cleanedKey)) {
        cleanedKey = removeSurroundingQuotes(cleanedKey);
        cleanedKey = cleanedKey.replace(/[:=]+$/, "");
      }
      return cleanedKey + ":";
    });

  const maxKeyLength = Math.max(...cleanedKeys.map((k) => k.length));

  return rows
    .filter((r) => r.length === 2)
    .map(([key, value], index) => {
      let cleanedValue = cleanText(value);
      if (!isSpecialCase(cleanedValue)) {
        cleanedValue = cleanedValue.replace(/[,;]+$/, "");
        cleanedValue = removeSurroundingQuotes(cleanedValue);
      }

      return `${cleanedKeys[index].padEnd(maxKeyLength, " ")} ${cleanedValue}`;
    })
    .join("\n");
}

function formatTableData(rows: string[][]): string {
  if (rows.length === 0) return "";

  const columnCount = Math.max(...rows.map((r) => r.length));

  const cleanedRows = rows.map((row) =>
    row.map((cell) => cell.replace(/[\r\n]+/g, " ").trim())
  );

  if (columnCount === 2) {
    return formatKeyValue(cleanedRows);
  } else {
    return formatMarkdownTable(cleanedRows);
  }
}

function formatMarkdownTable(rows: string[][]): string {
  if (rows.length === 0) return "";

  const columnCount = Math.max(...rows.map((r) => r.length));

  const cleanedRows = rows.map((row) =>
    row.map((cell) =>
      (cell || "").replace(/[\r\n]+/g, " ").replace(/\s+/g, " ").trim()
    )
  );

  const colWidths: number[] = Array(columnCount).fill(0);
  cleanedRows.forEach((row) => {
    row.forEach((cell, index) => {
      colWidths[index] = Math.max(colWidths[index], cell.length);
    });
  });

  const formatRow = (row: string[]) => {
    const padded = row.map((cell, i) => {
      const content = cell || "";
      return content.padEnd(colWidths[i], " ");
    });
    return "| " + padded.join(" | ") + " |";
  };

  return cleanedRows.map(formatRow).join("\n");
}

// ============================================================================
// label / span / dt-dd / div pair
// ============================================================================

function extractLabelKeyValue(container: HTMLElement): string | null {
  const keyValuePairs: string[][] = [];
  const labels = container.querySelectorAll("label");

  labels.forEach((label) => {
    const key = (label.textContent || "").trim();

    let sibling = label.nextElementSibling;
    while (sibling && sibling.textContent?.trim() === "") {
      sibling = sibling.nextElementSibling;
    }

    if (sibling) {
      const value = (sibling.textContent || "").trim();
      keyValuePairs.push([key, value]);
      sibling.remove();
    }

    label.remove();
  });

  if (keyValuePairs.length === 0) return null;

  return formatKeyValue(keyValuePairs);
}

function extractSpanKeyValue(container: HTMLElement): string | null {
  const keyValuePairs: string[][] = [];
  const nodes = Array.from(container.querySelectorAll("*"));

  let lastSpan: HTMLElement | null = null;

  nodes.forEach((node: Element) => {
    if (node.tagName.toLowerCase() === "span" && container.contains(node)) {
      if (lastSpan) {
        const key = lastSpan.textContent?.trim() || "";
        const value = node.textContent?.trim() || "";

        if (key && value) {
          keyValuePairs.push([key, value]);
          lastSpan.remove();
          node.remove();
          lastSpan = null;
        }
      } else {
        lastSpan = node as HTMLElement;
      }
    }
  });

  if (keyValuePairs.length === 0) return null;

  return formatKeyValue(keyValuePairs);
}

function extractDtDdKeyValue(container: HTMLElement): string | null {
  const keyValuePairs: string[][] = [];
  const elements = Array.from(container.querySelectorAll("dt, dd"));

  for (let i = 0; i < elements.length; i++) {
    const el = elements[i];

    if (el instanceof Element && el.tagName.toLowerCase() === "dt") {
      const key = el.textContent?.trim() || "";

      const next = elements[i + 1];
      if (next instanceof Element && next.tagName.toLowerCase() === "dd") {
        const value = next.textContent?.trim() || "";
        if (key && value) {
          keyValuePairs.push([key, value]);
          el.remove();
          next.remove();
        }
        i++;
      }
    }
  }

  if (keyValuePairs.length === 0) return null;

  return formatKeyValue(keyValuePairs);
}

function extractPairDivKeyValue(container: HTMLElement): string | null {
  const keyValuePairs: string[][] = [];
  let lastKey: string | null = null;

  const parents = container.querySelectorAll<HTMLElement>("*");
  parents.forEach((parent) => {
    if (!container.contains(parent)) return;

    const children = Array.from(parent.children);

    if (children.length === 2) {
      const key = (children[0].textContent || "").trim();
      const value = (children[1].textContent || "").trim();
      let extracted = false;

      if (key && value) {
        keyValuePairs.push([key, value]);
        lastKey = key;
        extracted = true;
      } else if (!key && value && lastKey) {
        keyValuePairs.push([lastKey, value]);
        extracted = true;
      } else if (key && !value) {
        // lascio nel DOM per altri tentativi
        lastKey = key;
      }

      if (extracted) {
        children[0].remove();
        children[1].remove();
        parent.remove();
      }
    }
  });

  if (keyValuePairs.length === 0) return null;

  return formatKeyValue(keyValuePairs);
}

// ============================================================================
// Inline row key-value / anchor row
// ============================================================================

const INLINE_LABEL_PATTERN = /[:：]\s*$/;

const getInlineNodeText = (node: Node): string => {
  if (node.nodeType === Node.TEXT_NODE) {
    return (
      node.textContent
        ?.replace(/\u00A0/g, " ")
        .replace(/\s+/g, " ")
        .trim() ?? ""
    );
  }

  if (node instanceof HTMLElement) {
    return (
      node.textContent
        ?.replace(/\u00A0/g, " ")
        .replace(/\s+/g, " ")
        .trim() ?? ""
    );
  }

  return "";
};

const normalizeLabelKey = (key: string): string => {
  return key.replace(/[:：\s]+$/, "").trim();
};

function extractAnchorValueRows(container: HTMLElement): string | null {
  const keyValuePairs: string[][] = [];
  const candidates = container.querySelectorAll<HTMLElement>("p, div, li");

  candidates.forEach((node) => {
    if (!container.contains(node)) return;

    if (node.closest("table, thead, tbody, tfoot, tr, dl")) return;

    const elementChildren = Array.from(node.children).filter(
      (child): child is HTMLElement => child instanceof HTMLElement
    );

    if (elementChildren.length < 2 || elementChildren.length > 4) return;

    const labelEl = elementChildren[0];
    const valueEls = elementChildren.slice(1);

    const labelText = getInlineNodeText(labelEl);
    if (!labelText || labelText.length > 80) return;

    const labelQualifies =
      labelEl.matches("a, strong, span") ||
      labelEl.hasAttribute("href") ||
      /filter-option|title|label/i.test(labelEl.className);

    if (!labelQualifies) return;

    const values = valueEls
      .map((child) => getInlineNodeText(child))
      .filter(Boolean);

    if (values.length === 0) return;

    const containsAnotherLabel = values.some((text) =>
      INLINE_LABEL_PATTERN.test(text ?? "")
    );
    if (containsAnotherLabel) return;

    const valueText = values.join(" ").trim();
    if (!valueText) return;

    keyValuePairs.push([normalizeLabelKey(labelText), valueText]);
    node.remove();
  });

  return keyValuePairs.length > 0 ? formatKeyValue(keyValuePairs) : null;
}

function extractInlineRowKeyValue(container: HTMLElement): string | null {
  const keyValuePairs: string[][] = [];
  const parents = container.querySelectorAll<HTMLElement>("*");

  parents.forEach((parent) => {
    if (!container.contains(parent)) return;
    if (parent.closest("table, thead, tbody, tfoot, tr, dl")) return;

    const elementChildren = Array.from(parent.children).filter(
      (child): child is HTMLElement => child instanceof HTMLElement
    );

    if (elementChildren.length < 2 || elementChildren.length > 6) return;

    const labelChild = elementChildren.find((child) => {
      const text = getInlineNodeText(child);
      return text && INLINE_LABEL_PATTERN.test(text);
    });

    if (!labelChild) return;

    const keyText = getInlineNodeText(labelChild);
    if (!keyText || keyText.length > 80) return;

    const labelIndex = elementChildren.indexOf(labelChild);
    const valueCandidates = elementChildren.slice(labelIndex + 1);

    const values: string[] = [];
    const consumedNodes: Node[] = [];

    if (valueCandidates.length > 0) {
      const containsAnotherLabel = valueCandidates.some((child) =>
        INLINE_LABEL_PATTERN.test(getInlineNodeText(child))
      );
      if (containsAnotherLabel) return;

      valueCandidates.forEach((child) => {
        const text = getInlineNodeText(child);
        if (text) values.push(text);
        consumedNodes.push(child);
      });
    }

    if (values.length === 0) {
      let sibling: ChildNode | null = labelChild.nextSibling;
      while (sibling) {
        const text = getInlineNodeText(sibling);
        if (text && INLINE_LABEL_PATTERN.test(text)) break;

        if (text) values.push(text);
        consumedNodes.push(sibling);
        sibling = sibling.nextSibling;
      }
    }

    if (values.length === 0) return;

    keyValuePairs.push([normalizeLabelKey(keyText), values.join(" ")]);

    consumedNodes.forEach((node) => {
      if (node.parentNode) {
        node.parentNode.removeChild(node);
      }
    });
    labelChild.remove();
  });

  return keyValuePairs.length > 0 ? formatKeyValue(keyValuePairs) : null;
}

// ============================================================================
// Text key-value (nuovo) + legacy fallback
// ============================================================================

function collectStructuredLines(container: HTMLElement): string[] {
  const doc = container.ownerDocument ?? document;
  const walker = doc.createTreeWalker(
    container,
    NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT,
    null
  );
  const lines: string[] = [];
  let currentLine = "";

  const flushLine = () => {
    const normalized = currentLine.trim();
    if (normalized) {
      lines.push(normalized);
    }
    currentLine = "";
  };

  while (walker.nextNode()) {
    const node = walker.currentNode;

    if (node.nodeType === Node.TEXT_NODE) {
      const rawText = node.textContent ?? "";
      if (!rawText) continue;

      const segments = rawText.split(/[\r\n]+/);
      segments.forEach((segment, index) => {
        const text = segment.replace(/\s+/g, " ").trim();
        if (text) {
          currentLine += (currentLine ? " " : "") + text;
        }
        if (index < segments.length - 1) {
          flushLine();
        }
      });
    } else if (node.nodeType === Node.ELEMENT_NODE) {
      const element = node as Element;
      const tag = element.tagName.toLowerCase();

      if (tag === "li") {
        flushLine();
        currentLine = "-";
      } else if (["strong", "b", "i", "em", "u", "span"].includes(tag)) {
        continue;
      } else if (
        ["p", "div", "section", "article", "header", "footer", "br", "table", "tr", "pre", "code"].includes(tag)
      ) {
        flushLine();
      }
    }
  }

  flushLine();
  return lines;
}

function extractTextKeyValue(
  container: HTMLElement,
  options: { removeNodes?: boolean; allowSimpleLines?: boolean } = {}
): string | null {
  const keyValuePairs: string[][] = [];
  const textNodes = Array.from(container.querySelectorAll("*"));

  const structuredLines = collectStructuredLines(container);
  const fallbackLines = (container.textContent || "")
    .split(/\r\n|\n|\r/)
    .map((line) => line.replace(/\s+/g, " ").trim())
    .filter(Boolean);
  const lines = structuredLines.length > 0 ? structuredLines : fallbackLines;

  const isSpecialCase = (text: string) =>
    /^\d{1,2}:\d{2}(:\d{2})?$/.test(text) || // ora
    /^https?:\/\/\S+$/.test(text) || // URL
    /^\S+@\S+\.\S+$/.test(text) || // email
    /^\d{4}-\d{2}-\d{2}$/.test(text) || // data ISO
    /^UTC[+-]?\d{1,2}:\d{2}$/.test(text) || // timezone
    /^\/[\w\/\-:.]+$/.test(text); // path

  lines.forEach((line) => {
    const trimmedLine = line.trim();
    if (trimmedLine === "") return;

    const parsed = parseKeyValueLine(trimmedLine);
    if (parsed) {
      const [key, value] = parsed;

      if (isSpecialCase(trimmedLine)) return;

      keyValuePairs.push([key, value]);

      if (options.removeNodes !== false) {
        textNodes.forEach((node) => {
          if (
            node.textContent?.includes(trimmedLine) ||
            node.textContent?.includes(key) ||
            node.textContent?.includes(value)
          ) {
            node.remove();
          }
        });
      }
    } else if (options.allowSimpleLines) {
      const simpleMatch = trimmedLine.match(/^([A-Za-z0-9][\w\s-]{0,80})\s+(.+)$/);
      if (simpleMatch) {
        const keyCandidate = simpleMatch[1].trim();
        const valueCandidate = simpleMatch[2].trim();
        if (keyCandidate && valueCandidate && !isSpecialCase(trimmedLine)) {
          keyValuePairs.push([keyCandidate, valueCandidate]);
        }
      }
    }
  });

  if (keyValuePairs.length === 0) return null;

  return formatKeyValue(keyValuePairs);
}

const GENERIC_KEY_VALUE_PATTERNS: RegExp[] = [
  /^-?\s*(.+?)\s*[:：=]\s*(.+)$/,
  /^-?\s*(.+?)\t+(.+)$/,
  /^-?\s*(.+?)\s+-{1,3}\s+(.+)$/,
  /^-?\s*(.+?)\s+\|\s+(.+)$/,
  /^-?\s*(.+?)(?:\s*\.{2,}\s+)(.+)$/,
];

const sanitizeKeyCandidate = (key: string): string => {
  return key.replace(/[\s.:=-]+$/, "").replace(/^\s*[-•]+/, "").trim();
};

const isValidKeyCandidate = (key: string): boolean => {
  if (!key) return false;
  if (key.length > 80) return false;
  const firstChar = key.trim().charAt(0);
  // CONSENTI anche chiavi che iniziano con numeri (es. tabelle Defender/Azure)
  if (!/[A-Za-z0-9]/.test(firstChar)) return false;
  return true;
};

function parseKeyValueLine(line: string): [string, string] | null {
  for (const pattern of GENERIC_KEY_VALUE_PATTERNS) {
    const match = line.match(pattern);
    if (!match) continue;

    const key = sanitizeKeyCandidate(match[1] ?? "");
    const value = (match[2] ?? "").trim();

    if (!key || !value) continue;
    if (!isValidKeyCandidate(key)) continue;

    return [key, value];
  }

  return null;
}

// Legacy: versione vecchia più semplice, usata come fallback
function legacyExtractTextKeyValue(container: HTMLElement): string | null {
  const keyValuePairs: string[][] = [];
  const textNodes = Array.from(container.querySelectorAll("*"));
  const lines = (container.textContent || "").split("\n");

  const isSpecialCase = (text: string) =>
    /^\d{1,2}:\d{2}(:\d{2})?$/.test(text) ||
    /^https?:\/\/\S+$/.test(text) ||
    /^\S+@\S+\.\S+$/.test(text) ||
    /^\d{4}-\d{2}-\d{2}$/.test(text) ||
    /^UTC[+-]?\d{1,2}:\d{2}$/.test(text) ||
    /^\/[\w\/\-:.]+$/.test(text);

  lines.forEach((line) => {
    const trimmedLine = line.trim();
    if (trimmedLine === "") return;

    const match = trimmedLine.match(/^([^\s:=][^:=]*)\s*[:=]\s*(.+)$/);
    if (match) {
      const key = match[1].trim();
      const value = match[2].trim();

      if (isSpecialCase(trimmedLine)) return;

      keyValuePairs.push([key, value]);

      textNodes.forEach((node) => {
        if (
          node.textContent?.includes(trimmedLine) ||
          node.textContent?.includes(key) ||
          node.textContent?.includes(value)
        ) {
          node.remove();
        }
      });
    }
  });

  if (keyValuePairs.length === 0) return null;

  return formatKeyValue(keyValuePairs);
}

// ============================================================================
// Splunk
// ============================================================================

function extractSplunkKeyValue(container: HTMLElement): string | null {
  const keyValuePairs: string[][] = [];
  const keyLevelSpans = container.querySelectorAll("span.key[class*='level-']");

  keyLevelSpans.forEach((levelSpan) => {
    const keyNameEl = Array.from(levelSpan.children).find((child) =>
      (child as Element).matches("span.key-name")
    );
    const valueEl = Array.from(levelSpan.children).find((child) =>
      (child as Element).matches("span.t")
    );

    if (keyNameEl && valueEl) {
      const key = (keyNameEl as Element).textContent?.trim() || "";
      const value = (valueEl as Element).textContent?.trim() || "";

      if (key && value) {
        keyValuePairs.push([key, value]);
      }
    }
  });

  keyLevelSpans.forEach((levelSpan) => levelSpan.remove());

  if (keyValuePairs.length === 0) return null;

  return formatKeyValue(keyValuePairs);
}

// ============================================================================
// Testo rimanente
// ============================================================================

function extractRemainingText(container: HTMLElement, separator: string = "\n"): string {
  return collectStructuredLines(container).join(separator).trim();
}



