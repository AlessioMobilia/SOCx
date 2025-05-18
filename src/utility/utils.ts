// src/utils.ts
import { sendToContentScript } from "@plasmohq/messaging"
import { Storage } from "@plasmohq/storage"
import * as XLSX from "xlsx"

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


// Logic to identify the type of IOC
export const identifyIOC = (text: string): string | null => {
  // Regex to validate IP, hash, domain, URL, email, MAC address, and ASN
  const regexIPv6 = /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:[0-9]{1,3}\.){3}[0-9]{1,3}/g;
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
  if (ipRegex.test(text) || regexIPv6.test(text)) {
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
  const regexIPv6 = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/g;
  // Verifica se l'indirizzo è un IPv6 valido
  if (ip.match(regexIPv6)) {
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
    await sendToContentScript({
      name: "copy-to-clipboard",
      body: { text }
    })
    showNotification("Done", "IOC copied to clipboard")
  } catch (err) {
    console.error("Error copying to clipboard:", err)
  }
}






export const extractIOCs = (text: string, refanged: boolean = true): string[] | null => {
  const regexIPv6 = /([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])/g;
  const ipAddressRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  const domainRegex = /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g;
  const urlRegex = /\bhttps?:\/\/[^\s,;\r\n]+\b/g;
  const md5Regex = /\b[a-fA-F0-9]{32}\b/g;
  const sha1Regex = /\b[a-fA-F0-9]{40}\b/g;
  const sha256Regex = /\b[a-fA-F0-9]{64}\b/g;
  const emailRegex = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
  const defangedUrlRegex = /\bhxxps?:\/\/[^\s,;\r\n]+\b/g;
  const defangedDomainRegex = /\b(?:[a-zA-Z0-9-]+\[\.\])+[a-zA-Z]{2,}\b/g;
  const defangedIpRegex = /\b(?:\d{1,3}\[\.\]){3}\d{1,3}\b/g;
  const macAddressRegex = /\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b/g;
  const asnRegex = /\bAS\d{1,5}(?:\.\d{1,5})?\b/gi;
  const combinedRegex = new RegExp(
    `(${regexIPv6.source}|${ipAddressRegex.source}|${domainRegex.source}|${urlRegex.source}|${md5Regex.source}|${sha1Regex.source}|${sha256Regex.source}|${emailRegex.source}|${defangedUrlRegex.source}|${defangedDomainRegex.source}|${defangedIpRegex.source}|${macAddressRegex.source}|${asnRegex.source})`,
    'gi'
  );

  // Find all matches with the combined regex
  const matches = text.match(combinedRegex);

  // Map the found IOCs and apply refanging
  if (refanged && matches != null) {
    return matches
      .map((ioc) => refang(ioc).trim()) // Apply refanging and remove spaces
      .filter(Boolean); // Filter out any empty values
  } else if (matches != null) {
    return matches.filter(Boolean);
  } else {
    return null;
  }
};






/**
* Main function to format combined AbuseIPDB and VirusTotal data.
* @param data Dati combinati.
* @returns Stringa formattata.
*/
export const parseAndFormatResults = (data: any): string => {
  const lines: string[] = [];
  console.log("Data:", data);

  if (data?.AbuseIPDB?.data) {
    lines.push(formatAbuseIPDBData(data.AbuseIPDB));
    lines.push(""); // Separazione
  }

  if (data?.VirusTotal?.data) {
    lines.push(formatVirusTotalData(data.VirusTotal));
  }

  return lines.join("\n").trim();
};












export const formatAbuseIPDBData = (abuseData: any): string => {
  const d = abuseData?.data;
  if (!d) return "";

  const hostnames =
    d.hostnames && d.hostnames.length > 0
      ? d.hostnames.join(", ")
      : undefined;

  const isWhitelisted = d.isWhitelisted === true
    ? "Yes"
    : d.isWhitelisted === false
    ? "No"
    : "Unknown";

  // Prepara i dati
  const fields: Record<string, string | number> = {
    "IP:": d.ipAddress,
    "Abuse Score:": `${d.abuseConfidenceScore}%`,
    "Total Reports:": d.totalReports,
    "ISP:": d.isp,
    "Country:": d.countryCode,
    "Domain:": d.domain,
    "Usage Type:": d.usageType,
    "IP Version:": d.ipVersion === 6 ? "IPv6" : "IPv4",
    "Is Tor:": d.isTor ? "Yes" : "No",
    "Is Whitelisted:": isWhitelisted,
    ...(hostnames ? { "Hostnames:": hostnames } : {}),
    "Last Reported:": d.lastReportedAt ?? "N/A"
  };

  // Calcola la larghezza massima per allineare
  const labelWidth = Math.max(...Object.keys(fields).map(k => k.length));

  // Genera le righe allineate
  const lines = Object.entries(fields).map(
    ([label, value]) => `- ${label.padEnd(labelWidth)} ${value}`
  );

  return `IP Information (AbuseIPDB):\n${lines.join("\n")}`;
};




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
    allFields.push({ section: isDomain ? "Domain Information (VirusTotal)" : isIp ? "IP Information (VirusTotal)" : "IOC Information (VirusTotal)", label, value })
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




