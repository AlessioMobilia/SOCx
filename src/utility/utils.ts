// src/utils.ts

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


// Logica per identificare il tipo di IOC
export const identifyIOC = (text: string): string | null => {
  // Regex per validare IP, hash, dominio, URL, email, MAC address e ASN
  const regexIPv6 = /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:[0-9]{1,3}\.){3}[0-9]{1,3}/g;
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
  const domainRegex = /^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
  const urlRegex = /https?:\/\/[^\s]+/;
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  const macAddressRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
  const asnRegex = /^AS\d{1,5}(?:\.\d{1,5})?$/i;

  // Controlla se l'input è un indirizzo MAC
  if (macAddressRegex.test(text)) {
    return "MAC";
  }

  // Controlla se l'input è un ASN
  if (asnRegex.test(text)) {
    return "ASN";
  }

  // Controlla se l'input è un IP (IPv4 o IPv6)
  if (ipRegex.test(text) || regexIPv6.test(text)) {
    if (isPrivateIP(text)) {
      showNotification("Errore", text + " è un IP Privato");
      return "Private IP";
    } else {
      return "IP";
    }
  }

  // Controlla se l'input è un hash
  if (hashRegex.test(text)) return "Hash";

  // Controlla se l'input è un dominio
  if (domainRegex.test(text)) return "Dominio";

  // Controlla se l'input è un URL
  if (urlRegex.test(text)) return "URL";

  // Controlla se l'input è un'email
  if (emailRegex.test(text)) return "Email";

  // Se non corrisponde a nessun IoC, restituisci null
  return null;
};


// Verifica IP privato
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




export const showNotification = (title: string, message: string, type: "basic" = "basic") => {
  chrome.notifications.create({
    type,
    title,
    message,
    iconUrl: chrome.runtime.getURL("/assets/icon.png"),
  })
}



export const saveIOC = async (type: string, text: string): Promise<boolean> => {
  try {
    const result = await chrome.storage.local.get(["iocHistory"]); // Usa chrome.storage.local
    let iocHistory = result.iocHistory || [];
    // Controlla se l'IOC è già presente
    const isDuplicate = iocHistory.some(
      (ioc) => ioc.text === text && ioc.type === type
    );
    if (!isDuplicate) {
      // Aggiungi il nuovo IOC all'inizio dell'array
      iocHistory.unshift({ type, text, timestamp: new Date().toISOString() });
      // Mantieni solo gli ultimi 20 IOC
      if (iocHistory.length > 20) {
        iocHistory = iocHistory.slice(0, 20);
      }
      // Salva lo storico aggiornato
      await chrome.storage.local.set({ iocHistory }); // Usa chrome.storage.local
      return true;
    } else {
      return true; // L'IOC è già presente, ma consideriamo l'operazione comunque valida
    }
  } catch (error) {
    return false;
  }
};



export const copyToClipboard = (text: string, tabId: number): void => {
  chrome.tabs.sendMessage(tabId, { action: "copyToClipboard", text }, (response) => {
    if (response?.success) {
      showNotification("Fatto", "IOC copiati nella clipboard");
    } 
  });
};



export const extractIOCs = (text: string, refanged: boolean = true): string[] => {
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

  // Trova tutte le corrispondenze con la regex combinata
  const matches = text.match(combinedRegex);


  // Mappa gli IOC trovati e applica il refanging
  if (refanged && matches!=null) {
    return matches
      .map((ioc) => refang(ioc).trim()) // Applica il refanging e rimuove spazi
      .filter(Boolean); // Filtra eventuali valori vuoti
  } else if (matches!=null) {
    return matches.filter(Boolean);
  }else{
    return null;
  }
};



export const formatAbuseIPDBData = (abuseData: any): string => {
  const d = abuseData?.data
  if (!d) return ""

  return `
Informazioni IP (AbuseIPDB):
- IP:\t\t\t${formatValue(d.ipAddress)}
- Punteggio di Abuso:\t${formatValue(d.abuseConfidenceScore)}%
- Segnalazioni Totali:\t${formatValue(d.totalReports)}
- ISP:\t\t\t${formatValue(d.isp)}
- Paese:\t\t${formatValue(d.countryCode)}
- Dominio:\t\t${formatValue(d.domain)}
- Ultima Segnalazione:\t${formatValue(d.lastReportedAt)}
  `.trim()
}


export const formatVirusTotalData = (vtData: any): string => {
  const d = vtData?.data
  if (!d || !d.attributes) return ""

  const attr = d.attributes
  const stats = attr.last_analysis_stats ?? {}
  const cert = attr.last_https_certificate ?? {}
  const whois = attr.whois ?? ""

  const categories = attr.categories
    ? `Categorie:\t\t${Object.values(attr.categories).join(", ")}`
    : "Nessuna categoria disponibile."

  const certSection = cert.validity || cert.issuer?.CN
    ? `
Certificato HTTPS:
- Valido fino:\t\t${formatValue(cert.validity?.not_after)}
- Emittente:\t\t${formatValue(cert.issuer?.CN)}
    `.trim()
    : "Nessun certificato HTTPS disponibile."

  const whoisSection = whois
    ? `\n\nInformazioni Whois:\n${extractKeyWhoisInfo(whois)}`
    : "\n\nInformazioni Whois:\nNessuna informazione disponibile."

  return `
Informazioni Dominio/IP (VirusTotal):
- IOC:\t\t\t${formatValue(d.id)}
Analisi Vendor:
- Malevoli:\t\t${formatValue(stats.malicious)}
- Sospetti:\t\t${formatValue(stats.suspicious)}
- Non rilevati:\t\t${formatValue(stats.undetected)}
- Sicuri:\t\t${formatValue(stats.harmless)}
${categories}
${certSection}
${whoisSection}
  `.trim()
}



const formatValue = (value: any, defaultValue: string = "N/A"): string => {
  if (value === 0 || value === false) return value.toString()
  return value || defaultValue
}




/**
* Funzione principale per formattare i dati combinati di AbuseIPDB e VirusTotal.
* @param data Dati combinati.
* @returns Stringa formattata.
*/
export const parseAndFormatResults = (data: any): string => {
  const abuse = data?.AbuseIPDB?.data;
  const vt = data?.VirusTotal?.data?.attributes;
  const whoisText = vt?.whois || "";

  const lines: string[] = [];

  // =======================
  // 🛡️ AbuseIPDB Section
  // =======================
  if (abuse) {
    lines.push("Informazioni AbuseIPDB:");
    lines.push(`- Punteggio di Abuso:\t${abuse.abuseConfidenceScore ?? "N/A"}`);
    lines.push(`- Totale Segnalazioni:\t${abuse.totalReports ?? "N/A"}`);
    lines.push(`- Paese:\t\t${abuse.countryCode ?? "N/A"}`);
    lines.push(`- ISP:\t\t\t${abuse.isp ?? "N/A"}`);
    lines.push(""); // blank line
  }

  // =======================
  // 🔍 VirusTotal Section
  // =======================
  if (vt) {
    const stats = vt.last_analysis_stats ?? {};
    lines.push("Informazioni VirusTotal:");
    lines.push(`- IOC:\t\t\t${data?.VirusTotal?.data?.id ?? "N/A"}`);
    lines.push(`- Malevoli:\t\t${stats.malicious ?? 0}`);
    lines.push(`- Sospetti:\t\t${stats.suspicious ?? 0}`);
    lines.push(`- Sicuri:\t\t${stats.harmless ?? 0}`);
    lines.push(`- Non rilevati:\t\t${stats.undetected ?? 0}`);
    lines.push(""); // blank line

    // WHOIS chiave: usa stesse funzioni dei CSV
    const creation = extractSingleFromWhois(whoisText, /Created:\s*(.+)/gi, "earliest") ??
                     extractSingleFromWhois(whoisText, /Creation Date:\s*(.+)/gi, "earliest") ??
                     extractSingleFromWhois(whoisText, /Registered On:\s*(.+)/gi, "earliest");

    const expiry = extractSingleFromWhois(whoisText, /Expiry Date:\s*(.+)/gi, "earliest") ??
                   extractSingleFromWhois(whoisText, /Expire Date:\s*(.+)/gi, "earliest") ??
                   extractSingleFromWhois(whoisText, /Expires On:\s*(.+)/gi, "earliest");

    const registrar = extractSingleFromWhois(whoisText, /Registrar(?: Name)?:\s*(.+)/gi, "first") ??
                      extractSingleFromWhois(whoisText, /Sponsoring Registrar:\s*(.+)/gi, "first");

    const org = extractBestOrganization(whoisText);

    lines.push("Informazioni Whois:");
    lines.push(`- Data di Creazione:\t${creation ?? "N/A"}`);
    lines.push(`- Data di Scadenza:\t${expiry ?? "N/A"}`);
    lines.push(`- Registrar:\t\t${registrar ?? "N/A"}`);
    lines.push(`- Organizzazione:\t${org ?? "N/A"}`);
  }

  return lines.join("\n").trim();
};



/**
* Estrae le informazioni chiave dal campo whois.
* @param whois Testo completo del whois.
* @returns Stringa formattata con le informazioni chiave.
*/
/**
* Estrae le informazioni chiave dal campo whois.
* @param whois Testo completo del whois.
* @returns Stringa formattata con le informazioni chiave.
*/
const extractKeyWhoisInfo = (whois: string): string => {
  if (!whois) return "Nessuna informazione disponibile.";

  const extractMultiple = (regex: RegExp): string[] => {
    const matches = [...whois.matchAll(regex)];
    return matches.map((m) => m[1].trim());
  };

  const dedup = (arr: string[]) =>
    Array.from(new Set(arr.map((s) => s.trim())));

  const lines: string[] = [];

  const creationDates = dedup(extractMultiple(/Created:\s*(.+)/gi));
  const expireDates = dedup(extractMultiple(/Expire Date:\s*(.+)/gi));
  const orgs = dedup(extractMultiple(/Organization:\s*(.+)/gi));
  const statuses = dedup(extractMultiple(/Status:\s*(.+)/gi));

  const section = [
    { label: "Data di Creazione", values: creationDates },
    { label: "Data di Scadenza", values: expireDates },
    { label: "Organizzazione", values: orgs },
    { label: "Stato", values: statuses }
  ];

  section.forEach(({ label, values }) => {
    if (values.length > 0) {
      lines.push(`${label}:`);
      values.forEach((v) => lines.push(`  - ${v}`));
    }
  });

  return lines.length > 0
    ? lines.join("\n")
    : "Nessuna informazione chiave trovata nel record Whois.";
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


export const convertResultsToCSV = (results: { [key: string]: any }): string => {
  const rows = [["IOC", "Servizio", "Tipo", "Valore"]];

  for (const [ioc, result] of Object.entries(results)) {
    for (const [service, data] of Object.entries(result)) {
      if (typeof data === "object" && data !== null && "error" in data) {
        rows.push([ioc, service, "Errore", (data as any).error]);
        continue;
      }

      if (
        service === "VirusTotal" &&
        typeof data === "object" &&
        data !== null &&
        "data" in data &&
        "attributes" in (data as any).data
      ) {
        const stats = (data as any).data.attributes.last_analysis_stats;
        if (stats) {
          rows.push([ioc, service, "Malicious", stats.malicious?.toString() ?? "0"]);
          rows.push([ioc, service, "Suspicious", stats.suspicious?.toString() ?? "0"]);
          rows.push([ioc, service, "Harmless", stats.harmless?.toString() ?? "0"]);
        }
      }

      if (
        service === "AbuseIPDB" &&
        typeof data === "object" &&
        data !== null &&
        "data" in data
      ) {
        const abuseScore = (data as any).data.abuseConfidenceScore;
        rows.push([ioc, service, "Abuse Score", abuseScore?.toString() ?? "N/A"]);
      }
    }
  }

  // Convert to CSV format (quoted cells)
  return rows.map((r) => r.map((c) => `"${c}"`).join(",")).join("\n");
};


export const exportResultsByEngine = (results: { [key: string]: any }) => {
  const vtRows = [
    [
      "IOC",
      "Malicious",
      "Suspicious",
      "Harmless",
      "Undetected",
      "WHOIS Creation Date",
      "WHOIS Expiry Date",
      "Registrar",
      "Organization"
    ]
  ];


  const abuseRows = [
    ["IOC", "Abuse Score", "Total Reports", "Country", "ISP"]
  ];

  for (const [ioc, result] of Object.entries(results)) {
    const vt = result?.VirusTotal?.data?.attributes;
    if (vt) {
      const stats = vt.last_analysis_stats || {};
      const whoisText = result?.VirusTotal?.data?.attributes?.whois || "";
      const creationDate =
        extractSingleFromWhois(whoisText, /Created:\s*(.+)/gi, "earliest") ??
        extractSingleFromWhois(whoisText, /Creation Date:\s*(.+)/gi, "earliest") ??
        extractSingleFromWhois(whoisText, /Registered On:\s*(.+)/gi, "earliest");


      const expiryDate =
        extractSingleFromWhois(whoisText, /Expiry Date:\s*(.+)/gi, "earliest") ??
        extractSingleFromWhois(whoisText, /Expire Date:\s*(.+)/gi, "earliest") ??
        extractSingleFromWhois(whoisText, /Expires On:\s*(.+)/gi, "earliest");


      const registrar =
        extractSingleFromWhois(whoisText, /Registrar(?: Name)?:\s*(.+)/gi, "first") ??
        extractSingleFromWhois(whoisText, /Sponsoring Registrar:\s*(.+)/gi, "first");


      const organization = extractBestOrganization(whoisText);





      vtRows.push([
        ioc,
        stats.malicious?.toString() ?? "0",
        stats.suspicious?.toString() ?? "0",
        stats.harmless?.toString() ?? "0",
        stats.undetected?.toString() ?? "0",
        creationDate ?? "N/A",
        expiryDate ?? "N/A",
        registrar ?? "N/A",
        organization ?? "N/A"
      ]);

    }

    const abuse = result?.AbuseIPDB?.data;
    if (abuse) {
      abuseRows.push([
        ioc,
        abuse.abuseConfidenceScore?.toString() ?? "0",
        abuse.totalReports?.toString() ?? "0",
        abuse.countryCode ?? "N/A",
        abuse.isp ?? "N/A"
      ]);
    }
  }

  if (vtRows.length > 1) downloadCSV(vtRows, "VirusTotal_IOC_Results");
  if (abuseRows.length > 1) downloadCSV(abuseRows, "AbuseIPDB_IOC_Results");
};

// Estrae un singolo campo da testo WHOIS
export const extractSingleFromWhois = (
  whois: string,
  regex: RegExp,
  strategy: "first" | "earliest" = "first"
): string | null => {
  const matches = [...whois.matchAll(regex)]
    .map((m) => (m[1] ? m[1].trim() : null))
    .filter((v): v is string => !!v);

  if (matches.length === 0) return null;

  if (strategy === "earliest") {
    const validDates = matches
      .map((d) => new Date(d))
      .filter((d) => !isNaN(d.getTime()))
      .sort((a, b) => a.getTime() - b.getTime());

    return validDates.length > 0 ? validDates[0].toISOString().split("T")[0] : null;
  }

  return matches[0];
};

export const extractBestOrganization = (whois: string): string => {
  const matches = [...whois.matchAll(/Organization:\s*(.+)/gi)]
    .map((m) => (m[1] ? m[1].trim() : null))
    .filter((v): v is string => !!v);

  const preferred = matches.find(
    (org) =>
      !/registrar|markmonitor|limited|llc/i.test(org) &&
      !org.toLowerCase().includes("privacy")
  );

  return preferred ?? matches[0] ?? "N/A";
};



const downloadCSV = (rows: string[][], filename: string) => {
  const csv = rows.map((r) => r.map((c) => `"${c}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const date = new Date().toISOString().split("T")[0];
  a.href = url;
  a.download = `${filename}_${date}.csv`;
  a.click();
  URL.revokeObjectURL(url);
};



export const exportResultsToExcel = (results: { [key: string]: any }) => {
  const vtSheetData: (string | number)[][] = [
    [
      "IOC",
      "Malicious",
      "Suspicious",
      "Harmless",
      "Undetected",
      "WHOIS Creation Date",
      "WHOIS Expiry Date",
      "Registrar",
      "Organization"
    ]
  ]

  const abuseSheetData: (string | number)[][] = [
    ["IOC", "Abuse Score", "Total Reports", "Country", "ISP"]
  ]

  const vtStyles: any[] = []
  const abuseStyles: any[] = []

  for (const [ioc, result] of Object.entries(results)) {
    // VirusTotal
    const vt = result?.VirusTotal?.data?.attributes
    const whoisText = vt?.whois || ""

    const stats = vt?.last_analysis_stats || {}
    const creationDate =
      extractSingleFromWhois(whoisText, /Created:\s*(.+)/gi, "earliest") ??
      extractSingleFromWhois(whoisText, /Creation Date:\s*(.+)/gi, "earliest")
    const expiryDate =
      extractSingleFromWhois(whoisText, /Expiry Date:\s*(.+)/gi, "earliest") ??
      extractSingleFromWhois(whoisText, /Expire Date:\s*(.+)/gi, "earliest")
    const registrar =
      extractSingleFromWhois(whoisText, /Registrar(?: Name)?:\s*(.+)/gi, "first")
    const organization = extractBestOrganization(whoisText)

    const vtRow = [
      ioc,
      stats.malicious ?? 0,
      stats.suspicious ?? 0,
      stats.harmless ?? 0,
      stats.undetected ?? 0,
      creationDate ?? "N/A",
      expiryDate ?? "N/A",
      registrar ?? "N/A",
      organization ?? "N/A"
    ]

    vtSheetData.push(vtRow)

    // AbuseIPDB
    const abuse = result?.AbuseIPDB?.data
    if (abuse) {
      abuseSheetData.push([
        ioc,
        abuse.abuseConfidenceScore ?? 0,
        abuse.totalReports ?? 0,
        abuse.countryCode ?? "N/A",
        abuse.isp ?? "N/A"
      ])
    }
  }

  const workbook = XLSX.utils.book_new()
  const vtSheet = XLSX.utils.aoa_to_sheet(vtSheetData)
  const abuseSheet = XLSX.utils.aoa_to_sheet(abuseSheetData)

  // Applica lo stile solo a campi di rischio (colori basati su valori)
  applyConditionalFormatting(vtSheet, vtSheetData, [1, 2]) // malicious/suspicious
  applyConditionalFormatting(abuseSheet, abuseSheetData, [1]) // abuse score

  XLSX.utils.book_append_sheet(workbook, vtSheet, "VirusTotal")
  XLSX.utils.book_append_sheet(workbook, abuseSheet, "AbuseIPDB")

  XLSX.writeFile(workbook, `SOCx_IOC_Report_${new Date().toISOString().split("T")[0]}.xlsx`)
}

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


export const fetchSpurData = async (ip: string): Promise<any> => {
  const apiKey = await chrome.storage.local.get(["spurApiKey"]);
  if (!apiKey.spurApiKey) {
    throw new Error("Chiave API di Spur non trovata.");
  }

  const response = await fetch(`https://api.spur.us/v2/context/${ip}`, {
    headers: {
      "Token": apiKey.spurApiKey
    }
  });

  if (!response.ok) {
    throw new Error(`Errore nella richiesta API Spur: ${response.statusText}`);
  }

  return response.json();
};


export const formatSpurData = (data: any): string => {
  if (!data) return "Nessuna informazione da Spur.";

  const infrastructure = data.infrastructure || "N/A";
  const risks = data.risks ? data.risks.join(", ") : "Nessuno";
  const proxies = data.client?.proxies ? data.client.proxies.join(", ") : "Nessuno";
  const services = data.services ? data.services.join(", ") : "Nessuno";

  return `
Informazioni Spur:
- Infrastruttura: ${infrastructure}
- Rischi: ${risks}
- Proxies: ${proxies}
- Servizi: ${services}
  `.trim();
};

