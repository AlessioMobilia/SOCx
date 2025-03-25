// src/utils.ts

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
    iconUrl: chrome.runtime.getURL("/public/icon.png"),
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
    console.error("Errore nel salvataggio dell'IOC:", error);
    return false;
  }
};



export const copyToClipboard = (text: string, tabId: number): void => {
  chrome.tabs.sendMessage(tabId, { action: "copyToClipboard", text }, (response) => {
    if (response?.success) {
      console.log("IOC copiato nella clipboard:", text);
      showNotification("Fatto", "IOC copiati nella clipboard");
    } else {
      console.error("Errore durante la copia nella clipboard:", response?.error);
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
  console.log(asnRegex.test(text));
  const matches = text.match(combinedRegex);
  console.log(matches);

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



/**
* Formatta i dati di AbuseIPDB in un testo leggibile.
* @param abuseData Dati di AbuseIPDB.
* @returns Stringa formattata.
*/
/**
* Formatta i dati di AbuseIPDB in un testo leggibile.
* @param abuseData Dati di AbuseIPDB.
* @returns Stringa formattata.
*/
export const formatAbuseIPDBData = (abuseData: any): string => {
if (!abuseData?.data) return "";

const {
  ipAddress,
  abuseConfidenceScore,
  totalReports,
  isp,
  countryCode,
  domain,
  lastReportedAt,
} = abuseData.data;

// Gestisci correttamente i valori falsy
const formatValue = (value: any, defaultValue: string = "N/A") => {
  if (value === 0 || value === false) return value.toString(); // Mostra "0" o "false" invece di "N/A"
  return value || defaultValue;
};

return `
Informazioni IP (AbuseIPDB):
- IP:\t\t\t${formatValue(ipAddress)}
- Punteggio di Abuso:\t${formatValue(abuseConfidenceScore)}%
- Segnalazioni Totali:\t${formatValue(totalReports)}
- ISP:\t\t\t${formatValue(isp)}
- Paese:\t\t${formatValue(countryCode)}
- Dominio:\t\t${formatValue(domain)}
- Ultima Segnalazione:\t${formatValue(lastReportedAt)}
`.trim();
};

/**
* Formatta i dati di VirusTotal in un testo leggibile.
* @param vtData Dati di VirusTotal.
* @returns Stringa formattata.
*/
/**
* Formatta i dati di VirusTotal in un testo leggibile.
* @param vtData Dati di VirusTotal.
* @returns Stringa formattata.
*/
/**
* Formatta i dati di VirusTotal in un testo leggibile.
* @param vtData Dati di VirusTotal.
* @returns Stringa formattata.
*/
/**
* Formatta i dati di VirusTotal in un testo leggibile.
* @param vtData Dati di VirusTotal.
* @returns Stringa formattata.
*/
export const formatVirusTotalData = (vtData: any): string => {
if (!vtData?.data) return "";

const {
  id,
  attributes: {
    last_analysis_stats,
    categories,
    whois,
    last_https_certificate,
  } = {},
} = vtData.data;

// Funzione per gestire valori 0 e false
const formatValue = (value: any, defaultValue: string = "N/A") => {
  if (value === 0 || value === false) return value; // Mostra 0 o false come valori validi
  return value || defaultValue; // Usa defaultValue solo se il valore è null/undefined
};

// Formatta le statistiche di analisi
const analysisStats = last_analysis_stats
  ? `
Analisi Vendor:
- Malevoli:\t\t${formatValue(last_analysis_stats.malicious)}
- Sospetti:\t\t${formatValue(last_analysis_stats.suspicious)}
- Non rilevati:\t\t${formatValue(last_analysis_stats.undetected)}
- Sicuri:\t\t${formatValue(last_analysis_stats.harmless)}
`.trim()
  : "Nessuna analisi disponibile.";

// Formatta le categorie
const formattedCategories = categories
  ? `Categorie:\t\t${Object.values(categories).join(", ")}`
  : "Nessuna categoria disponibile.";

// Formatta il certificato HTTPS
const certInfo = last_https_certificate
  ? `
Certificato HTTPS:
- Valido fino:\t\t${formatValue(last_https_certificate.validity?.not_after)}
- Emittente:\t\t${formatValue(last_https_certificate.issuer?.CN)}
`.trim()
  : "Nessun certificato HTTPS disponibile.";

// Formatta il whois con le informazioni chiave
const whoisInfo = whois
  ? `Informazioni Whois:\n${extractKeyWhoisInfo(whois)}`
  : "";

// Costruisci il risultato finale
const result = `
Informazioni Dominio/IP (VirusTotal):
- IOC:\t\t\t${formatValue(id)}
${analysisStats}
${formattedCategories}
${certInfo}
${whoisInfo}
`.trim();

return result;
};





/**
* Funzione principale per formattare i dati combinati di AbuseIPDB e VirusTotal.
* @param data Dati combinati.
* @returns Stringa formattata.
*/
export const parseAndFormatResults = (data: any): string => {
const abuseIPDBText = formatAbuseIPDBData(data?.AbuseIPDB);
const virusTotalText = formatVirusTotalData(data?.VirusTotal);

return `
${abuseIPDBText}

${virusTotalText}
`.trim();
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
if (!whois) return "";

const keyInfo: { [key: string]: string } = {};

// Funzione per gestire valori 0 e false
const formatValue = (value: any, defaultValue: string = "\t\t\tN/A") => {
  if (value === 0 || value === false) return value; // Mostra 0 o false come valori validi
  return value || defaultValue; // Usa defaultValue solo se il valore è null/undefined
};

// Estrai la data di creazione
const creationDateMatch = whois.match(/Creation Date:\s*(.+)/i);
if (creationDateMatch) {
  keyInfo["Data di Creazione"] = formatValue(creationDateMatch[1]);
}

// Estrai l'emittente (Registrar)
const registrarMatch = whois.match(/Registrar:\s*(.+)/i);
if (registrarMatch) {
  keyInfo["Registrar"] = "\t\t"+formatValue(registrarMatch[1]);
}

// Estrai lo stato del dominio
const domainStatusMatch = whois.match(/Domain Status:\s*(.+)/i);
if (domainStatusMatch) {
  keyInfo["Stato del Dominio"] = formatValue(domainStatusMatch[1]);
}

// Formatta le informazioni chiave
return Object.entries(keyInfo)
  .map(([key, value]) => `${key}:\t${value}`)
  .join("\n");
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