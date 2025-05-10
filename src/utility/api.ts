// src/utility/api.ts

export const checkVirusTotal = async (ioc: string, type: string): Promise<any> => {
  const supportedTypes = ["ip", "dominio", "url", "hash"];
  if (!supportedTypes.includes(type.toLowerCase())) {
    throw new Error(`Tipo di IOC non supportato per VirusTotal: ${type}`);
  }
  const apiKey = await chrome.storage.local.get(["virusTotalApiKey"]);
  if (!apiKey.virusTotalApiKey) {
    throw new Error("API key di VirusTotal non trovata.");
  }
  let url: string;
  switch (type.toLowerCase()) {
    case "ip":
      url = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ioc)}`;
      break;
    case "dominio":
      url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ioc)}`;
      break;
    case "url":
      url = `https://www.virustotal.com/api/v3/urls/${encodeURIComponent(ioc)}`;
      break;
    case "hash":
      url = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(ioc)}`;
      break;
    default:
      throw new Error(`Tipo di IOC non supportato per VirusTotal: ${type}`);
  }
  return fetchAPIVT(url, apiKey.virusTotalApiKey);
};



// Funzione per eseguire richieste API a VirusTotal
export const fetchAPIVT = async (url: string, apiKey: string): Promise<any> => {
  const response = await fetch(url, {
    method: "GET",
    headers: {
      accept: "application/json",
      "x-apikey": apiKey,
    },
  });

  if (!response.ok) {
    // Prova a ottenere il body della risposta per dettagli
    let errorDetails = "";
    try {
      const errorJson = await response.json();
      errorDetails = JSON.stringify(errorJson, null, 2);
    } catch (e) {
      errorDetails = await response.text();
    }

    throw new Error(
      `Errore API (${response.status}): ${response.statusText}\nDettagli:\n${errorDetails}`
    );
  }

  await incrementDailyCounter("VT");
  return response.json();
};



// Funzione per eseguire richieste API a AbuseIPDB
export const fetchAPIAbuse = async (url: string, apiKey: string): Promise<any> => {
  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "Accept": "application/json",
        "Key": apiKey,
      },
    });

    if (!response.ok) {
      throw new Error(`Errore nella richiesta API: ${response.statusText}`);
    }

    // Incrementa il contatore giornaliero per AbuseIPDB
    await incrementDailyCounter("Abuse");

    return response.json();
  } catch (error) {
    console.error("Errore durante la richiesta API:", error);
    throw error;
  }
};



  // Funzione per verificare un IP su AbuseIPDB
export const checkAbuseIPDB = async (ioc: string): Promise<any> => {
  // Ottieni la chiave API da chrome.storage.local
  const apiKey = await chrome.storage.local.get(["abuseIPDBApiKey"]);
  
  // Verifica se la chiave API è stata trovata
  if (!apiKey.abuseIPDBApiKey) {
    throw new Error("Chiave API di AbuseIPDB non trovata.");
  }

  // Costruisci l'URL per la richiesta API
  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${ioc}`;
  console.log("URL della richiesta:", url);

  // Esegui la richiesta API utilizzando fetchAPI
  return fetchAPIAbuse(url, apiKey.abuseIPDBApiKey);
};






// Ottieni la data corrente in formato YYYY-MM-DD
const getTodayDate = (): string => {
  const today = new Date();
  return today.toISOString().split("T")[0];
};

// Funzione per incrementare il contatore giornaliero
const incrementDailyCounter = async (apiName: string) => {
  const today = getTodayDate();
  const key = `${apiName}_${today}`;

  const counters = await chrome.storage.local.get(key);
  const currentCount = counters[key] || 0;

  await chrome.storage.local.set({ [key]: currentCount + 1 });
};

// Funzione per ottenere i contatori giornalieri
const getDailyCounters = async (): Promise<{ [key: string]: number }> => {
  const today = getTodayDate();
  const keys = [`VT_${today}`, `Abuse_${today}`];

  const counters = await chrome.storage.local.get(keys);
  return counters;
};

  