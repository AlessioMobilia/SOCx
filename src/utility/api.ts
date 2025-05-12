// src/utility/api.ts

export const checkVirusTotal = async (ioc: string, type: string): Promise<any> => {
  const supportedTypes = ["ip", "domain", "url", "hash"];
  if (!supportedTypes.includes(type.toLowerCase())) {
    throw new Error(`Unsupported IOC type for VirusTotal: ${type}`);
  }
  const apiKey = await chrome.storage.local.get(["virusTotalApiKey"]);
  if (!apiKey.virusTotalApiKey) {
    throw new Error("VirusTotal API key not found.");
  }
  let url: string;
  switch (type.toLowerCase()) {
    case "ip":
      url = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ioc)}`;
      break;
    case "domain":
      url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ioc)}`;
      break;
    case "url":
      url = `https://www.virustotal.com/api/v3/urls/${encodeURIComponent(ioc)}`;
      break;
    case "hash":
      url = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(ioc)}`;
      break;
    default:
      throw new Error(`Unsupported IOC type for VirusTotal: ${type}`);
  }
  return fetchAPIVT(url, apiKey.virusTotalApiKey);
};

// Function to make API requests to VirusTotal
export const fetchAPIVT = async (url: string, apiKey: string): Promise<any | null> => {
  const response = await fetch(url, {
    method: "GET",
    headers: {
      accept: "application/json",
      "x-apikey": apiKey,
    },
  });

  if (!response.ok) {
    // Specific 404 handling: hash not found on VirusTotal
    if (response.status === 404) {
      console.warn("Hash not found on VirusTotal.");
      return null;
    }

    // Other errors: throw an exception with details
    let errorDetails = "";
    try {
      const errorJson = await response.json();
      errorDetails = JSON.stringify(errorJson, null, 2);
    } catch (e) {
      errorDetails = await response.text();
    }

    throw new Error(
      `API Error (${response.status}): ${response.statusText}\nDetails:\n${errorDetails}`
    );
  }

  await incrementDailyCounter("VT");
  return response.json();
};

// Function to make API requests to AbuseIPDB
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
      throw new Error(`API Request Error: ${response.statusText}`);
    }

    // Increment the daily counter for AbuseIPDB
    await incrementDailyCounter("Abuse");

    return response.json();
  } catch (error) {
    console.error("Error during API request:", error);
    throw error;
  }
};

// Function to check an IP on AbuseIPDB
export const checkAbuseIPDB = async (ioc: string): Promise<any> => {
  // Get the API key from chrome.storage.local
  const apiKey = await chrome.storage.local.get(["abuseIPDBApiKey"]);

  // Check if the API key is found
  if (!apiKey.abuseIPDBApiKey) {
    throw new Error("AbuseIPDB API key not found.");
  }

  // Build the URL for the API request
  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${ioc}`;
  console.log("Request URL:", url);

  // Execute the API request using fetchAPI
  return fetchAPIAbuse(url, apiKey.abuseIPDBApiKey);
};

// Get the current date in YYYY-MM-DD format
const getTodayDate = (): string => {
  const today = new Date();
  return today.toISOString().split("T")[0];
};

// Function to increment the daily counter
const incrementDailyCounter = async (apiName: string) => {
  const today = getTodayDate();
  const key = `${apiName}_${today}`;

  const counters = await chrome.storage.local.get(key);
  const currentCount = counters[key] || 0;

  await chrome.storage.local.set({ [key]: currentCount + 1 });
};

// Function to get the daily counters
const getDailyCounters = async (): Promise<{ [key: string]: number }> => {
  const today = getTodayDate();
  const keys = [`VT_${today}`, `Abuse_${today}`];

  const counters = await chrome.storage.local.get(keys);
  return counters;
};
