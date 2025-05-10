// src/options/index.tsx
import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import OptionsUI from "./OptionsUI";
import "./options.css";
import "../utility/config.css";
import "../utility/colors.css";
import { defaultServices } from "../utility/defaultServices";

const Options = () => {
  const [virusTotalApiKey, setVirusTotalApiKey] = useState("");
  const [abuseIPDBApiKey, setAbuseIPDBApiKey] = useState("");
  const [selectedServices, setSelectedServices] = useState<{ [key: string]: string[] }>(defaultServices);
  const [isDarkMode, setIsDarkMode] = useState(true);

  // Carica le impostazioni salvate all'avvio
  useEffect(() => {
    chrome.storage.local.get(["virusTotalApiKey", "abuseIPDBApiKey", "selectedServices", "isDarkMode"], (result) => {
      if (result.virusTotalApiKey) setVirusTotalApiKey(result.virusTotalApiKey);
      if (result.abuseIPDBApiKey) setAbuseIPDBApiKey(result.abuseIPDBApiKey);
      if (result.selectedServices) setSelectedServices(result.selectedServices);
      if (result.isDarkMode !== undefined) setIsDarkMode(result.isDarkMode);
    });
  }, []);

  // Salva automaticamente le impostazioni
  useEffect(() => {
    chrome.storage.local.set({ virusTotalApiKey, abuseIPDBApiKey, selectedServices, isDarkMode });
  }, [virusTotalApiKey, abuseIPDBApiKey, selectedServices, isDarkMode]);

  // Applica il colore di sfondo al body
  useEffect(() => {
    document.body.className = isDarkMode ? "dark-mode" : "light-mode";
  }, [isDarkMode]);

  // Gestisci il cambio dei servizi
  const handleServiceChange = (type: string, service: string) => {
    const updatedServices = { ...selectedServices };
    if (updatedServices[type].includes(service)) {
      updatedServices[type] = updatedServices[type].filter((s) => s !== service);
    } else {
      updatedServices[type].push(service);
    }
    setSelectedServices(updatedServices);
  };


  const handleTestKeys = async () => {
  const results: string[] = []

  const testFetch = async (
    label: string,
    url: string,
    headers: HeadersInit
  ) => {
    try {
      const res = await fetch(url, { headers })
      results.push(
        `✅ ${label}: ${res.ok ? "OK" : `Errore (${res.status})`}`
      )
    } catch (err) {
      results.push(`❌ ${label}: Errore di rete`)
    }
  }

  if (virusTotalApiKey) {
    await testFetch("VirusTotal", "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", {
      "x-apikey": virusTotalApiKey
    })
  } else {
    results.push("⚠️ VirusTotal: Chiave non inserita")
  }

  if (abuseIPDBApiKey) {
    await testFetch("AbuseIPDB", "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8", {
      Accept: "application/json",
      Key: abuseIPDBApiKey
    })
  } else {
    results.push("⚠️ AbuseIPDB: Chiave non inserita")
  }

  alert(results.join("\n"))
}


  return (
    <OptionsUI
      isDarkMode={isDarkMode}
      virusTotalApiKey={virusTotalApiKey}
      abuseIPDBApiKey={abuseIPDBApiKey}
      selectedServices={selectedServices}
      onDarkModeToggle={() => setIsDarkMode((prev) => !prev)}
      onServiceChange={handleServiceChange}
      onVirusTotalApiKeyChange={setVirusTotalApiKey}
      onAbuseIPDBApiKeyChange={setAbuseIPDBApiKey}
      onTestKeys={handleTestKeys}
    />
  );
};

export default Options;

// Monta il componente React
const root = document.getElementById("root");
if (root) {
  createRoot(root).render(<Options />);
}