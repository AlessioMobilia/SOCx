import React, { useEffect, useState } from "react";

const BulkCheck = () => {
  const [textareaValue, setTextareaValue] = useState<string>("");
  const [iocList, setIocList] = useState<string[]>([]);
  const [results, setResults] = useState<{ [key: string]: any }>({});
  const [selectedServices, setSelectedServices] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [message, setMessage] = useState<string>("");
  const [isDarkMode, setIsDarkMode] = useState<boolean>(true);

  // Carica gli IOC salvati e le preferenze della dark mode
  useEffect(() => {
    chrome.storage.local.get(["bulkIOCList"], (result) => {
      if (result.bulkIOCList) {
        const loadedIOCs = Array.isArray(result.bulkIOCList)
          ? result.bulkIOCList.flat()
          : result.bulkIOCList.split(/[\n,]/).map((ioc: string) => ioc.trim()).filter(Boolean);
        setIocList(loadedIOCs);
        setTextareaValue(loadedIOCs.join("\n"));
      }
    });

    chrome.storage.local.get(["isDarkMode"], (result) => {
      if (result.isDarkMode !== undefined) {
        setIsDarkMode(result.isDarkMode);
      }
    });
  }, []);

  // Salva automaticamente bulkIOCList
  useEffect(() => {
    chrome.storage.local.set({ bulkIOCList: iocList });
  }, [iocList]);

  // Salva la preferenza della dark mode
  useEffect(() => {
    chrome.storage.local.set({ isDarkMode });
  }, [isDarkMode]);

  // Applica il colore di sfondo al body
  useEffect(() => {
    document.body.style.backgroundColor = isDarkMode ? "#1e1e1e" : "#ffffff";
  }, [isDarkMode]);

  // Funzioni di gestione del testo e degli IOC
  const updateIOCsFromText = (text: string) => {
    const iocs = extractIOCs(text);
    setIocList(iocs);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const text = event.target?.result as string;
        setTextareaValue(text);
        updateIOCsFromText(text);
      };
      reader.readAsText(file);
    }
  };

  const handleCheckBulk = async () => {
    if (iocList.length === 0) {
      alert("Inserisci almeno un IOC.");
      return;
    }
    setIsLoading(true);
    setMessage("Controllo bulk in corso...");
    try {
      const response = await chrome.runtime.sendMessage({ action: "checkBulkIOCs", iocList, services: selectedServices });
      setResults(response.results);
      setMessage("Controllo completato!");
    } catch (error) {
      setMessage("Errore durante il controllo bulk.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearList = () => {
    setTextareaValue("");
    setIocList([]);
    chrome.storage.local.set({ bulkIOCList: [] });
  };

  const handleTextAreaChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const value = e.target.value;
    setTextareaValue(value);
    updateIOCsFromText(value);
  };

  // Stili dinamici per il dark mode
  const styles: React.CSSProperties = {
    backgroundColor: isDarkMode ? "#1e1e1e" : "#ffffff",
    color: isDarkMode ? "#e0e0e0" : "#000000",
    padding: "16px",
    fontFamily: "Arial, sans-serif",
  };

  const textAreaStyles: React.CSSProperties = {
    width: "100%",
    height: "100px",
    padding: "8px",
    fontSize: "14px",
    border: isDarkMode ? "1px solid #555" : "1px solid #ccc",
    borderRadius: "4px",
    resize: "none",
    backgroundColor: isDarkMode ? "#2d2d2d" : "#ffffff",
    color: isDarkMode ? "#e0e0e0" : "#000000",
  };

  const buttonStyles: React.CSSProperties = {
    width: "100%",
    padding: "8px",
    marginTop: "16px",
    backgroundColor: isDarkMode ? "#333" : "#007bff",
    color: "#fff",
    border: "none",
    borderRadius: "4px",
    cursor: "pointer",
  };

  const clearButtonStyles: React.CSSProperties = {
    ...buttonStyles,
    backgroundColor: isDarkMode ? "#5a0000" : "#ffcccc", // Colore rosso per il pulsante di eliminazione
    color: isDarkMode ? "#fff" : "#000",
  };

  const toggleDarkModeStyles: React.CSSProperties = {
    position: "fixed",
    bottom: "16px",
    right: "16px",
    padding: "8px",
    backgroundColor: isDarkMode ? "#555" : "#007bff",
    color: "#fff",
    border: "none",
    borderRadius: "4px",
    cursor: "pointer",
  };

  const toggleDarkMode = () => {
    setIsDarkMode((prev) => !prev);
  };

  return (
    <div style={styles}>
      <h1>Controllo Bulk IOC</h1>
      <textarea
        style={textAreaStyles}
        placeholder="Incolla gli IOC qui (separati da righe o virgole)..."
        value={textareaValue}
        onChange={handleTextAreaChange}
      />
      <input
        type="file"
        accept=".txt"
        onChange={handleFileUpload}
        style={{ marginTop: "16px" }}
      />
      <div style={{ marginTop: "16px" }}>
        <label>
          <input
            type="checkbox"
            checked={selectedServices.includes("VirusTotal")}
            onChange={(e) => {
              if (e.target.checked) {
                setSelectedServices([...selectedServices, "VirusTotal"]);
              } else {
                setSelectedServices(selectedServices.filter((s) => s !== "VirusTotal"));
              }
            }}
          />
          VirusTotal
        </label>
        <label style={{ marginLeft: "16px" }}>
          <input
            type="checkbox"
            checked={selectedServices.includes("AbuseIPDB")}
            onChange={(e) => {
              if (e.target.checked) {
                setSelectedServices([...selectedServices, "AbuseIPDB"]);
              } else {
                setSelectedServices(selectedServices.filter((s) => s !== "AbuseIPDB"));
              }
            }}
          />
          AbuseIPDB
        </label>
      </div>
      <button
        onClick={handleCheckBulk}
        disabled={isLoading}
        style={{
          ...buttonStyles,
          backgroundColor: isLoading ? "#cccccc" : isDarkMode ? "#333" : "#007bff",
          cursor: isLoading ? "not-allowed" : "pointer",
        }}
      >
        {isLoading ? "Controllo in corso..." : "Avvia Controllo"}
      </button>
      <button
        onClick={handleClearList}
        style={clearButtonStyles}
      >
        Cancella Lista
      </button>
      {message && <p style={{ marginTop: "16px", color: isLoading ? "#000" : "#007bff" }}>{message}</p>}
      <h2>Risultati</h2>
      {results && Object.entries(results).map(([ioc, result]) => (
        <div
          key={ioc}
          style={{
            marginTop: "16px",
            padding: "8px",
            border: "1px solid #ccc",
            borderRadius: "4px",
            backgroundColor: isDarkMode ? "#2d2d2d" : "#f9f9f9",
            color: isDarkMode ? "#e0e0e0" : "#000000",
          }}
        >
          <h3>{ioc}</h3>
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </div>
      ))}
      <button
        onClick={toggleDarkMode}
        style={toggleDarkModeStyles}
      >
        {isDarkMode ? "Light Mode" : "Dark Mode"}
      </button>
    </div>
  );
};

// Funzioni di utilità
const extractIOCs = (text: string): string[] => {
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
  const combinedRegex = new RegExp(
    `(${ipAddressRegex.source}|${domainRegex.source}|${urlRegex.source}|${md5Regex.source}|${sha1Regex.source}|${sha256Regex.source}|${emailRegex.source}|${defangedUrlRegex.source}|${defangedDomainRegex.source}|${defangedIpRegex.source})`,
    'g'
  );
  const matches = text.match(combinedRegex);
  if (!matches) return [];
  const refang = (ioc: string): string => {
    ioc = ioc.replace(/^hxxps:\/\//i, "https://").replace(/^hxxp:\/\//i, "http://");
    ioc = ioc.replace(/\[\.\]/g, ".");
    return ioc;
  };
  return matches
    .map((ioc) => refang(ioc).trim())
    .filter(Boolean);
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "copyToClipboard") {
    navigator.clipboard.writeText(message.text)
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ error: err.message }));
  }
  return true; // Mantieni il canale aperto per la risposta asincrona
});

export default BulkCheck;