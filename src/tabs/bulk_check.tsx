import React, { useEffect, useState } from "react";
import BulkCheckUI from "./BulkCheckUI";
import { extractIOCs } from "../utility/utils";
import "./bulk_check.css";

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
    chrome.storage.sync.get(["isDarkMode"], (result) => {
      if (result.isDarkMode !== undefined) {
        setIsDarkMode(result.isDarkMode);
      }
    });
  }, []);
  useEffect(() => {
    document.body.className = isDarkMode ? "dark-mode" : "light-mode";
  }, [isDarkMode]);

  // Salva automaticamente bulkIOCList
  useEffect(() => {
    chrome.storage.local.set({ bulkIOCList: iocList });
  }, [iocList]);

  // Salva la preferenza della dark mode
  useEffect(() => {
    chrome.storage.sync.set({ isDarkMode });
  }, [isDarkMode]);

  // Applica il colore di sfondo al body
  useEffect(() => {
    document.body.className = isDarkMode ? "dark-mode" : "light-mode";
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
      console.log(iocList)
      const response = await chrome.runtime.sendMessage({ action: "checkBulkIOCs", iocList, services: selectedServices });
      setResults(response.results);
      setMessage("Controllo completato!");
    } catch (error) {
      console.error("Errore durante il controllo bulk:", error);
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

  const handleServiceToggle = (service: string, checked: boolean) => {
    if (checked) {
      setSelectedServices([...selectedServices, service]);
    } else {
      setSelectedServices(selectedServices.filter((s) => s !== service));
    }
  };

  const toggleDarkMode = () => {
    setIsDarkMode((prev) => !prev);
  };

  return (
    <BulkCheckUI
      textareaValue={textareaValue}
      onTextAreaChange={handleTextAreaChange}
      onFileUpload={handleFileUpload}
      selectedServices={selectedServices}
      onServiceToggle={handleServiceToggle}
      onCheckBulk={handleCheckBulk}
      onClearList={handleClearList} 
      isLoading={isLoading}
      message={message}
      results={results}
      isDarkMode={isDarkMode}
    />
  );
};








export default BulkCheck;