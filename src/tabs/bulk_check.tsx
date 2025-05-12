import React, { useEffect, useState } from "react";
import BulkCheckUI from "./BulkCheckUI";
import { extractIOCs } from "../utility/utils";
import "./bulk_check.css";
import { exportResultsByEngine, exportResultsToExcel } from "../utility/utils"; 

const BulkCheck = () => {
  const [textareaValue, setTextareaValue] = useState<string>("");
  const [iocList, setIocList] = useState<string[]>([]);
  const [results, setResults] = useState<{ [key: string]: any }>({});
  const [selectedServices, setSelectedServices] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [message, setMessage] = useState<string>("");
  const [isDarkMode, setIsDarkMode] = useState<boolean>(true);

  // Load saved IOCs and dark mode preferences
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
  useEffect(() => {
    document.body.className = isDarkMode ? "dark-mode" : "light-mode";
  }, [isDarkMode]);

  // Automatically save bulkIOCList
  useEffect(() => {
    chrome.storage.local.set({ bulkIOCList: iocList });
  }, [iocList]);

  // Save dark mode preference
  useEffect(() => {
    chrome.storage.local.set({ isDarkMode });
  }, [isDarkMode]);

  // Apply background color to the body
  useEffect(() => {
    document.body.className = isDarkMode ? "dark-mode" : "light-mode";
  }, [isDarkMode]);

  // Text and IOC handling functions
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
      alert("Please enter at least one IOC.");
      return;
    }
    setIsLoading(true);
    setMessage("Bulk check in progress...");
    try {
      const response = await chrome.runtime.sendMessage({ action: "checkBulkIOCs", iocList, services: selectedServices });
      setResults(response.results);
      setMessage("Check completed!");
    } catch (error) {
      setMessage("Error during bulk check.");
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

  const handleExport = (format: "csv" | "xlsx") => {
    if (format === "csv") {
      exportResultsByEngine(results);
    } else if (format === "xlsx") {
      exportResultsToExcel(results);
    }
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
      onExport={handleExport}
    />
  );
};

export default BulkCheck;
