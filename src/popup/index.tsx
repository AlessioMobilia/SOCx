import React, { useState, useEffect } from "react";
import { createRoot } from "react-dom/client";
import PopupUI from "./PopupUI";
import "./popup.css";
import "../utility/config.css"; // Importa la configurazione
import "../utility/colors.css";

const Popup = () => {
  const [iocHistory, setIocHistory] = useState<
    { type: string; text: string; timestamp: string }[]
  >([]);
  const [windowId, setWindowId] = useState<number | null>(null);
  const [isDarkMode, setIsDarkMode] = useState(true);

  // Carica lo storico degli IOC e la preferenza della dark mode
  useEffect(() => {
    chrome.storage.local.get(["iocHistory"], (result) => {
      setIocHistory(result.iocHistory ?? []); // Usa [] se iocHistory è null o undefined
    });
    chrome.storage.local.get(["isDarkMode"], (result) => {
        setIsDarkMode(result.isDarkMode ?? false);
    });
    chrome.windows.getCurrent({ populate: false }, (window) => {
      if (window.id !== undefined) {
        setWindowId(window.id);
      }
    });
  }, []);

  // Salva la preferenza della dark mode
  useEffect(() => {
    chrome.storage.local.set({ isDarkMode });
  }, [isDarkMode]);

  // Applica il colore di sfondo al body
  useEffect(() => {
    document.body.className = isDarkMode ? "dark-mode" : "light-mode";
  }, [isDarkMode]);

  // Apri il controllo bulk IOC
  const handleBulkCheckClick = () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("/tabs/bulk_check.html") });
  };

  // Apri il side panel
  const handleOpenSidePanelClick = () => {
    if (windowId !== null) {
      chrome.sidePanel.open({ windowId });
    } else {
      console.error("Impossibile ottenere l'ID della finestra corrente.");
    }
  };

  // Cancella la cronologia degli IOC
  const handleClearHistory = () => {
    setIocHistory([]);
    chrome.storage.local.set({ iocHistory: [] });
  };

  return (
    <PopupUI
      isDarkMode={isDarkMode}
      iocHistory={iocHistory}
      onBulkCheckClick={handleBulkCheckClick}
      onOpenSidePanelClick={handleOpenSidePanelClick}
      onClearHistory={handleClearHistory}
    />
  );
};

export default Popup;

// Monta il componente React
const root = document.getElementById("root");
if (root) {
  createRoot(root).render(<Popup />);
}