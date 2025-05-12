import React, { useState, useEffect } from "react";
import { createRoot } from "react-dom/client";
import PopupUI from "./PopupUI";
import "./popup.css";
import "../utility/config.css"; // Import configuration
import "../utility/colors.css";

const Popup = () => {
  const [iocHistory, setIocHistory] = useState<
    { type: string; text: string; timestamp: string }[]
  >([]);
  const [windowId, setWindowId] = useState<number | null>(null);
  const [isDarkMode, setIsDarkMode] = useState(true);

  // Load IOC history and dark mode preference
  useEffect(() => {
    chrome.storage.local.get(["iocHistory"], (result) => {
      setIocHistory(result.iocHistory ?? []); // Use [] if iocHistory is null or undefined
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

  // Save dark mode preference
  useEffect(() => {
    chrome.storage.local.set({ isDarkMode });
  }, [isDarkMode]);

  // Apply background color to body
  useEffect(() => {
    document.body.className = isDarkMode ? "dark-mode" : "light-mode";
  }, [isDarkMode]);

  // Open bulk IOC check tab
  const handleBulkCheckClick = () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("/tabs/bulk_check.html") });
  };

  // Open the side panel
  const handleOpenSidePanelClick = () => {
    if (windowId !== null) {
      chrome.sidePanel.open({ windowId });
    } else {
      console.error("Unable to get current window ID.");
    }
  };

  // Clear IOC history
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

// Mount the React component
const root = document.getElementById("root");
if (root) {
  createRoot(root).render(<Popup />);
}
