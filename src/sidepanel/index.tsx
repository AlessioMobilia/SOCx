// src/sidepanel/index.tsx
import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import SidePanelUI from "./SidePanelUI";
import { defang, refang, isAlreadyDefanged, extractIOCs } from "../utility/utils"; // Supponiamo che queste funzioni siano in un file utils.ts
import "./sidepanel.css";
import "../utility/config.css";
import "../utility/colors.css";

const SidePanel = () => {
  const [note, setNote] = useState("");
  const [isDarkMode, setIsDarkMode] = useState(true);

  // Carica il testo salvato e la preferenza della dark mode
  useEffect(() => {
    chrome.storage.local.get(["note"], (result) => {
      if (result.note) {
        setNote(result.note);
      }
    });
    chrome.storage.sync.get(["isDarkMode"], (result) => {
      if (result.isDarkMode !== undefined) {
        setIsDarkMode(result.isDarkMode);
      }
    });
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.action === "updateText") {
        const { oldText, newText } = message;
        chrome.storage.local.get(["note"], (result) => {
          if (result.note) {
            const newNote = result.note.replaceAll(oldText.trim().replace(/(\r\n|\n|\r)/gm, ""), newText);
            setNote(newNote);
            saveNote(newNote);
          }
        });
        sendResponse({ success: true });
      }
    });
  }, []);

  useEffect(() => {
    document.body.className = isDarkMode ? "dark-mode" : "light-mode";
  }, [isDarkMode]);

  // Applica il colore di sfondo al body
  useEffect(() => {
    document.body.className = isDarkMode ? "dark-mode" : "light-mode";
  }, [isDarkMode]);

  // Salva il testo nello storage
  const saveNote = (text: string) => {
    chrome.storage.local.set({ note: text });
  };

  // Salva come file TXT
  const saveAsTxt = () => {
    const blob = new Blob([note], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "blocco_note.txt";
    a.click();
    URL.revokeObjectURL(url);
  };

  // Elimina tutto il contenuto
  const clearNote = () => {
    setNote("");
    chrome.storage.local.set({ note: "" });
  };

  // Funzioni per Refang e Defang
  const handleRefang = () => {
    const iocs = extractIOCs(note, false);
    let updatedNote = note;
    iocs.forEach((ioc) => {
      const refanged = refang(ioc);
      updatedNote = updatedNote.replaceAll(ioc, refanged);
    });
    setNote(updatedNote);
    saveNote(updatedNote);
  };

  const handleDefang = () => {
    const iocs = extractIOCs(note, false);
    let updatedNote = note;
    iocs.forEach((ioc) => {
      if (!isAlreadyDefanged(ioc)) {
        const defanged = defang(ioc);
        updatedNote = updatedNote.replaceAll(ioc, defanged);
      }
    });
    setNote(updatedNote);
    saveNote(updatedNote);
  };

  return (
    <SidePanelUI
      note={note}
      isDarkMode={isDarkMode}
      onTextChange={(e) => {
        setNote(e.target.value);
        saveNote(e.target.value);
      }}
      onSaveTxt={saveAsTxt}
      onClearNote={clearNote}
      onRefang={handleRefang}
      onDefang={handleDefang}
    />
  );
};

export default SidePanel;

// Monta il componente React
const root = document.getElementById("root");
if (root) {
  createRoot(root).render(<SidePanel />);
}