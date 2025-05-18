import React, { useState, useEffect } from "react"
import { createRoot } from "react-dom/client"
import PopupUI from "./PopupUI"
import "./popup.css"
import "../utility/config.css"
import "../utility/colors.css"
import { Storage } from "@plasmohq/storage"
import { showNotification } from "~src/utility/utils"

const storage = new Storage({ area: "local" })

const Popup = () => {
  const [iocHistory, setIocHistory] = useState<
    { type: string; text: string; timestamp: string }[]
  >([])
  const [windowId, setWindowId] = useState<number | null>(null)
  const [isDarkMode, setIsDarkMode] = useState(true)

useEffect(() => {
  const load = async () => {
    try {
      const history = await storage.get("iocHistory")

      if (Array.isArray(history)) {
        setIocHistory(history)
      } else if (typeof history === "string") {
        try {
          const parsed = JSON.parse(history)
          if (Array.isArray(parsed)) {
            setIocHistory(parsed)
          } else {
            await storage.remove("iocHistory") // ❌ Rimuovi se non è un array
            setIocHistory([])
          }
        } catch {
          await storage.remove("iocHistory") // ❌ Rimuovi se parse fallisce
          setIocHistory([])
        }
      } else {
        await storage.remove("iocHistory") // ❌ Rimuovi se non è un array o stringa
        setIocHistory([])
      }

      const theme = await storage.get<boolean>("isDarkMode")
      setIsDarkMode(theme ?? false)
    } catch (err) {
      console.error("Errore caricando i dati:", err)
      setIocHistory([])
    }
  }

  load()

  chrome.windows.getCurrent({ populate: false }, (window) => {
    if (window.id !== undefined) {
      setWindowId(window.id)
    }
  })
}, [])


  useEffect(() => {
    storage.set("isDarkMode", isDarkMode)
  }, [isDarkMode])

  useEffect(() => {
    document.body.className = isDarkMode ? "dark-mode" : "light-mode"
  }, [isDarkMode])

  const handleBulkCheckClick = () => {
    const url = chrome.runtime.getURL("/tabs/bulk-check.html")
    chrome.tabs.create({ url })
  }

  const handleOpenSidePanelClick = () => {
    if ("sidePanel" in chrome && chrome.sidePanel?.open && windowId !== null) {
      chrome.sidePanel.open({ windowId })
    } else {
      showNotification("Error", "You must open manually the side panel.")
    }
  }

  const handleClearHistory = () => {
    setIocHistory([])
    storage.set("iocHistory", [])
  }

  return (
    <PopupUI
      isDarkMode={isDarkMode}
      iocHistory={iocHistory}
      onBulkCheckClick={handleBulkCheckClick}
      onOpenSidePanelClick={handleOpenSidePanelClick}
      onClearHistory={handleClearHistory}
    />
  )
}

export default Popup

const root = document.getElementById("root")
if (root) {
  createRoot(root).render(<Popup />)
}
