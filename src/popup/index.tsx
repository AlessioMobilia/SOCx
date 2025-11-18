import React, { useState, useEffect } from "react"
import { createRoot } from "react-dom/client"
import PopupUI from "./PopupUI"
import "../styles/tailwind.css"
import { Storage } from "@plasmohq/storage"
import { showNotification } from "~src/utility/utils"
import { ensureIsDarkMode, persistIsDarkMode } from "../utility/theme"

const storage = new Storage({ area: "local" })

const Popup = () => {
  const [iocHistory, setIocHistory] = useState<
    { type: string; text: string; timestamp: string }[]
  >([])
  const [windowId, setWindowId] = useState<number | null>(null)
  const [isDarkMode, setIsDarkMode] = useState(true)
  const [themeLoaded, setThemeLoaded] = useState(false)

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
              await storage.remove("iocHistory")
              setIocHistory([])
            }
          } catch {
            await storage.remove("iocHistory")
            setIocHistory([])
          }
        } else {
          await storage.remove("iocHistory")
          setIocHistory([])
        }

        const theme = await ensureIsDarkMode()
        setIsDarkMode(theme)
      } catch (err) {
        console.error("Errore caricando i dati:", err)
        setIocHistory([])
      } finally {
        setThemeLoaded(true)
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
    if (!themeLoaded) return
    persistIsDarkMode(isDarkMode)
  }, [isDarkMode, themeLoaded])

  useEffect(() => {
    document.body.className = isDarkMode ? "dark-mode" : "light-mode"
  }, [isDarkMode])

  const handleBulkCheckClick = () => {
    const url = chrome.runtime.getURL("/tabs/bulk-check.html")
    chrome.tabs.create({ url })
  }

  const handleSubnetExtractorClick = () => {
    const url = chrome.runtime.getURL("/tabs/subnet-extractor.html")
    chrome.tabs.create({ url })
  }

  const handleSubnetCheckClick = () => {
    const url = chrome.runtime.getURL("/tabs/subnet-check.html")
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

  const handleOpenOptionsClick = () => {
    if (chrome.runtime?.openOptionsPage) {
      chrome.runtime.openOptionsPage()
    } else {
      const url = chrome.runtime.getURL("options.html")
      window.open(url, "_blank")
    }
  }

  return (
    <PopupUI
      isDarkMode={isDarkMode}
      iocHistory={iocHistory}
      onBulkCheckClick={handleBulkCheckClick}
      onSubnetExtractorClick={handleSubnetExtractorClick}
      onSubnetCheckClick={handleSubnetCheckClick}
  onOpenSidePanelClick={handleOpenSidePanelClick}
  onClearHistory={handleClearHistory}
  onToggleTheme={() => setIsDarkMode((prev) => !prev)}
  onOpenOptionsClick={handleOpenOptionsClick}
    />
  )
}

export default Popup

const root = document.getElementById("root")
if (root) {
  createRoot(root).render(<Popup />)
}
