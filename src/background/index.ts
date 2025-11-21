import { setupContextMenus } from "./menus"
import { handleMenuClick } from "./menu-handler"

console.log("Background script loaded")

// Eseguito al primo avvio o aggiornamento dell'estensione
chrome.runtime.onInstalled.addListener(async () => {
  try {
    // Se usi Side Panel API (non ancora pienamente supportata da Plasmo)
    if (chrome.sidePanel?.setOptions) {
      await chrome.sidePanel.setOptions({ enabled: true })
    }

    await setupContextMenus()
  } catch (e) {
    console.error("Error during onInstalled setup:", e)
  }
})

// Listener per click sui context menu
chrome.contextMenus.onClicked.addListener((info, tab) => {
  try {
    handleMenuClick(info, tab)
  } catch (e) {
    console.error("Error in handleMenuClick:", e)
  }
})

chrome.runtime.onMessage.addListener((message) => {
  if (message?.type !== "floating-buttons-preference-changed") {
    return
  }
  const enabled = Boolean(message.enabled)
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach((tab) => {
      if (typeof tab.id !== "number") {
        return
      }
      chrome.tabs.sendMessage(
        tab.id,
        {
          type: "floating-buttons-preference-changed",
          enabled
        },
        () => {
          const err = chrome.runtime.lastError
          if (err && !/Receiving end/.test(err.message ?? "")) {
            console.debug("Floating button preference broadcast failed:", err.message)
          }
        }
      )
    })
  })
})
