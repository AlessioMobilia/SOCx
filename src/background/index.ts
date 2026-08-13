import { setupContextMenus } from "./menus"
import { handleMenuClick } from "./menu-handler"

type ChromiumExtensionApi = typeof chrome & {
  sidePanel?: {
    setOptions?: (options: { enabled: boolean }) => Promise<void>
  }
}

const extensionApi = chrome as ChromiumExtensionApi

console.log("Background script loaded")

// Eseguito al primo avvio o aggiornamento dell'estensione
chrome.runtime.onInstalled.addListener(async () => {
  try {
    const isFirefox = ["firefox", "gecko"].includes(
      process.env.PLASMO_BROWSER ?? ""
    )
    if (!isFirefox && extensionApi.sidePanel?.setOptions) {
      await extensionApi.sidePanel.setOptions({ enabled: true })
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
