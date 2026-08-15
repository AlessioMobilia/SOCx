import {
  SELECTION_BUTTONS_MESSAGE,
  SERVICE_PAGE_COPY_BUTTONS_MESSAGE
} from "../utility/buttonPreferences"
import { handleMenuClick } from "./menu-handler"
import { getContextMenuApi, setupContextMenus } from "./menus"

type ChromiumExtensionApi = typeof chrome & {
  sidePanel?: {
    setOptions?: (options: { enabled: boolean }) => Promise<void>
  }
}

const extensionApi = chrome as ChromiumExtensionApi
const contextMenuApi = getContextMenuApi()
const manifest = chrome.runtime.getManifest() as chrome.runtime.Manifest & {
  browser_specific_settings?: { gecko?: { id?: string } }
}
const isFirefox = Boolean(manifest.browser_specific_settings?.gecko)
let contextMenuSetup = Promise.resolve()
const buttonPreferenceMessages = new Set([
  SELECTION_BUTTONS_MESSAGE,
  SERVICE_PAGE_COPY_BUTTONS_MESSAGE
])

console.log("Background script loaded")

const scheduleContextMenuSetup = (reason: string): Promise<void> => {
  contextMenuSetup = contextMenuSetup
    .catch(() => undefined)
    .then(() => setupContextMenus(contextMenuApi))
    .catch((error) => {
      console.error(`Context menu setup failed (${reason}):`, error)
    })

  return contextMenuSetup
}

// Firefox uses a persistent MV2 background page, where menus should also be
// registered at top level. This repairs installs where onInstalled was missed.
if (isFirefox) {
  void scheduleContextMenuSetup("Firefox background startup")
}

// Eseguito al primo avvio o aggiornamento dell'estensione
chrome.runtime.onInstalled.addListener(async () => {
  try {
    if (!isFirefox && extensionApi.sidePanel?.setOptions) {
      await extensionApi.sidePanel.setOptions({ enabled: true })
    }

    await scheduleContextMenuSetup("extension install/update")
  } catch (e) {
    console.error("Error during onInstalled setup:", e)
  }
})

chrome.runtime.onStartup.addListener(() => {
  void scheduleContextMenuSetup("browser startup")
})

// Listener per click sui context menu
contextMenuApi.onClicked.addListener((info, tab) => {
  try {
    handleMenuClick(info, tab)
  } catch (e) {
    console.error("Error in handleMenuClick:", e)
  }
})

chrome.runtime.onMessage.addListener((message) => {
  if (!buttonPreferenceMessages.has(message?.type)) {
    return
  }
  const type = message.type
  const enabled = Boolean(message.enabled)
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach((tab) => {
      if (typeof tab.id !== "number") {
        return
      }
      chrome.tabs.sendMessage(
        tab.id,
        {
          type,
          enabled
        },
        () => {
          const err = chrome.runtime.lastError
          if (err && !/Receiving end/.test(err.message ?? "")) {
            console.debug("Button preference broadcast failed:", err.message)
          }
        }
      )
    })
  })
})
