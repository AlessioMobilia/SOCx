import {
  SELECTION_BUTTONS_MESSAGE,
  SERVICE_PAGE_COPY_BUTTONS_MESSAGE
} from "../utility/buttonPreferences"
import {
  DEFAULT_QUERY_MENU_ENABLED,
  OPEN_QUERY_PALETTE_MESSAGE,
  QUERY_MENU_ENABLED_KEY,
  resolveBooleanPreference
} from "../utility/query/paletteBridge"
import { refreshAllSources } from "../utility/query/registry"
import { commandPage, QUERY_COMMAND } from "../utility/shortcuts"
import { handleMenuClick } from "./menu-handler"
import { getContextMenuApi, setupContextMenus } from "./menus"
import { setupQueryMenus } from "./query-menus"
import { openQueryWorkspace } from "./query-workspace"

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

const queryMenusEnabled = async (): Promise<boolean> => {
  try {
    const stored = await chrome.storage.local.get(QUERY_MENU_ENABLED_KEY)
    return resolveBooleanPreference(
      stored?.[QUERY_MENU_ENABLED_KEY],
      DEFAULT_QUERY_MENU_ENABLED
    )
  } catch {
    return DEFAULT_QUERY_MENU_ENABLED
  }
}

const scheduleContextMenuSetup = (reason: string): Promise<void> => {
  contextMenuSetup = contextMenuSetup
    .catch(() => undefined)
    .then(() =>
      setupContextMenus(contextMenuApi, [
        async () => {
          if (await queryMenusEnabled()) {
            await setupQueryMenus(contextMenuApi)
          }
        }
      ])
    )
    .catch((error) => {
      console.error(`Context menu setup failed (${reason}):`, error)
    })

  return contextMenuSetup
}

/** Opens the palette in the active tab, falling back to the SOCx query page. */
const openPaletteInActiveTab = async (
  body: Record<string, unknown> = {}
): Promise<void> => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  if (typeof tab?.id !== "number") return

  chrome.tabs.sendMessage(
    tab.id,
    { name: OPEN_QUERY_PALETTE_MESSAGE, body },
    () => {
      if (chrome.runtime.lastError) {
        // Restricted page: the palette cannot be injected there, so the
        // standalone query page is opened instead of failing silently.
        void openQueryWorkspace()
      }
    }
  )
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

    // Populate the built-in catalogue before building its menu. Existing pins
    // are respected: an upstream change is reported, never silently adopted.
    await refreshAllSources()
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

// Keyboard shortcuts. Only the palette ships with a suggested combination; the
// others stay unbound until the analyst assigns one from the browser shortcuts
// page, which is also the only place a combination can be changed.
if (chrome.commands?.onCommand) {
  chrome.commands.onCommand.addListener((command) => {
    if (command === QUERY_COMMAND) {
      void openPaletteInActiveTab()
      return
    }
    const page = commandPage(command)
    if (page) {
      void chrome.tabs.create({ url: chrome.runtime.getURL(page) })
    }
  })
}

// The menu mirrors the enabled packs, so it is rebuilt whenever they change.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return
  const relevant = [
    "queryPackSources",
    "queryPackCache",
    "queryPackUserLibrary",
    QUERY_MENU_ENABLED_KEY
  ]
  if (relevant.some((key) => key in changes)) {
    void scheduleContextMenuSetup("query packs changed")
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
