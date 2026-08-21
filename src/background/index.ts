import {
  SELECTION_BUTTONS_MESSAGE,
  SERVICE_PAGE_COPY_BUTTONS_MESSAGE
} from "../utility/buttonPreferences"
import { resolveActiveTab } from "../utility/extensionCallbacks"
import {
  DEFAULT_QUERY_MENU_ENABLED,
  OPEN_QUERY_PALETTE_MESSAGE,
  QUERY_MENU_ENABLED_KEY,
  resolveBooleanPreference
} from "../utility/query/paletteBridge"
import { refreshAllSources } from "../utility/query/registry"
import {
  commandPage,
  firefoxDefaultShortcutUpdates,
  QUERY_COMMAND,
  SMART_FORMAT_COMMAND
} from "../utility/shortcuts"
import { handleMenuClick } from "./menu-handler"
import { getContextMenuApi, setupContextMenus } from "./menus"
import { setupQueryMenus } from "./query-menus"
import { openQueryWorkspace } from "./query-workspace"

type ChromiumExtensionApi = typeof chrome & {
  sidePanel?: {
    setOptions?: (options: { enabled: boolean }) => Promise<void>
  }
}

type FirefoxCommandsApi = {
  getAll: () => Promise<chrome.commands.Command[]>
  update: (details: { name: string; shortcut: string }) => Promise<void>
}

const extensionApi = chrome as ChromiumExtensionApi
const firefoxCommands = (
  globalThis as typeof globalThis & {
    browser?: { commands?: FirefoxCommandsApi }
  }
).browser?.commands
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

const migrateFirefoxDefaultShortcuts = async (): Promise<void> => {
  if (!firefoxCommands) return
  const commands = await firefoxCommands.getAll()
  for (const update of firefoxDefaultShortcutUpdates(commands)) {
    try {
      await firefoxCommands.update(update)
    } catch (error) {
      console.warn(`Unable to migrate shortcut ${update.name}:`, error)
    }
  }
}

/** Opens the palette in the active tab, falling back to the SOCx query page. */
const openPaletteInActiveTab = async (
  body: Record<string, unknown> = {},
  commandTab?: chrome.tabs.Tab
): Promise<void> => {
  const tab = await resolveActiveTab(
    commandTab,
    (callback) =>
      chrome.tabs.query({ active: true, currentWindow: true }, callback),
    () => chrome.runtime.lastError
  )
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

const formatSelectionInActiveTab = async (
  commandTab?: chrome.tabs.Tab
): Promise<void> => {
  const tab = await resolveActiveTab(
    commandTab,
    (callback) =>
      chrome.tabs.query({ active: true, currentWindow: true }, callback),
    () => chrome.runtime.lastError
  )
  if (typeof tab?.id !== "number") return

  chrome.tabs.sendMessage(
    tab.id,
    { name: "format-selection", silentWhenEmpty: true },
    () => {
      // Restricted browser pages do not host the content script. The command
      // remains a no-op there instead of opening an unrelated extension page.
      void chrome.runtime.lastError
    }
  )
}

// Firefox uses a persistent MV2 background page, where menus should also be
// registered at top level. This repairs installs where onInstalled was missed.
if (isFirefox) {
  void scheduleContextMenuSetup("Firefox background startup")
}

// Eseguito al primo avvio o aggiornamento dell'estensione
chrome.runtime.onInstalled.addListener(async (details) => {
  try {
    if (!isFirefox && extensionApi.sidePanel?.setOptions) {
      await extensionApi.sidePanel.setOptions({ enabled: true })
    }

    // Populate the built-in catalogue before building its menu. Existing pins
    // are respected: an upstream change is reported, never silently adopted.
    await refreshAllSources()
    await scheduleContextMenuSetup("extension install/update")

    // Firefox retains the effective shortcuts across extension updates. Only
    // replace combinations shipped as SOCx defaults through 1.4.1; custom and
    // disabled commands remain untouched.
    if (
      isFirefox &&
      details.reason === "update" &&
      details.previousVersion &&
      /^1\.(?:[0-3](?:\.|$)|4\.[01](?:\.|$))/.test(details.previousVersion)
    ) {
      await migrateFirefoxDefaultShortcuts()
    }
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

// Keyboard shortcuts are changed from the browser shortcuts page linked in
// Options. In-page commands act on the active tab; workspace commands open a
// dedicated extension page.
if (chrome.commands?.onCommand) {
  chrome.commands.onCommand.addListener((command, tab) => {
    if (command === QUERY_COMMAND) {
      void openPaletteInActiveTab({}, tab)
      return
    }
    if (command === SMART_FORMAT_COMMAND) {
      void formatSelectionInActiveTab(tab)
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
