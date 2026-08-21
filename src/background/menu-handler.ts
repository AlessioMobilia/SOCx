import { Storage } from "@plasmohq/storage"

import { servicesConfig } from "../utility/servicesConfig"
import {
  copyToClipboard,
  defang,
  extractIOCs,
  formatAndCopySelection,
  formatCVEs,
  identifyIOC,
  isPrivateIP,
  refang,
  saveIOC,
  showNotification,
  uniqueStrings
} from "../utility/utils"
import { runMagicIoc } from "./magic-ioc"
import { SOCX_QUERY_PALETTE_MENU } from "./menus"
import {
  parseQueryMenuId,
  QUERY_MENU_OPEN_ALL,
  QUERY_MENU_PREFIX
} from "./query-menus"
import { openQueryPaletteFromMenu } from "./query-palette-menu"
import { openQueryWorkspace } from "./query-workspace"

const storage = new Storage({ area: "local" })

export async function handleMenuClick(info: any, tab: any) {
  if (info.menuItemId === SOCX_QUERY_PALETTE_MENU) {
    const indicators = info.selectionText
      ? (extractIOCs(info.selectionText) ?? [])
      : []
    await openQueryPaletteFromMenu(tab?.id, indicators, undefined, {
      sendMessage: (tabId, message, callback) =>
        chrome.tabs.sendMessage(tabId, message, callback),
      getLastError: () => chrome.runtime.lastError,
      openWorkspace: openQueryWorkspace
    })
    return
  }

  // Pack-specific query entries also work without a selection, right inside a
  // console search bar.
  if (
    info.menuItemId === QUERY_MENU_OPEN_ALL ||
    String(info.menuItemId).startsWith(QUERY_MENU_PREFIX)
  ) {
    const templateKey = parseQueryMenuId(info.menuItemId)
    const indicators = info.selectionText
      ? (extractIOCs(info.selectionText) ?? [])
      : []

    await openQueryPaletteFromMenu(
      tab?.id,
      indicators,
      templateKey ?? undefined,
      {
        sendMessage: (tabId, message, callback) =>
          chrome.tabs.sendMessage(tabId, message, callback),
        getLastError: () => chrome.runtime.lastError,
        openWorkspace: (values) =>
          openQueryWorkspace(values, templateKey ?? undefined)
      }
    )
    return
  }

  const selection = info.selectionText?.trim()
  if (!selection) {
    showNotification("Error", "No text selected.")
    return
  }

  const iocList = extractIOCs(selection)
  const ioc = iocList?.[0]
  const type = identifyIOC(ioc)

  const copyOps: Record<string, () => void> = {
    refangIOC: () => copyToClipboard(iocList.map(refang).join("\n")),
    defangIOC: () => copyToClipboard(iocList.map(defang).join("\n")),
    copyCVE: () => copyToClipboard(formatCVEs(selection, false)),
    copyCVECSV: () => copyToClipboard(formatCVEs(selection, true)),
    extractText: () => formatAndCopySelection(tab.id, info.frameId)
  }

  console.log("Menu clicked:", info.menuItemId, selection, tab.id)
  if (info.menuItemId in copyOps) {
    console.log("Copying:", info.menuItemId)
    copyOps[info.menuItemId]()
    return
  }

  if (!ioc || !type) {
    showNotification("Error", "Invalid IOC.")
    return
  }

  if (type === "IP" && isPrivateIP(ioc)) {
    showNotification("Private", "Private IP, skipping analysis.")
    return
  }

  if (info.menuItemId === "CyberChef") {
    const base64 = btoa(unescape(encodeURIComponent(selection))).replaceAll(
      "=",
      ""
    )
    chrome.tabs.create({
      url: `https://gchq.github.io/CyberChef/#input=${base64}`
    })
    return
  }

  if (info.menuItemId === "AddToBulkCheck") {
    await storage.set("bulkIOCList", uniqueStrings(iocList ?? []))
    // Apri la pagina React (tabs/bulk-check.tsx)
    chrome.tabs.create({ url: chrome.runtime.getURL("tabs/bulk-check.html") })
    return
  }

  await saveIOC(type, ioc)

  if (info.menuItemId === "MagicIOC") {
    await runMagicIoc({
      ioc,
      type,
      tabId: tab?.id,
      tabIndex: tab?.index,
      windowId: tab?.windowId
    })
    return
  }

  const [menuType, service] = info.menuItemId.toString().split("_")
  const config = servicesConfig.services[service]

  if (config?.supportedTypes.includes(type)) {
    chrome.tabs.create({ url: config.url(type, ioc) })
  } else {
    showNotification("Error", "Invalid service or type.")
  }
}
