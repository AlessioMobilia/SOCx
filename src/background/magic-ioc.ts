import { Storage } from "@plasmohq/storage"

import { requestTabConfirmation } from "../utility/confirmBridge"
import { defaultServices } from "../utility/defaultServices"
import { isTabGroupingEnabled, openIocTabs } from "../utility/iocTabs"
import type { CustomService } from "../utility/iocTypes"
import { servicesConfig } from "../utility/servicesConfig"
import { showNotification } from "../utility/utils"

const storage = new Storage({ area: "local" })

// Above this many tabs the lookup asks for a confirmation, so a misconfigured
// service list cannot flood the window by accident.
export const MAGIC_IOC_CONFIRM_THRESHOLD = 5

export type MagicIocContext = {
  ioc: string
  type: string
  tabId?: number
  tabIndex?: number
  windowId?: number
}

export const buildMagicIocUrls = (
  type: string,
  ioc: string,
  selected: Record<string, string[]>,
  customServices: CustomService[]
): string[] => {
  const urls: string[] = []

  for (const service of selected[type] ?? []) {
    const config = servicesConfig.services[service]
    if (!config?.supportedTypes.includes(type)) {
      continue
    }
    const url = config.url(type, ioc)
    if (url) {
      urls.push(url)
    }
  }

  for (const service of customServices) {
    if (service?.type === type && service.url?.includes("{ioc}")) {
      urls.push(service.url.replaceAll("{ioc}", encodeURIComponent(ioc)))
    }
  }

  // The same provider can be reachable from both lists; open it once.
  return Array.from(new Set(urls))
}

const readMagicIocServices = async (
  type: string,
  ioc: string
): Promise<string[]> => {
  const storedSelected =
    await storage.get<Record<string, string[]>>("selectedServices")
  const selected = { ...defaultServices, ...(storedSelected ?? {}) }
  const rawCustom = await storage.get("customServices")
  const customServices: CustomService[] = Array.isArray(rawCustom)
    ? (rawCustom as CustomService[])
    : []

  return buildMagicIocUrls(type, ioc, selected, customServices)
}

export const runMagicIoc = async ({
  ioc,
  type,
  tabId,
  tabIndex,
  windowId
}: MagicIocContext): Promise<{ opened: number; cancelled: boolean }> => {
  const urls = await readMagicIocServices(type, ioc)

  if (urls.length === 0) {
    showNotification("Error", "No service selected.")
    return { opened: 0, cancelled: false }
  }

  if (urls.length > MAGIC_IOC_CONFIRM_THRESHOLD) {
    const confirmed = await requestTabConfirmation(tabId, {
      title: "Open every configured lookup?",
      message: `${ioc} is configured with ${urls.length} services. They open as background tabs grouped under this indicator.`,
      confirmLabel: `Open ${urls.length} tabs`
    })

    if (confirmed !== true) {
      showNotification(
        "Cancelled",
        confirmed === false
          ? "Magic IOC lookup cancelled."
          : "Unable to show the safety confirmation; no tabs were opened."
      )
      return { opened: 0, cancelled: true }
    }
  }

  const grouping = await isTabGroupingEnabled()
  const { tabIds, grouped } = await openIocTabs({
    ioc,
    urls,
    openerTabId: tabId,
    openerIndex: tabIndex,
    windowId,
    grouping
  })

  if (tabIds.length === 0) {
    showNotification("Error", "Unable to open the lookup tabs.")
  } else if (!grouped && tabIds.length > 1) {
    // Grouping is off, or unavailable as on Firefox: the analyst is told where
    // the tabs landed since nothing labels them in the tab strip.
    showNotification(
      "Magic IOC",
      `${tabIds.length} background tabs opened for ${ioc}.`
    )
  }

  return { opened: tabIds.length, cancelled: false }
}
