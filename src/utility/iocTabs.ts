// Cross-browser helpers used to open the lookup tabs of a single indicator.
//
// Chromium based browsers (Chrome, Edge) expose `chrome.tabs.group` and the
// `chrome.tabGroups` namespace, so the tabs of one investigation are collected
// in a single labelled group that can be collapsed or closed at once. Firefox
// has no equivalent API: there the tabs are simply opened next to the tab that
// triggered the lookup, and grouping is skipped without failing.

import { Storage } from "@plasmohq/storage"

export const TAB_GROUPING_KEY = "magicIocTabGroupingEnabled"
export const DEFAULT_TAB_GROUPING_ENABLED = true

const storage = new Storage({ area: "local" })

export const resolveTabGroupingPreference = (value: unknown): boolean =>
  typeof value === "boolean" ? value : DEFAULT_TAB_GROUPING_ENABLED

export const isTabGroupingEnabled = async (): Promise<boolean> => {
  try {
    return resolveTabGroupingPreference(
      await storage.get<boolean>(TAB_GROUPING_KEY)
    )
  } catch {
    return DEFAULT_TAB_GROUPING_ENABLED
  }
}

export type OpenedIocTabs = {
  tabIds: number[]
  grouped: boolean
}

type CreateProperties = {
  url: string
  active?: boolean
  index?: number
  windowId?: number
  openerTabId?: number
}

type ChromiumTabsApi = typeof chrome.tabs & {
  group?: (options: {
    tabIds: number | number[]
    groupId?: number
    createProperties?: { windowId?: number }
  }) => Promise<number>
}

type TabGroupsApi = {
  update?: (
    groupId: number,
    properties: { title?: string; color?: string; collapsed?: boolean }
  ) => Promise<unknown>
}

export const TAB_GROUP_COLORS = [
  "blue",
  "cyan",
  "green",
  "orange",
  "pink",
  "purple",
  "red",
  "yellow"
] as const

// A stable colour per indicator keeps repeated lookups visually consistent.
export const pickTabGroupColor = (seed: string): string => {
  let hash = 0
  for (let index = 0; index < seed.length; index += 1) {
    hash = (hash * 31 + seed.charCodeAt(index)) >>> 0
  }
  return TAB_GROUP_COLORS[hash % TAB_GROUP_COLORS.length]
}

export const buildTabGroupTitle = (ioc: string, maxLength = 28): string => {
  const normalized = ioc.trim()
  if (normalized.length <= maxLength) {
    return normalized
  }
  return `${normalized.slice(0, maxLength - 1)}…`
}

// Firefox resolves `tabs.create` with a promise while Chromium answers through
// a callback; both shapes are accepted here.
const createTab = (properties: CreateProperties): Promise<chrome.tabs.Tab> =>
  new Promise((resolve, reject) => {
    try {
      const maybePromise = chrome.tabs.create(
        properties as chrome.tabs.CreateProperties,
        (tab) => {
          const error = chrome.runtime.lastError
          if (error) {
            reject(new Error(error.message))
            return
          }
          resolve(tab)
        }
      ) as unknown as Promise<chrome.tabs.Tab> | undefined

      if (maybePromise && typeof maybePromise.then === "function") {
        maybePromise.then(resolve, reject)
      }
    } catch (error) {
      reject(error)
    }
  })

const groupTabs = async (
  tabIds: number[],
  ioc: string,
  windowId?: number
): Promise<boolean> => {
  const tabsApi = chrome.tabs as ChromiumTabsApi
  if (tabIds.length === 0 || typeof tabsApi.group !== "function") {
    return false
  }

  try {
    const groupId = await tabsApi.group({
      tabIds,
      ...(typeof windowId === "number"
        ? { createProperties: { windowId } }
        : {})
    })

    const tabGroups = (chrome as typeof chrome & { tabGroups?: TabGroupsApi })
      .tabGroups
    if (typeof tabGroups?.update === "function") {
      await tabGroups.update(groupId, {
        title: buildTabGroupTitle(ioc),
        color: pickTabGroupColor(ioc)
      })
    }
    return true
  } catch (error) {
    // Grouping is a convenience: a failure must never hide the lookup results.
    console.debug("Unable to group the lookup tabs:", error)
    return false
  }
}

export const openIocTabs = async ({
  ioc,
  urls,
  openerTabId,
  openerIndex,
  windowId,
  grouping = true
}: {
  ioc: string
  urls: string[]
  openerTabId?: number
  openerIndex?: number
  windowId?: number
  grouping?: boolean
}): Promise<OpenedIocTabs> => {
  const tabIds: number[] = []

  for (const [offset, url] of urls.entries()) {
    try {
      const tab = await createTab({
        url,
        // Background tabs keep the analyst on the page they were reading.
        active: false,
        ...(typeof windowId === "number" ? { windowId } : {}),
        ...(typeof openerTabId === "number" ? { openerTabId } : {}),
        ...(typeof openerIndex === "number"
          ? { index: openerIndex + offset + 1 }
          : {})
      })
      if (typeof tab?.id === "number") {
        tabIds.push(tab.id)
      }
    } catch (error) {
      console.error("Unable to open the lookup tab:", url, error)
    }
  }

  const grouped = grouping ? await groupTabs(tabIds, ioc, windowId) : false
  return { tabIds, grouped }
}
