import { servicesConfig } from "../utility/servicesConfig"

export type ContextMenuApi = {
  create: (properties: chrome.contextMenus.CreateProperties) => Promise<void>
  removeAll: () => Promise<void>
  onClicked: {
    addListener: (
      callback: (
        info: chrome.contextMenus.OnClickData,
        tab?: chrome.tabs.Tab
      ) => void
    ) => void
  }
}

type FirefoxMenusApi = {
  create: (
    properties: chrome.contextMenus.CreateProperties,
    callback?: () => void
  ) => string | number
  removeAll: () => Promise<void>
  onClicked: ContextMenuApi["onClicked"]
}

type FirefoxBrowserApi = {
  menus?: FirefoxMenusApi
}

const runtimeErrorMessage = (): string | undefined =>
  chrome.runtime.lastError?.message

const chromiumContextMenuApi = (): ContextMenuApi => ({
  create: (properties) =>
    new Promise((resolve, reject) => {
      chrome.contextMenus.create(properties, () => {
        const error = runtimeErrorMessage()
        if (error) {
          reject(new Error(error))
          return
        }
        resolve()
      })
    }),
  removeAll: () =>
    new Promise((resolve, reject) => {
      chrome.contextMenus.removeAll(() => {
        const error = runtimeErrorMessage()
        if (error) {
          reject(new Error(error))
          return
        }
        resolve()
      })
    }),
  onClicked: chrome.contextMenus.onClicked
})

export const getContextMenuApi = (): ContextMenuApi => {
  const firefoxMenus = (
    globalThis as typeof globalThis & { browser?: FirefoxBrowserApi }
  ).browser?.menus

  if (!firefoxMenus) {
    return chromiumContextMenuApi()
  }

  return {
    create: async (properties) => {
      firefoxMenus.create(properties)
    },
    removeAll: async () => {
      await firefoxMenus.removeAll()
    },
    onClicked: firefoxMenus.onClicked
  }
}

export const getContextMenuDefinitions =
  (): chrome.contextMenus.CreateProperties[] => {
    const definitions: chrome.contextMenus.CreateProperties[] = []

    const baseMenus = [
      { id: "MagicIOC", title: "MAGIC IOC" },
      { id: "extractText", title: "Key:Value Smart formatting" },
      { id: "AddToBulkCheck", title: "Bulk Check" },
      { id: "CyberChef", title: "Open in CyberChef" },
      { id: "getIOC", title: "Extract IOC" },
      { id: "refangIOC", title: "Refang IOC", parentId: "getIOC" },
      { id: "defangIOC", title: "Defang IOC", parentId: "getIOC" },
      { id: "CVE", title: "Extract CVE" },
      { id: "copyCVE", title: "Copy CVEs", parentId: "CVE" },
      { id: "copyCVECSV", title: "Copy CVEs as CSV", parentId: "CVE" }
    ]

    baseMenus.forEach((item) => {
      definitions.push({
        ...item,
        contexts: ["selection"]
      })
    })

    Object.entries(servicesConfig.availableServices).forEach(
      ([type, services]) => {
        definitions.push({
          id: type,
          title: `Check ${type}`,
          contexts: ["selection"]
        })

        services.forEach((service) => {
          definitions.push({
            id: `${type}_${service}`,
            title: servicesConfig.services[service].title,
            contexts: ["selection"],
            parentId: type
          })
        })
      }
    )

    return definitions
  }

export const setupContextMenus = async (
  contextMenus = getContextMenuApi()
): Promise<void> => {
  await contextMenus.removeAll()
  for (const definition of getContextMenuDefinitions()) {
    await contextMenus.create(definition)
  }
}
