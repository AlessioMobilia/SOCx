import {
  copyToClipboard, extractIOCs, refang, defang, formatCVEs,
  identifyIOC, isPrivateIP, showNotification, saveIOC
} from "../utility/utils"
import { servicesConfig } from "../utility/servicesConfig"
import { defaultServices } from "../utility/defaultServices"
import { Storage } from "@plasmohq/storage"

const storage = new Storage({ area: "local" })

type SelectedServices = {
  [iocType: string]: string[] // Es: { IP: ["VirusTotal", ...] }
}

export async function handleMenuClick(info: any, tab: any) {
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
    copyCVECSV: () => copyToClipboard(formatCVEs(selection, true))
  }

  console.log("Menu clicked:", info.menuItemId, selection, tab.id)
  if (info.menuItemId in copyOps) {
    console.log("Copying:", info.menuItemId);
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
    const base64 = btoa(unescape(encodeURIComponent(selection))).replaceAll("=", "")
    chrome.tabs.create({ url: `https://gchq.github.io/CyberChef/#input=${base64}` })
    return
  }

  if (info.menuItemId === "AddToBulkCheck") {
    await storage.set("bulkIOCList", iocList)
    // Apri la pagina React (tabs/bulk-check.tsx)
    chrome.tabs.create({ url: chrome.runtime.getURL("tabs/bulk-check.html") })
    return
  }

  await saveIOC(type, ioc)

  if (info.menuItemId === "MagicIOC") {
    const selected = await storage.get<SelectedServices>("selectedServices") || defaultServices

    if (!selected[type]) {
      showNotification("Error", "No service selected.")
      return
    }

    selected[type].forEach((service) => {
      const config = servicesConfig.services[service]
      if (config?.supportedTypes.includes(type)) {
        chrome.tabs.create({ url: config.url(type, ioc) })
      }
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
