import {
  copyToClipboard, extractIOCs, refang, defang, formatCVEs,
  identifyIOC, isPrivateIP, showNotification, saveIOC
} from "../utility/utils";
import { servicesConfig } from "../utility/servicesConfig";
import { defaultServices } from "../utility/defaultServices";

export async function handleMenuClick(info: chrome.contextMenus.OnClickData, tab: chrome.tabs.Tab) {
  const selection = info.selectionText?.trim();
  if (!selection) return showNotification("Errore", "Nessun testo selezionato.");

  const iocList = extractIOCs(selection);
  const ioc = iocList?.[0];
  const type = identifyIOC(ioc);

  if (!ioc || !type) return showNotification("Errore", "IOC non valido.");
  if (type === "IP" && isPrivateIP(ioc)) return showNotification("Privato", "IP privato, nessuna analisi.");

  const copyOps = {
    "refangIOC": () => copyToClipboard(iocList.map(refang).join("\n"), tab.id),
    "defangIOC": () => copyToClipboard(iocList.map(defang).join("\n"), tab.id),
    "copyCVE": () => copyToClipboard(formatCVEs(selection, false), tab.id),
    "copyCVECSV": () => copyToClipboard(formatCVEs(selection, true), tab.id)
  };

  if (info.menuItemId in copyOps) return copyOps[info.menuItemId]();

  if (info.menuItemId === "CyberChef") {
    const base64 = btoa(unescape(encodeURIComponent(selection))).replaceAll("=", "");
    chrome.tabs.create({ url: `https://gchq.github.io/CyberChef/#input=${base64}` });
    return;
  }

  if (info.menuItemId === "AddToBulkCheck") {
    chrome.storage.local.set({ bulkIOCList: iocList }, () => {
      chrome.tabs.create({ url: chrome.runtime.getURL('/tabs/bulk_check.html') });
    });
    return;
  }

  await saveIOC(type, ioc);

  if (info.menuItemId === "MagicIOC") {
    const settings = await chrome.storage.local.get("selectedServices");
    const selected = settings.selectedServices || defaultServices;

    if (!selected[type]) return showNotification("Errore", "Nessun servizio selezionato.");

    selected[type].forEach(service => {
      const config = servicesConfig.services[service];
      if (config?.supportedTypes.includes(type)) {
        chrome.tabs.create({ url: config.url(type, ioc) });
      }
    });
    return;
  }

  const [menuType, service] = info.menuItemId.toString().split("_");
  const config = servicesConfig.services[service];

  if (config?.supportedTypes.includes(type)) {
    chrome.tabs.create({ url: config.url(type, ioc) });
  } else {
    showNotification("Errore", "Servizio o tipo non valido.");
  }
}
