import { servicesConfig } from "../utility/servicesConfig";

export const setupContextMenus = () => {
  chrome.storage.local.get(["isDarkMode"], (result) => {
    if (result.isDarkMode === undefined) {
      chrome.storage.local.set({ isDarkMode: false });
    }
  });

  const baseMenus = [
    { id: "MagicIOC", title: "MAGIC IOC" },
    { id: "AddToBulkCheck", title: "Bulk Check" },
    { id: "CyberChef", title: "Apri in CyberChef" },
    { id: "getIOC", title: "Estrai IOC" },
    { id: "refangIOC", title: "Refang IOC", parentId: "getIOC" },
    { id: "defangIOC", title: "Defang IOC", parentId: "getIOC" },
    { id: "CVE", title: "Estrai CVE" },
    { id: "copyCVE", title: "Estrai le CVE", parentId: "CVE" },
    { id: "copyCVECSV", title: "Estrai le CVE in formato CSV", parentId: "CVE" }
  ];

  baseMenus.forEach(item => {
    chrome.contextMenus.create({
      ...item,
      contexts: ["selection"]
    });
  });

  Object.entries(servicesConfig.availableServices).forEach(([type, services]) => {
    chrome.contextMenus.create({
      id: type,
      title: `Verifica ${type}`,
      contexts: ["selection"]
    });

    services.forEach(service => {
      chrome.contextMenus.create({
        id: `${type}_${service}`,
        title: servicesConfig.services[service].title,
        contexts: ["selection"],
        parentId: type
      });
    });
  });
};
