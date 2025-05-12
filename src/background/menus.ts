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
    { id: "CyberChef", title: "Open in CyberChef" },
    { id: "getIOC", title: "Extract IOC" },
    { id: "refangIOC", title: "Refang IOC", parentId: "getIOC" },
    { id: "defangIOC", title: "Defang IOC", parentId: "getIOC" },
    { id: "CVE", title: "Extract CVE" },
    { id: "copyCVE", title: "Copy CVEs", parentId: "CVE" },
    { id: "copyCVECSV", title: "Copy CVEs as CSV", parentId: "CVE" }
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
      title: `Check ${type}`,
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
