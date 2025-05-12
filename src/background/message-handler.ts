import { extractIOCs, identifyIOC, saveIOC, showNotification } from "../utility/utils";
import { servicesConfig } from "../utility/servicesConfig";
import { checkVirusTotal, checkAbuseIPDB } from "../utility/api";
import { defaultServices } from "../utility/defaultServices";

export function handleMessages(request, sender, sendResponse) {
  if (request.action === "checkBulkIOCs") {
    const { iocList, services } = request;
    checkBulk(iocList, services).then((results) => {
      sendResponse({ results });
    });
    return true; // Required because sendResponse is async
  }

  if (request.action === "MagicIOCRequest") {
    const ioc = extractIOCs(request.IOC)?.[0];
    const type = identifyIOC(ioc);

    if (!ioc || !type) {
      showNotification("Error", "Invalid IOC.");
      return;
    }

    saveIOC(type, ioc).then(() => {
      chrome.storage.local.get(["selectedServices", "customServices"]).then((config) => {
        const selected = config.selectedServices || defaultServices;
        const customServices = config.customServices || [];

        if (selected[type]) {
          selected[type].forEach(service => {
            const sConf = servicesConfig.services[service];
            if (sConf?.supportedTypes.includes(type)) {
              chrome.tabs.create({ url: sConf.url(type, ioc) });
            }
          });
        }

        const customForType = customServices.filter((s) => s.type === type);
        customForType.forEach((service) => {
          if (service.url.includes("{ioc}")) {
            const finalUrl = service.url.replace("{ioc}", encodeURIComponent(ioc));
            chrome.tabs.create({ url: finalUrl });
          }
        });
      });
    });

    return true;
  }
}

async function checkBulk(iocList: string[], services: string[]) {
  const results = {};
  const keys = await chrome.storage.local.get(["virusTotalApiKey", "abuseIPDBApiKey"]);

  for (const service of services) {
    if (service === "VirusTotal" && !keys.virusTotalApiKey) {
      showNotification("Error", "Missing VirusTotal API key.");
      return {};
    }
    if (service === "AbuseIPDB" && !keys.abuseIPDBApiKey) {
      showNotification("Error", "Missing AbuseIPDB API key.");
      return {};
    }
  }

  for (const ioc of iocList) {
    const type = identifyIOC(ioc);
    interface IOCServiceResult {
      VirusTotal?: any;
      AbuseIPDB?: any;
      [key: string]: any;
    }

    const result: IOCServiceResult = {};

    if (type) {
      if (services.includes("VirusTotal") && type !== "MAC") {
        result.VirusTotal = await checkVirusTotal(ioc, type);
      }
      if (services.includes("AbuseIPDB") && type === "IP") {
        result.AbuseIPDB = await checkAbuseIPDB(ioc);
      }
    }
    results[ioc] = result;
  }

  return results;
}
