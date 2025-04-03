// src/background.ts
import { copyToClipboard, identifyIOC, isPrivateIP, refang, defang, showNotification, saveIOC, formatCVEs, extractIOCs } from "./utility/utils";
import { checkVirusTotal, checkAbuseIPDB } from "./utility/api";
import { servicesConfig } from "./utility/servicesConfig";
import { SlowBuffer } from "buffer";

chrome.runtime.onInstalled.addListener(() => {
  chrome.sidePanel.setOptions({
    enabled: true,
  })
})






// Creazione del menu contestuale
chrome.runtime.onInstalled.addListener(() => {

  chrome.storage.local.get(["isDarkMode"], (result) => {
    if (result.isDarkMode !== undefined)
    {
      chrome.storage.local.set({ isDarkMode: false });
    }
  });

  chrome.sidePanel.setOptions({ enabled: true });

  // Menu principale
  chrome.contextMenus.create({
    id: "MagicIOC",
    title: "MAGIC IOC",
    contexts: ["selection"],
  });

  chrome.contextMenus.create({
    id: "AddToBulkCheck",
    title: "Bulk Check",
    contexts: ["selection"],
  });

  chrome.contextMenus.create({
    id: "CyberChef",
    title: "Apri in CyberChef",
    contexts: ["selection"],
  });

  chrome.contextMenus.create({
    id: "getIOC",
    title: "Estrai IOC",
    contexts: ["selection"],
  });

  chrome.contextMenus.create({
    id: "refangIOC",
    title: "Refang IOC",
    contexts: ["selection"],
    parentId:"getIOC",
  });

  chrome.contextMenus.create({
    id: "defangIOC",
    title: "Defang IOC",
    contexts: ["selection"],
    parentId:"getIOC",
  });

  chrome.contextMenus.create({
    id: "CVE",
    title: `Estrai CVE`,
    contexts: ["selection"],
  });

  chrome.contextMenus.create({
    id: "copyCVE",
    title: `Extrai le CVE`,
    contexts: ["selection"],
    parentId: "CVE",
  });

  chrome.contextMenus.create({
    id: "copyCVECSV",
    title: `Extrai le CVE in formato CSV`,
    contexts: ["selection"],
    parentId: "CVE",
  });


  // Crea sottomenù per ogni tipo di IOC
  Object.entries(servicesConfig.availableServices).forEach(([type, services]) => {
    chrome.contextMenus.create({
      id: type,
      title: `Verifica ${type}`,
      contexts: ["selection"],
    });

    // Aggiungi i servizi sotto ogni tipo di IOC
    services.forEach((service) => {
      chrome.contextMenus.create({
        id: `${type}_${service}`,
        title: servicesConfig.services[service].title,
        contexts: ["selection"],
        parentId: type,
      });
    });
  });
});

// Gestione del clic sul menu contestuale
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!info.menuItemId || !info.selectionText) {
    showNotification("Errore", "Nessun testo selezionato o voce di menu non valida.");
    return;
  }
  const txt = info.selectionText.trim();

  if (info.menuItemId === "refangIOC" && info.selectionText) {
    const iocs = extractIOCs(txt, false);
    var refangedIOCs = "";
    iocs.forEach((ioc: string) => {
      const refangedText = refang(ioc);
      refangedIOCs = refangedIOCs + refangedText + "\n";
    });
    copyToClipboard(refangedIOCs, tab.id);
    return;
  }

  if (info.menuItemId === "defangIOC") {
    const iocs = extractIOCs(txt);
    var defangedIOCs = "";
    iocs.forEach((ioc: string) => {
      const defangedText = defang(ioc);
      defangedIOCs = defangedIOCs + defangedText + "\n";
    });
    copyToClipboard(defangedIOCs, tab.id);
    return;
  }

  if (info.menuItemId === "copyCVE") {
    const CVEs = formatCVEs(txt, false);
    copyToClipboard(CVEs, tab.id);
    return;
  }

  if (info.menuItemId === "copyCVECSV") {
    const CVEs = formatCVEs(txt, true);
    copyToClipboard(CVEs, tab.id);
    return;
  }

  if (info.menuItemId === "CyberChef") {
    if (txt.length > 0) {
      // Converti il testo in Base64 (supporto per Unicode)
      const base64Text = btoa(txt).replaceAll("=","");
  
      // Costruisci l'URL di CyberChef con l'input in Base64
      const cyberChefUrl = `https://gchq.github.io/CyberChef/#input=${base64Text}`;
  
      // Apri una nuova scheda con l'URL di CyberChef
      chrome.tabs.create({ url: cyberChefUrl }, (tab) => {
        if (chrome.runtime.lastError) {
          showNotification("Errore", "Impossibile aprire CyberChef.");
        } else {
          showNotification("Successo", "CyberChef aperto con successo.");
        }
      });
    } else {
      showNotification("Errore", "Nessun IOC valido trovato nel testo selezionato.");
    }
    return;
  }

  const ioc = <string>extractIOCs(txt)[0];
  if (!ioc) {
    showNotification("Errore", "Nessun IOC valido trovato nel testo selezionato.");
    return;
  }

  const type = identifyIOC(ioc);
  if (!type) {
    showNotification("Errore", "Tipo di IOC non supportato.");
    return;
  }

  if (type === "IP" && isPrivateIP(ioc)) {
    showNotification("Avviso", "L'IP è privato e non può essere verificato.");
    return;
  }

  if (!(await saveIOC(type, ioc))) {
    showNotification("Errore", "Impossibile salvare l'IOC.");
    return;
  }

  if (info.menuItemId === "AddToBulkCheck") {
    const ioc = extractIOCs(txt); // Estrai gli IOC dal testo selezionato
  
    if (ioc && ioc.length > 0) {
      // Salva gli IOC in chrome.storage.local
      chrome.storage.local.set({ bulkIOCList: ioc }, () => {
        // Apri la pagina bulk_check.html dopo aver salvato gli IOC
        chrome.tabs.create({ url: chrome.runtime.getURL('/tabs/bulk_check.html') });
      });
    } else {
      showNotification("Errore", "Nessun IOC valido trovato nel testo selezionato.");
    }
    return;
  }

  if (info.menuItemId === "MagicIOC") {
    chrome.storage.local.get(["selectedServices"]).then(result=>{
      

      var selectedServices = null;
      if(!result.selectedServices){
        selectedServices = defaultServices;
      }else{
        selectedServices = result.selectedServices;
      }
      
      if (selectedServices && selectedServices[type]) {
        selectedServices[type].forEach((service: string) => {
          const serviceConfig = servicesConfig.services[service];
          if (serviceConfig && serviceConfig.supportedTypes.includes(type)) {
            const url = serviceConfig.url(type, ioc);
            if (url) {
              chrome.tabs.create({ url });
            }
          }
        });
      } else {
        showNotification("Errore", "Nessun servizio selezionato per questo tipo di IOC.");
      }

    });

    
  } else {
    const [serviceType, service] = info.menuItemId.toString().split("_");
    const serviceConfig = servicesConfig.services[service];
    if (serviceConfig && serviceConfig.supportedTypes.includes(type)) {
      const url = serviceConfig.url(type, ioc);
      if (url) {
        chrome.tabs.create({ url });
      } else {
        showNotification("Errore", "Tipo di IOC non supportato per questo servizio.");
      }
    } else {
      showNotification("Errore", "Servizio non trovato.");
    }
  }
});




chrome.runtime.onMessage.addListener( (request, sender, sendResponse) => {

  if (request.action === "checkBulkIOCs") {
    const { iocList, services } = request

    // Avvia il processo asincrono
    checkBulkIOCs(iocList, services)
      .then((results) => sendResponse({ results })) // Invia la risposta
      .catch((error) => sendResponse({ error: error.message })) // Invia l'errore
    // Indica che la risposta sarà asincrona
    return true
  }

  if (request.action === "MagicIOCRequest") {
    const ioc = extractIOCs(request.IOC)[0];
    const type = identifyIOC(ioc);

    saveIOC(type, ioc).then(result =>{if(!result){
      showNotification("Errore", "Impossibile salvare l'IOC.");
      return;
      }
    })
      

    var selectedServices = [];
    
    chrome.storage.local.get(["selectedServices"]).then(result =>{
      var selectedServices = null;
      if(!result.selectedServices){
        selectedServices = defaultServices;
      }else{
        selectedServices = result.selectedServices;
      }
      
      if (selectedServices && selectedServices[type]) {
        selectedServices[type].forEach((service: string) => {
          const serviceConfig = servicesConfig.services[service];
          if (serviceConfig && serviceConfig.supportedTypes.includes(type)) {
            const url = serviceConfig.url(type, ioc);
            if (url) {
              chrome.tabs.create({ url });
            }
          }
        });
      } else {
        showNotification("Errore", "Nessun servizio selezionato per questo tipo di IOC.");
      }
    
    });
    
    return true;
  }
})

const checkBulkIOCs = async (iocList: string[], services: string[]): Promise<{ [key: string]: any }> => {
  const results: { [key: string]: any } = {};

  // Verifica la presenza delle chiavi API per i servizi selezionati
  const apiKeys = await chrome.storage.local.get(["virusTotalApiKey", "abuseIPDBApiKey"]);
  
  for (const service of services) {
    if (service === "VirusTotal" && !apiKeys.virusTotalApiKey) {
      showNotification("Errore", "Chiave API di VirusTotal mancante. Configurala nelle impostazioni.");
      return results; // Interrompi l'esecuzione se la chiave manca
    }
    if (service === "AbuseIPDB" && !apiKeys.abuseIPDBApiKey) {
      showNotification("Errore", "Chiave API di AbuseIPDB mancante. Configurala nelle impostazioni.");
      return results; // Interrompi l'esecuzione se la chiave manca
    }
  }

  // Esegui il controllo degli IOC
  for (const ioc of iocList) {
    const type = identifyIOC(ioc);
    if (type) {
      const result = await checkIOC(ioc, type, services);
      results[ioc] = result;
    }
  }

  return results;
};

const checkIOC = async (ioc: string, type: string, services: string[]): Promise<any> => {
  const result: { [key: string]: any } = {}
  for (const service of services) {
    if (service === "VirusTotal" && servicesConfig.services["VirusTotal"].supportedTypes.includes(type)) {
      result.VirusTotal = await checkVirusTotal(ioc, type)
    } else if (service === "AbuseIPDB" && type==="IP") {
      result.AbuseIPDB = await checkAbuseIPDB(ioc)
    }
  }

  return result || "";
}


  const defaultServices = <{ [key: string]: string[] }>({
    IP: ["VirusTotal", "AbuseIPDB"],
    Dominio: ["VirusTotal"],
    URL: ["VirusTotal"],
    Hash: ["VirusTotal"],
    Email: ["HaveIBeenPwned"],
    ASN: ["BGPToolkit"],
    MAC: ["MACVendors"],
  });