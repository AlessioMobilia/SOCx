import type { PlasmoCSConfig } from "plasmo";
import { identifyIOC, extractIOCs, formatVirusTotalData, formatAbuseIPDBData, showNotification, saveIOC } from "../utility/utils";
import tippy from 'tippy.js';
import 'tippy.js/dist/tippy.css';
import { servicesConfig } from "../utility/servicesConfig";
import './content.css';



export const config: PlasmoCSConfig = {
  matches: ["<all_urls>"],
  all_frames: true
};


// Ascolta i messaggi dal background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "copyToClipboard") {
    navigator.clipboard.writeText(message.text)
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ error: err.message }));
  }
  return true; // Mantieni il canale aperto per la risposta asincrona
});

// Funzione per creare e mostrare il pulsante
const createButton = (IOC: string): HTMLButtonElement => {
  const type = identifyIOC(IOC);
  
  const ButtonName =  type === "IP" ? "Abuse" : "VT";
  const serviceConfig = servicesConfig.services["VirusTotal"];
  if(!serviceConfig.supportedTypes.includes(type)) return;

  const button = document.createElement("button");
  button.style.background = "url("+chrome.runtime.getURL("/assets/"+ (type === "IP" ? "abuseipdb" : "virustotal")+".png")+")";
  button.style.backgroundSize = "cover"; // o "contain"
  button.style.width = "25px";
  button.style.height = "25px";
  button.id = "IOCButton_SOCx";
  //button.textContent = ButtonName;

  // Aggiungi stili personalizzati
  button.style.padding = "5px 10px";
  button.style.border = "none";
  button.style.borderRadius = "4px";
  button.style.cursor = "pointer";
  button.style.position = "absolute";
  button.style.zIndex = "1000";
  //button.style.backgroundColor = "#0D6EFD";

  // Gestisci il clic sul pulsante
  button.addEventListener("click", async (event) => {
    try {
      const response = await GetIOCInfo(IOC);
      const data = response.results[Object.keys(response.results)[0]];
      const info = identifyIOC(IOC) === "IP" ? <string>formatAbuseIPDBData(data?.AbuseIPDB) : <string>formatVirusTotalData(data?.VirusTotal);
      if (!(await saveIOC(identifyIOC(IOC), IOC))) {
          showNotification("Errore", "Impossibile salvare l'IOC.");
          return;
        }
      createTooltip(info, button);
      navigator.clipboard.writeText(info);

      

    } catch (error) {
      console.error("Errore durante il recupero dei dati IOC:", error);
    }
  });

  return button;
};

const createMagicButton = (IOC: string): HTMLButtonElement => {
  const ButtonName = "";
  const button = document.createElement("button");
  button.style.background = "url("+chrome.runtime.getURL("/assets/icon.png")+")";
  button.style.backgroundSize = "cover"; // o "contain"
  button.style.width = "25px";
  button.style.height = "25px";
  button.id = "MagicButton_SOCx";
  button.textContent = ButtonName;

  // Aggiungi stili personalizzati
  button.style.padding = "5px 10px";
  button.style.border = "none";
  button.style.borderRadius = "4px";
  button.style.cursor = "pointer";
  button.style.position = "absolute";
  button.style.zIndex = "1000";
  button.style.backgroundColor = "#FFC107";

  // Gestisci il clic sul pulsante
  button.addEventListener("click", (event) => {
    
    RequestIOCInfo(IOC).then();
    
  });

  return button;
};

const GetIOCInfo = (IOC: string): Promise<any> => {
  return new Promise((resolve, reject) => {
    const iocList = [IOC];
    const selectedServices = [identifyIOC(IOC) === "IP" ? "AbuseIPDB" : "VirusTotal"];
    chrome.runtime.sendMessage(
      { action: "checkBulkIOCs", iocList, services: selectedServices },
      (response) => {
        resolve(response);
      }
    );
  });
};

const RequestIOCInfo = (IOC: string): Promise<any> => {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(
      { action: "MagicIOCRequest", IOC },
      (response) => {
        resolve(response);
      }
    );
  });
};

// Variabile per memorizzare il pulsante corrente
let currentButton: HTMLButtonElement | null = null;
let currentMagicButton: HTMLButtonElement | null = null;
let oldselection: String | null = null;

// Gestisci la selezione del testo
document.addEventListener("mouseup", () => {
  const selection = window.getSelection();
  if(selection ==null){
    oldselection = null;
    if (currentButton) {
      currentButton.remove();
      currentButton = null;
    }
  
    if (currentMagicButton) {
      currentMagicButton.remove();
      currentMagicButton = null;
    }
    return;
  }
    
  if (selection?.toString() === oldselection) return;
  oldselection = selection.toString();
  const IOCs = extractIOCs(selection?.toString().trim());
  if(IOCs==null) return;
  const selectedText = IOCs[0];

  // Rimuovi il pulsante esistente se c'è
  if (currentButton) {
    currentButton.remove();
    currentButton = null;
  }

  if (currentMagicButton) {
    currentMagicButton.remove();
    currentMagicButton = null;
  }

  if (selectedText) {
    let rect: DOMRect;
  
    // Ottieni la selezione corrente
    const selection = window.getSelection();
    if (selection.rangeCount > 0) {
      const range = selection.getRangeAt(0);
      rect = range.getBoundingClientRect();
  
      // Verifica se la selezione è all'interno di un input o textarea
      const activeElement = document.activeElement;
      if (activeElement instanceof HTMLInputElement || activeElement instanceof HTMLTextAreaElement) {
        const input = activeElement;
  
        // Crea un div temporaneo per misurare la posizione del testo
        const div = document.createElement('div');
        const span = document.createElement('span');
  
        // Copia gli stili dell'input nel div
        const computedStyle = window.getComputedStyle(input);
        for (const prop of computedStyle) {
          div.style[prop] = computedStyle.getPropertyValue(prop);
        }
  
        // Imposta il contenuto del div con il testo prima della selezione
        div.textContent = input.value.substring(0, input.selectionEnd);
        div.appendChild(span);
        document.body.appendChild(div);
  
        // Ottieni le posizioni degli elementi
        const divPos = div.getBoundingClientRect();
        const spanPos = span.getBoundingClientRect();
        const inputPos = input.getBoundingClientRect();
  
        // Calcola la posizione corretta
        rect = {
          top: inputPos.top + (spanPos.top - divPos.top) - input.scrollTop,
          left: inputPos.left + (spanPos.left - divPos.left) - input.scrollLeft,
          width: spanPos.width,
          height: spanPos.height,
          right: inputPos.left + (spanPos.left - divPos.left) + spanPos.width - input.scrollLeft + 3,
          bottom: inputPos.top + (spanPos.top - divPos.top) + spanPos.height - input.scrollTop,
        } as DOMRect;
  
        // Rimuovi il div temporaneo
        document.body.removeChild(div);
  
      }
  
      // Crea e posiziona il pulsante vicino al testo selezionato
      const button = createButton(selectedText);
      var ButtonWidth = 0;
      if(button){
        document.body.appendChild(button);
        button.style.position = 'absolute';
        button.style.left = `${rect.right + window.scrollX + 3}px`; // 5px di margine
        button.style.top = `${rect.top + window.scrollY}px`;
        currentButton = button;
        ButtonWidth = button.clientWidth;
      }

      
  
      // Creazione e posizionamento del MagicButton
      const IOC = extractIOCs(selectedText)[0];
      const Magicbutton = createMagicButton(IOC);
      if(Magicbutton){
        document.body.appendChild(Magicbutton);
        Magicbutton.style.position = 'absolute';
        Magicbutton.style.left = `${rect.right + window.scrollX + 10 + ButtonWidth}px`; // 5px di margine + larghezza del primo pulsante
        Magicbutton.style.top = `${rect.top + window.scrollY}px`;
        currentMagicButton = Magicbutton;
      }
      
    }
  }
});

// Rimuovi il pulsante se la selezione viene deselezionata
document.addEventListener("mousedown", (event) => {
  if (currentButton && !currentButton.contains(event.target as Node) && !currentMagicButton.contains(event.target as Node)) {
    currentButton.remove();
    currentMagicButton.remove();
    currentMagicButton=null;
    currentButton = null;
  }
});

// Funzione per creare il tooltip/popup
const createTooltip = (text: string, button: HTMLButtonElement) => {
  // Sostituisci i tab con spazi e i newline con <br> per l'HTML
  let modifiedText = text.replaceAll("\n", "<br>");

  // Aggiungi classi CSS in base ai valori
  modifiedText = modifiedText
    .replace(/Punteggio di Abuso:\t(\d+)\%/g, (match, value) => {
      const colorClass = parseInt(value) === 0 ? "notMalicious_tooltip" : "malicious_tooltip";
      return `<span class="${colorClass}">${match}</span>`;
    })
    .replace(/Malevoli:\t\t(\d+)/g, (match, value) => {
      const colorClass = parseInt(value) === 0 ? "notMalicious_tooltip" : "malicious_tooltip";
      return `<span class="${colorClass}">${match}</span>`;
    });

  // Crea il contenuto HTML
  const t = `<div>${modifiedText}</div>`;


  // Crea il tooltip con Tippy.js
  const tooltipInstance = tippy(button, {
    allowHTML: true,
    content: t,
  });

  tooltipInstance.show();
};