import type { PlasmoCSConfig } from "plasmo";
import { fetchSpurData, formatSpurData } from "../utility/utils"
import {
  extractIOCs,
  identifyIOC,
  showNotification,
  saveIOC,
  formatVirusTotalData,
  formatAbuseIPDBData
} from "../utility/utils";
import { servicesConfig } from "../utility/servicesConfig";
import { createButton, createMagicButton } from "../utility/buttonFactory";
import { createTooltip } from "../utility/tooltipFactory";
import "tippy.js/dist/tippy.css";
import "./content.css";

export const config: PlasmoCSConfig = {
  matches: ["<all_urls>"],
  all_frames: true
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "copyToClipboard") {
    navigator.clipboard.writeText(message.text)
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ error: err.message }));
  }
  return true;
});

let currentButton: HTMLButtonElement | null = null;
let currentMagicButton: HTMLButtonElement | null = null;
let oldSelection: string | null = null;

document.addEventListener("mouseup", debounce(handleSelection, 300));
document.addEventListener("selectionchange", handleSelectionChange);

function handleSelectionChange() {
  const selection = window.getSelection();
  if (!selection || selection.toString().trim() === "") {
    currentButton?.remove();
    currentMagicButton?.remove();
    currentButton = currentMagicButton = null;
    oldSelection = null;
  }
}

async function handleSelection() {
  const selection = window.getSelection();
  const selectedText = selection?.toString().trim();
  if (!selectedText || (selectedText === oldSelection && currentButton)) return;

  oldSelection = selectedText;
  const iocs = extractIOCs(selectedText);
  if (!iocs?.length) return;

  const ioc = iocs[0];
  const type = identifyIOC(ioc);
  if (!type) return;

  currentButton?.remove();
  currentMagicButton?.remove();

  const range = selection!.getRangeAt(0);
  let rect = range.getBoundingClientRect();

// Se rect è vuoto o invisibile, prova a calcolare la posizione manualmente per input/textarea
if (rect.width === 0 && rect.height === 0) {
  const activeElement = document.activeElement as HTMLElement;
  if (activeElement instanceof HTMLInputElement || activeElement instanceof HTMLTextAreaElement) {
    const input = activeElement;
    const computedStyle = window.getComputedStyle(input);

    // Crea div invisibile per misurare la posizione
    const mirrorDiv = document.createElement("div");
    mirrorDiv.style.position = "absolute";
    mirrorDiv.style.visibility = "hidden";
    mirrorDiv.style.whiteSpace = "pre-wrap";
    mirrorDiv.style.wordWrap = "break-word";
    mirrorDiv.style.left = "-9999px";

    // Copia tutti gli stili dell’input
    for (const prop of computedStyle) {
      mirrorDiv.style.setProperty(prop, computedStyle.getPropertyValue(prop));
    }

    // Posiziona e calcola la lunghezza del testo fino al punto selezionato
    mirrorDiv.textContent = input.value.substring(0, input.selectionEnd || 0);

    const span = document.createElement("span");
    mirrorDiv.appendChild(span);
    document.body.appendChild(mirrorDiv);

    const spanRect = span.getBoundingClientRect();
    const inputRect = input.getBoundingClientRect();

    rect = {
      top: inputRect.top + (spanRect.top - mirrorDiv.getBoundingClientRect().top) - input.scrollTop,
      left: inputRect.left + (spanRect.left - mirrorDiv.getBoundingClientRect().left) - input.scrollLeft,
      width: spanRect.width,
      height: spanRect.height,
      right: inputRect.left + (spanRect.left - mirrorDiv.getBoundingClientRect().left) + spanRect.width - input.scrollLeft,
      bottom: inputRect.top + (spanRect.top - mirrorDiv.getBoundingClientRect().top) + spanRect.height - input.scrollTop,
      toJSON: () => rect
    } as DOMRect;

    document.body.removeChild(mirrorDiv);
  }
}

// Se ancora non valido, abbandona
if (rect.width === 0 && rect.height === 0) return;



  // Button 1
  const button = createButton(ioc, async () => {
    try {
      const response = await getIOCInfo(ioc);
      const data = response.results[Object.keys(response.results)[0]];
      let info = "";

      if (type === "IP") {
        const abuseInfo = formatAbuseIPDBData(data?.AbuseIPDB) ?? "";
        let spurInfo = "";

        try {
          const { spurApiKey } = await chrome.storage.local.get(["spurApiKey"]);
          if (spurApiKey) {
            try {
              const spurData = await fetchSpurData(ioc);
              spurInfo = formatSpurData(spurData);
            } catch (spurError) {
              console.warn("Errore nel recupero Spur:", spurError);
            }
          } else {
            console.info("Chiave API Spur non presente, non verrà usato Spur.");
          }
        } catch (e) {
          console.warn("Errore Spur non gestito:", e);
        }

        info = [abuseInfo, spurInfo].filter(Boolean).join("\n\n");
      } else {
        info = formatVirusTotalData(data?.VirusTotal);
      }

      createTooltip(info, button);
      navigator.clipboard.writeText(info);


      if (!(await saveIOC(type, ioc))) {
        showNotification("Errore", "Impossibile salvare l'IOC.");
        return;
      }

    } catch (err) {
      console.error("Errore durante il recupero dei dati IOC:", err);
    }
  });

  if (button) {
    document.body.appendChild(button);
    button.style.left = `${rect.right + window.scrollX + 3}px`;
    button.style.top = `${rect.top + window.scrollY}px`;
    currentButton = button;
  }

  // Button 2
  const magicButton = createMagicButton(ioc, () => {
    requestIOCInfo(ioc);
  });

  if (magicButton) {
    document.body.appendChild(magicButton);
    const offset = button ? button.clientWidth + 10 : 10;
    magicButton.style.left = `${rect.right + window.scrollX + offset}px`;
    magicButton.style.top = `${rect.top + window.scrollY}px`;
    currentMagicButton = magicButton;
  }
}

function getIOCInfo(ioc: string): Promise<any> {
  const selectedServices = [identifyIOC(ioc) === "IP" ? "AbuseIPDB" : "VirusTotal"];
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(
      { action: "checkBulkIOCs", iocList: [ioc], services: selectedServices },
      resolve
    );
  });
}

function requestIOCInfo(ioc: string): Promise<any> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ action: "MagicIOCRequest", IOC: ioc }, resolve);
  });
}

function debounce(fn: Function, delay: number) {
  let timeout: NodeJS.Timeout;
  return (...args: any[]) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => fn(...args), delay);
  };
}
