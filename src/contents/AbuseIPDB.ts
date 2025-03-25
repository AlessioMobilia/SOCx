import type { PlasmoCSConfig } from "plasmo";
import "./content.css"; // Importa il file CSS


// Configurazione per il contenuto dello script
export const config: PlasmoCSConfig = {
  matches: ["https://www.abuseipdb.com/check/*"],
  all_frames: true,
};

// Funzione per estrarre e formattare le informazioni dal div
function extractAndFormatInfo() {
  const targetDiv = document.querySelector('.col-md-6 .well');
  if (!targetDiv) return null;

  // Estrai i dati dall'HTML
  const ip = targetDiv.querySelector('h3 > b ')?.textContent?.trim(); // IP
  const reports = targetDiv.querySelector('p > b')?.textContent?.trim(); // Numero di segnalazioni
  const confidence = targetDiv.querySelector('.progress-bar > span')?.textContent?.trim(); // Confidence
  const isp = targetDiv.querySelector('table tr:first-child td')?.textContent?.trim(); // ISP
  const usageType = targetDiv.querySelector('table tr:nth-child(2) td')?.textContent?.trim(); // Usage Type
  const asn = targetDiv.querySelector('table tr:nth-child(3) td')?.textContent?.trim(); // ASN
  const domain = targetDiv.querySelector('table tr:nth-child(4) td')?.textContent?.trim(); // Domain
  const country = targetDiv.querySelector('table tr:nth-child(5) td')?.textContent?.trim(); // Country
  const city = targetDiv.querySelector('table tr:nth-child(6) td')?.textContent?.trim(); // City

  // Formatta i dati in una stringa
  const formattedInfo = `
IP:\t\t\t${ip}
Segnalazioni AbuseIPDB:\t${reports}
Confidenza:\t\t${confidence}
ISP:\t\t\t${isp}
Usage Type:\t\t${usageType}
ASN:\t\t\t${asn}
Dominio:\t\t${domain}
Paese:\t\t\t${country}
Città:\t\t\t${city}
  `.trim();

  return formattedInfo;
}

// Funzione per copiare il testo nella clipboard
function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text)
    .then(() => {
      alert('Informazioni copiate nella clipboard!');
    })
    .catch((err) => {
      console.error('Errore durante la copia nella clipboard:', err);
      alert('Errore durante la copia nella clipboard.');
    });
}

// Funzione principale che verrà eseguita quando la pagina è caricata
console.log("Script eseguito");

const targetDiv = document.querySelector('.col-md-6 .well');
if (targetDiv) {
// Crea un nuovo pulsante
const newButton = document.createElement('button');
newButton.textContent = 'Copia Informazioni';
newButton.style.marginTop = '10px';
newButton.style.width = '100%';
newButton.style.backgroundColor = "#007bff";
newButton.style.color = "#fff";
newButton.id="IOBAbuseButton";
newButton.style.padding = "5px 10px";
newButton.style.border = "none";
newButton.style.borderRadius = "4px";
newButton.style.cursor = "pointer";
newButton.style.zIndex = "1000";

// Aggiungi un gestore di eventi al pulsante
newButton.addEventListener('click', () => {
    const formattedInfo = extractAndFormatInfo();
    if (formattedInfo) {
    copyToClipboard(formattedInfo);
    } else {
    alert('Errore: Impossibile estrarre le informazioni.');
    }
});

// Aggiungi il pulsante al div target
targetDiv.appendChild(newButton);
}

