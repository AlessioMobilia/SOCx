# 🚀 SOCx – Simple OSINT Centralized eXtension

**SOCx** è l'estensione essenziale per analisti di sicurezza, investigatori digitali e appassionati di **OSINT (Open-Source Intelligence)**. Progettata per velocizzare e centralizzare la verifica di **IOC (Indicators of Compromise)**, SOCx ti consente di eseguire controlli approfonditi direttamente dal browser in pochi clic.

Con l'integrazione di servizi leader come **VirusTotal**, **AbuseIPDB**, **Censys**, **Shodan**, **AlienVault**, **MxToolbox** e molti altri, SOCx offre una soluzione potente, comoda e totalmente **privacy-first**.

🔗 **Sito ufficiale**: [socx.alessiomobilia.com](http://socx.alessiomobilia.com/)

---

## ✨ Funzionalità principali

* 🔍 **Controllo istantaneo degli IOC**
  Analizza rapidamente IP, domini, URL, hash, email, ASN, MAC address e altro.

* 🌐 **Integrazione con oltre 20 servizi OSINT**
  Supporto per i servizi più usati nel settore della threat intelligence.

* 🛡️ **Privacy totale**
  Nessun dato viene tracciato, salvato o condiviso. Tutto avviene in locale.

* 🧠 **Interfaccia pulita e intuitiva**
  Progettata per essere leggera e immediata. Nessun fronzolo, solo OSINT.

---

## 🔌 Servizi supportati

*Consulta la lista completa nel README originale o nella documentazione.*

---

## 🧪 Come si usa

1. **Installa l’estensione** dal [Chrome Web Store](#)
2. **Clicca sull’icona SOCx** nella toolbar del browser
3. **Inserisci un IOC** (IP, dominio, hash, ecc.)
4. **Seleziona i motori da interrogare**
5. **Visualizza i risultati** o esporta in CSV/Excel

---

## 🛠️ Come compilare l’estensione (modalità sviluppo)

Hai bisogno di testare o modificare SOCx localmente? Ecco come fare:

### Requisiti

* Node.js (consigliata versione 18+)
* npm o yarn

### Installazione

```bash
git clone https://github.com/AlessioMobilia/socx.git
cd socx
npm install
```

### Avvio in modalità sviluppo

```bash
npm run dev
```

1. Apri **Chrome** e vai su `chrome://extensions`
2. Attiva la **Modalità sviluppatore**
3. Clicca su **"Carica estensione non pacchettizzata"**
4. Seleziona la cartella `.plasmo` generata da Plasmo (`socx/.plasmo`)

### Build finale (per produzione)

```bash
npm run build
```

La versione compilata sarà disponibile nella cartella `build/`.

---

## 🤝 Contribuire

SOCx è un progetto open-source: contributi, idee e miglioramenti sono benvenuti!

1. Forka il repository
2. Crea un branch per la tua feature/fix
3. Fai i commit delle modifiche
4. Invia una Pull Request

---

## 📄 Licenza

Distribuito con licenza **[MIT](LICENSE)**.

---

## 💬 Contatti

📧 [info@alessiomobilia.com](mailto:info@alessiomobilia.com)
🐛 Apri una issue su GitHub

---

### 🔐 SOCx: il tuo alleato OSINT nel browser — Sicuro, efficiente, gratuito.

---
