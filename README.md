# 🚀 SOCx – Simple OSINT Centralized eXtension

**SOCx** is the essential extension for security analysts, digital investigators, and **OSINT (Open-Source Intelligence)** enthusiasts. Designed to accelerate and centralize the verification of **IOC (Indicators of Compromise)**, SOCx allows you to perform in-depth checks directly from your browser in just a few clicks.

With integration of leading services like **VirusTotal**, **AbuseIPDB**, **Censys**, **Shodan**, **AlienVault**, **MxToolbox**, and many others, SOCx offers a powerful, convenient, and entirely **privacy-first** solution.

🔗 **Official Website**: [socx.alessiomobilia.com](http://socx.alessiomobilia.com/)

---

## 📥 Install SOCx

You can install SOCx directly from your browser’s official store:

- **Chrome Web Store**: https://chromewebstore.google.com/detail/socx/nanabcjeikkjaiabmlncionjliiobcaf
- **Firefox Add-ons**: https://addons.mozilla.org/it/firefox/addon/socx/
- **Microsoft Edge Add-ons**: https://microsoftedge.microsoft.com/addons/detail/socx/bghkcnheknfloofcbffhhlfaojknjkfp

---

## ✨ Key Features

- 🔍 **Instant IOC Check**
  Quickly analyze IPs, domains, URLs, hashes, emails, ASN, MAC addresses, and more.

- 📘 **Guided user workflow**
  A dedicated wiki with step‑by‑step examples, tips, and best practices for non‑technical users is available in the [SOCx wiki](https://github.com/AlessioMobilia/SOCx/wiki).

- 🌐 **Integration with over 20 OSINT services**
  Support for the most widely used services in the threat intelligence industry.

- 🛡️ **Privacy-first processing**
  SOCx does not run analytics or send investigation data to SOCx servers.
  Indicators, selected website content, and API keys are sent only when needed
  directly to the OSINT providers configured by the user.

- 🧾 **Compact threat-intelligence summaries**
  VirusTotal and AbuseIPDB results highlight high-confidence risk and positive
  signals without dumping raw responses. File aliases, digital signatures,
  WHOIS, certificate, network, and reporting details are capped to useful
  investigation context. Clipboard copies defang active indicators by default;
  this behavior can be disabled from Extension Settings.

- ⚡ **Coordinated provider requests**
  Provider lookups share short queues, transient-error retries, request
  deduplication, and a two-minute response cache. The cache can be cleared at
  any time from Extension Settings.

- ✨ **Smart selection formatting**
  Selected EDR, SIEM, OSINT, JSON, CEF, logfmt, key/value, CSV, HTML table, and
  ARIA grid data can be normalized for copying. Partial table selections reuse
  real headers when available and otherwise use neutral column names.

- 🧠 **Clean and intuitive interface**
  Designed to be lightweight and immediate. No frills, just OSINT.

---

## 🧪 How to Use

Use SOCx mainly while you browse: select an IOC (IP, domain, URL, hash, email, ASN, MAC) on any page and use the **right‑click menu** or **floating SOCx buttons** to open your favorite OSINT tools in one click. For long texts or lists, open the **popup** and use **Bulk IOC Check**, **Subnet tools**, or the **Field notes** side panel to organize and investigate indicators more efficiently.

For a more complete, always up‑to‑date guide with examples, screenshots, and best practices, see the [SOCx wiki](https://github.com/AlessioMobilia/SOCx/wiki).

---

## 🛠️ Development and release documentation

SOCx uses Node.js 22.13+ and pnpm 11.19.0. Install dependencies with the
version pinned in `package.json`:

```bash
git clone https://github.com/AlessioMobilia/socx.git
cd socx
corepack enable
corepack prepare pnpm@11.19.0 --activate
pnpm install
```

Run the complete static and production-build verification for Chrome, Edge,
and Firefox:

```bash
pnpm verify
```

Create the three ZIP archives ready for store validation:

```text
pnpm package
build/chrome-mv3-prod.zip
build/edge-mv3-prod.zip
build/firefox-prod.zip
```

See the detailed guides before changing or publishing a release:

- [Development, architecture, and cross-browser testing](docs/DEVELOPMENT.md)
- [Packaging and store publication runbook](docs/RELEASE.md)

---

## 🤝 Contributing

SOCx is an open-source project: contributions, ideas, and improvements are welcome!

1. Fork the repository
2. Create a branch for your feature/fix
3. Commit your changes
4. Submit a Pull Request

---

## 📄 License

Distributed under the **[MIT](LICENSE)** license.

---

## 💬 Contact

📧 [info@alessiomobilia.com](mailto:info@alessiomobilia.com)
🐛 Open an issue on GitHub

---

### 🔐 SOCx: Your OSINT ally in the browser — Secure, efficient, free.

---
