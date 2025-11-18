# SOCx – Simple OSINT Centralized eXtension – Wiki

SOCx is a browser extension designed to help security analysts, incident responders, and OSINT (Open‑Source Intelligence) enthusiasts work faster directly from the browser.

It centralizes common tasks around **Indicators of Compromise (IOCs)** such as:

- IP addresses (IPv4 and IPv6)
- Domains
- URLs
- File hashes
- Email addresses
- ASNs (Autonomous System Numbers)
- MAC addresses

SOCx connects these indicators to a variety of external tools and services so you can investigate them with a few clicks instead of copying and pasting into many different sites.

This wiki focuses on what you can do with SOCx and how to use it effectively, without going into code‑level details, so it remains useful across future updates.

---

## 1. Quick Start – How to Use SOCx

This section is a short, user‑facing guide meant to stay valid as the extension evolves.

### 1.1 Basic Workflow

1. **Install** SOCx from the Chrome Web Store and pin the icon.
2. **Open the popup** by clicking the SOCx icon in your browser toolbar.
3. **Configure your tools** (API keys and services) in the **Options** page.
4. **Browse normally**: when you see possible IOCs (IPs, domains, URLs, hashes, emails, ASN, MAC), you can:
   - Select text and use the **right‑click context menu**.
   - Select text and use the **floating buttons** that appear near the selection.
   - Use the **popup** to open bulk tools, subnet tools, and your notes area.

### 1.2 Common Actions

- **Quick check of a single IOC**
  1. Select an IP, domain, URL, hash, email, ASN, or MAC on any webpage.
  2. Click the floating SOCx button that appears nearby, or pick a SOCx entry from the right‑click menu.
  3. SOCx sends the indicator to the services you configured and may show a short summary and/or open tabs with detailed results.

- **Open all favorite tools for an IOC (“magic” action)**
  1. Select an IOC.
  2. Use the dedicated “magic” entry in the context menu or floating button group.
  3. SOCx automatically opens all the services you chose for that IOC type (for example, VirusTotal, AbuseIPDB, Shodan, SecurityTrails, plus any custom tools you added).

- **Smart formatting of structured text**
  1. Highlight a block of structured data (tables, “key: value” lists, JSON‑style output, scan results, etc.).
  2. Right‑click and choose the SOCx smart formatting option.
  3. SOCx cleans and restructures the content into a tidy text block and copies it to your clipboard – ideal for tickets, case notes, or reports.

- **Bulk IOC checks**
  1. From the popup, click **Bulk IOC Check**.
  2. Paste any text that contains indicators (for example, an email, report, or log snippet) or import a `.txt` file.
  3. SOCx automatically extracts the indicators, groups them by type, and lets you choose which services to run.
  4. Run the bulk check, review the summaries, and export results to CSV or Excel.

- **Subnet tools**
  - **Subnet Extractor**: Paste IP lists and get summarized IPv4/IPv6 subnets at chosen prefix lengths (for example, /24, /48), to quickly move from single IPs to higher‑level network ranges.
  - **Subnet Risk Scan**: Paste subnets (in CIDR notation), scan them against reputation services, and export a summarized risk report.

- **Field notes (side panel)**
  1. From the popup, click **Field notes** to open the SOCx side panel (where supported by your browser).
  2. Use it as a simple analyst notebook; the content is saved in your browser and survives restarts.
  3. You can defang/refang IOCs inside your notes and export them as a `.txt` file.

### 1.3 Where to Configure SOCx

- **Popup**
  - Central “cockpit” with shortcuts to:
    - Bulk IOC tools.
    - Subnet tools.
    - Side panel (notes).
    - Options.
  - Shows your latest IOCs and lets you quickly clear history.

- **Options page**
  - Set API keys for external services (for example, VirusTotal, AbuseIPDB, ProxyCheck).
  - Enable or disable additional enrichments (for example, VPN/proxy checks).
  - Choose which services should open for each IOC type when you use the “magic” actions.
  - Add custom services by providing a URL template that includes the IOC.

---

## 2. Main Features at a Glance

This section provides a high‑level overview of what SOCx can do, without tying it to specific implementation details.

### 2.1 IOC‑Aware Context Menus

- When you select text on a page and right‑click, SOCx adds extra menu items that can:
  - Detect IOCs (IP, domain, URL, hash, email, ASN, MAC) in the selection.
  - **Defang** or **refang** indicators and copy them to the clipboard.
  - Extract structured identifiers (for example, CVEs or similar).
  - Run smart formatting to turn “messy” structured text (tables, key/value lists) into a clean, copy‑ready block.
  - Add indicators to a bulk list for analysis in the dedicated tab.

These menus are designed to work on any website where you can select text, and new entries may appear in future versions as new workflows are added.

### 2.2 Floating Action Buttons on Selections

- When SOCx recognizes that your selection looks like a single IOC, it can show a small floating button group near the highlighted text.
- With a single click you can:
  - Trigger a quick check that copies a summary to the clipboard or opens a tooltip.
  - Launch your “magic” action that opens multiple tools at once.
- The buttons automatically follow your selection and adapt to the page layout so they remain usable even on complex web applications.

### 2.3 Popup – Your OSINT Cockpit

- The popup gives you a compact, always‑available control panel:
  - Quick actions: Bulk IOC Check, Subnet Extractor, Subnet Risk Scan, Field notes, Options.
  - A “recent IOCs” list to quickly re‑use indicators you have already checked.
  - A theme toggle (light/dark) shared across the rest of the extension.

### 2.4 Bulk IOC Checking

- Designed for situations where you receive long lists of indicators (for example, from emails, reports, CSV exports, or chat logs).
- Key capabilities:
  - Paste or import text and let SOCx automatically find and deduplicate IOCs.
  - See how many indicators of each type are present.
  - Select which engines to query (for example, VirusTotal for domains/hashes and AbuseIPDB for IPs).
  - Run the checks in one go and get a summarized risk view.
  - Export the results to CSV or Excel for sharing, reporting, or archiving.

### 2.5 Subnet‑Focused Tools

- **Subnet Extractor**
  - Takes raw IP lists and summarizes them into networks (subnets) using configurable prefix lengths.
  - Helps you move from “many single IPs” to a more strategic, subnet‑level view.

- **Subnet Risk Scan**
  - Accepts subnet ranges (CIDR format) and checks them against reputation data.
  - Highlights which networks appear clean, which are frequently reported, and provides high‑level context (when available).
  - Supports exports so you can include results in reports, firewall change requests, or additional analysis.

### 2.6 Field Notes in the Side Panel

- The side panel is a lightweight notes area that can stay visible alongside websites (when your browser supports side panels).
- It is tailored for analysts:
  - Keep scratch notes for a case or investigation.
  - Paste summaries generated by SOCx.
  - Defang IOCs in notes before sharing them.
  - Save or clear your notes easily.

### 2.7 Flexible Integrations with OSINT Services

- SOCx comes with built‑in support for many popular services (for example, VirusTotal, AbuseIPDB, Shodan, Censys, SecurityTrails, GreyNoise and others).
- You can:
  - Enable or disable specific engines per IOC type.
  - Add custom services by specifying a URL template where the IOC is inserted.
  - Combine multiple services in one click via “magic” actions.

This design is intentionally flexible so new services can be added and existing ones replaced over time, without changing the way you use the extension.

---

## 3. Configuration & Personalization

### 3.1 API Keys and Usage Limits

- Many external services require an API key or account.
- In the **Options** page you can:
  - Store your keys locally in the browser (SOCx does not upload them to a central server).
  - See simple indicators of daily usage where supported (for example, how many lookups you have already performed today).
  - Test your keys to confirm that they are valid.

If a service key is missing or invalid, SOCx will skip the related checks and may show a simple warning so you can fix the configuration.

### 3.2 Choosing Default Services per IOC Type

- For each IOC type (IP, Domain, URL, Hash, Email, ASN, MAC) you can choose which tools to open when you trigger a “magic” action.
- Examples:
  - For IP addresses, you might prefer a combination of IP reputation and internet‑scanning tools.
  - For domains and URLs, you might focus on scanners, WHOIS/registration, and category‑based services.
  - For hashes, file‑analysis or malware‑repository tools are often most relevant.
- These preferences can be changed at any time and apply wherever you use the “magic” actions (context menu, floating button, popup).

### 3.3 Custom Services

- If your team has internal tools or you prefer services not included by default, you can add them as **custom services**:
  - You choose the IOC type and provide a URL template where a placeholder is replaced by the IOC.
  - Once added, these appear alongside built‑in services in your “magic” actions.
- This makes SOCx adaptable to different organizations, environments, and personal toolchains.

### 3.4 Theme and Visual Preferences

- SOCx supports dark and light modes:
  - Controlled from the popup and reused across tabs, side panel, and options.
  - Saved in the browser so your preference is remembered next time you open SOCx.

---

## 4. Privacy & Security Considerations

### 4.1 Where Data Flows

- SOCx itself:
  - Does **not** send your data to any SOCx‑controlled backend.
  - Stores configuration (API keys, preferences, history) locally in your browser.
- When you run a lookup:
  - The IOC is sent directly from your browser to the external service(s) you selected (for example, VirusTotal, AbuseIPDB, Shodan, etc.).
  - For bulk and subnet checks, the same principle applies: the data is only sent to the services you chose.

You should still be mindful of your organization’s internal policies on sending internal indicators to third‑party services.

### 4.2 Handling of Sensitive IOCs

- SOCx helps you:
  - Defang IOCs before sharing them (for example, when sending an email or updating documentation).
  - Avoid accidentally sending private IP ranges to external reputation services (private subnets can be skipped by design).
  - Export results in a format that is easy to review and redact before sharing.

### 4.3 Local Storage

- SOCx stores:
  - A limited history of recently checked IOCs (for quick recall).
  - Your notes, if you use the side panel.
  - Your configuration (keys, preferences, custom services).
- All of this remains inside your browser profile:
  - You can clear it at any time using the Options page or the browser’s extension data controls.

---

## 5. Tips & Best Practices for Non‑Technical Users

- **Start simple**
  - Begin with just one or two services (for example, VirusTotal for domains and hashes, and AbuseIPDB for IPs).
  - Add more services only when you are comfortable with the workflow.

- **Use smart formatting for reports**
  - Whenever you see a structured result (tables, “key: value” sections, JSON‑like panels), try the smart formatting option.
  - This saves time when building reports, writing tickets, or updating case notes.

- **Prefer bulk tools for large lists**
  - If you receive a long list of indicators, don’t check them one by one.
  - Paste everything into the Bulk IOC Check tab and let SOCx categorize and deduplicate them.

- **Use the side panel as your temporary notebook**
  - Keep per‑case notes in the side panel and export them when the case is closed.
  - Defang IOCs in notes if you plan to share them externally.

- **Respect quotas and rate limits**
  - Free tiers of external services often limit the number of daily lookups.
  - Keep an eye on usage indicators in the Options page or bulk tools when available.

- **Review results critically**
  - External services are decision‑support tools, not absolute truth.
  - Combine results from multiple sources with your own judgement and context.

---

## 6. Notes for Developers

Here is a short summary for developers who want to run or modify SOCx locally.

### 6.1 Technologies Used

- **Language & framework**
  - TypeScript
  - React 18
  - Plasmo (browser extension framework)
- **Styling**
  - Tailwind CSS
  - Custom utility classes for the SOCx UI
- **Extension tooling**
  - Structured messaging between background, content scripts, and UI
  - Local storage for extension settings and history
- **Build tooling**
  - Node.js (recommended 18+)
  - pnpm (package manager)

These choices may evolve over time, but the high‑level approach—React + TypeScript + Plasmo—will likely stay similar in future versions.

### 6.2 Building and Running the Extension Locally

From the root of the repository:

1. **Install dependencies**
   ```bash
   pnpm install
   ```
2. **Run in development mode**
   ```bash
   pnpm dev
   ```
   - This starts the Plasmo dev pipeline and produces a `.plasmo` folder.
   - In Chrome/Chromium, go to `chrome://extensions`, enable **Developer Mode**, click **“Load unpacked”**, and select the `.plasmo` folder.
3. **Build for production**
   ```bash
   pnpm build
   ```
   - The compiled extension will be available in the `build/` folder.
   - You can load that folder as an unpacked extension or use it as the base for packaging/distribution.

For the latest, authoritative build instructions and any project‑specific notes, see the main `README.md`.
