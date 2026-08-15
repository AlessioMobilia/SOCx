import type { PlasmoCSConfig } from "plasmo"

import { Storage } from "@plasmohq/storage"

import {
  resolveServicePageCopyButtonsPreference,
  SELECTION_BUTTONS_KEY,
  SERVICE_PAGE_COPY_BUTTONS_KEY,
  SERVICE_PAGE_COPY_BUTTONS_MESSAGE
} from "../utility/buttonPreferences"
import { writeIntelClipboardText } from "../utility/clipboard"
import {
  mountServiceCopyButton,
  type ServiceCopyButtonController
} from "../utility/serviceCopyButton"
import {
  resolveServicePage,
  type ResolvedServicePage
} from "../utility/servicePageAdapters"
import {
  extractServicePageFields,
  formatServicePageReport,
  isServicePageReady
} from "../utility/servicePageIntel"

export const config: PlasmoCSConfig = {
  matches: [
    "https://www.virustotal.com/gui/*",
    "https://www.abuseipdb.com/check/*",
    "https://search.censys.io/*",
    "https://www.ipqualityscore.com/*",
    "https://ipinfo.io/*",
    "https://otx.alienvault.com/*",
    "https://exchange.xforce.ibmcloud.com/*",
    "https://mxtoolbox.com/*",
    "https://www.mxtoolbox.com/*",
    "https://pulsedive.com/*",
    "https://spur.us/*",
    "https://passivedns.mnemonic.no/*",
    "https://hunter.io/*",
    "https://www.shodan.io/*",
    "https://securitytrails.com/*",
    "https://urlscan.io/*",
    "https://haveibeenpwned.com/unifiedsearch/*",
    "https://api.macvendors.com/*",
    "https://www.wireshark.org/*",
    "https://viz.greynoise.io/*",
    "https://bazaar.abuse.ch/*",
    "https://www.robtex.com/*",
    "https://bgp.he.net/*",
    "https://tria.ge/*",
    "https://threatfox.abuse.ch/*",
    "https://viewdns.info/*",
    "https://www.viewdns.info/*",
    "https://talosintelligence.com/*",
    "https://www.talosintelligence.com/*",
    "https://urlhaus.abuse.ch/*",
    "https://check.spamhaus.org/*",
    "https://stat.ripe.net/*",
    "https://radar.cloudflare.com/*",
    "https://threatminer.org/*",
    "https://www.threatminer.org/*",
    "https://crt.sh/*",
    "https://hashlookup.circl.lu/*"
  ]
}

const storage = new Storage({ area: "local" })
let enabled = true
let mountedButton: ServiceCopyButtonController | null = null
let mountedPageKey = ""

const copyCurrentPage = async (page: ResolvedServicePage): Promise<boolean> => {
  const currentPage = resolveServicePage(window.location.href)
  if (!currentPage || currentPage.adapter.id !== page.adapter.id) return false

  const fields = extractServicePageFields(currentPage)
  const report = formatServicePageReport({
    page: currentPage,
    fields,
    sourceUrl: window.location.href
  })
  const result = await writeIntelClipboardText(report, {
    successMessage: `✔️ ${currentPage.adapter.label} data copied`,
    errorMessage: `❌ Unable to copy ${currentPage.adapter.label} data`
  })
  return result.success
}

const syncButton = (): void => {
  const page =
    enabled && isServicePageReady()
      ? resolveServicePage(window.location.href)
      : null
  const pageKey = page ? `${page.adapter.id}:${page.ioc}` : ""
  const existingHost = document.querySelector("[data-socx-service-copy]")

  if (!page) {
    mountedButton?.remove()
    mountedButton = null
    mountedPageKey = ""
    return
  }

  if (pageKey === mountedPageKey && existingHost) return
  mountedButton?.remove()
  mountedButton = mountServiceCopyButton({
    page,
    onCopy: () => copyCurrentPage(page)
  })
  mountedPageKey = pageKey
}

const start = async (): Promise<void> => {
  try {
    const preferences = await storage.getMany([
      SERVICE_PAGE_COPY_BUTTONS_KEY,
      SELECTION_BUTTONS_KEY
    ])
    enabled = resolveServicePageCopyButtonsPreference(
      preferences[SERVICE_PAGE_COPY_BUTTONS_KEY],
      preferences[SELECTION_BUTTONS_KEY]
    )
  } catch {
    enabled = true
  }
  syncButton()
  window.setInterval(syncButton, 1_000)
}

if (typeof chrome !== "undefined" && chrome.runtime?.onMessage) {
  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type !== SERVICE_PAGE_COPY_BUTTONS_MESSAGE) return
    enabled = message.enabled !== false
    syncButton()
  })
}

if (typeof chrome !== "undefined" && chrome.storage?.onChanged) {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== "local") return
    const change = changes[SERVICE_PAGE_COPY_BUTTONS_KEY]
    if (typeof change?.newValue !== "boolean") return
    enabled = change.newValue
    syncButton()
  })
}

void start()
