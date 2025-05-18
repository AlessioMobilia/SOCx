// src/background/messages/magic-ioc-request.ts
import type { PlasmoMessaging } from "@plasmohq/messaging"
import { extractIOCs, identifyIOC, saveIOC, showNotification } from "../../utility/utils"
import { servicesConfig } from "../../utility/servicesConfig"
import { defaultServices } from "../../utility/defaultServices"
import { Storage } from "@plasmohq/storage"

const storage = new Storage({ area: "local" })
console.log("[Plasmo] MagicIOCRequest handler loaded")

type CustomService = {
  name: string
  type: string
  url: string
}

const handler: PlasmoMessaging.MessageHandler = async (req, res) => {
  const ioc = extractIOCs(req.body.IOC)?.[0]
  const type = identifyIOC(ioc)

  if (!ioc || !type) {
    showNotification("Error", "Invalid IOC.")
    return res.send({ error: true })
  }

  await saveIOC(type, ioc)

  const selected = await storage.get("selectedServices") ?? defaultServices
  const rawCustom = await storage.get("customServices")
  const customServices: CustomService[] = Array.isArray(rawCustom) ? rawCustom : []

    // Predefined services
    if (selected[type]) {
    selected[type].forEach((service: string) => {
        const config = servicesConfig.services[service]
        if (config?.supportedTypes.includes(type)) {
        const url = config.url(type, ioc)
        chrome.tabs.create({ url })
        }
    })
    }

    // Custom services
    const customForType = customServices.filter((s) => s.type === type)
    customForType.forEach((service) => {
    if (service.url.includes("{ioc}")) {
        const finalUrl = service.url.replace("{ioc}", encodeURIComponent(ioc))
        chrome.tabs.create({ url: finalUrl })
    }
    })

  res.send({ done: true })
}

export default handler
