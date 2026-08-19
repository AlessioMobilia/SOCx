// src/background/messages/magic-ioc-request.ts
import type { PlasmoMessaging } from "@plasmohq/messaging"

import {
  extractIOCs,
  identifyIOC,
  saveIOC,
  showNotification
} from "../../utility/utils"
import { runMagicIoc } from "../magic-ioc"

console.log("[Plasmo] MagicIOCRequest handler loaded")

const handler: PlasmoMessaging.MessageHandler = async (req, res) => {
  const ioc = extractIOCs(req.body.IOC)?.[0]
  const type = identifyIOC(ioc)

  if (!ioc || !type) {
    showNotification("Error", "Invalid IOC.")
    return res.send({ error: true })
  }

  await saveIOC(type, ioc)

  const senderTab = req.sender?.tab
  const { opened, cancelled } = await runMagicIoc({
    ioc,
    type,
    tabId: senderTab?.id,
    tabIndex: senderTab?.index,
    windowId: senderTab?.windowId
  })

  res.send({ done: true, opened, cancelled })
}

export default handler
