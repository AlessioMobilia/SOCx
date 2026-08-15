import type { PlasmoMessaging } from "@plasmohq/messaging"

import { clearApiResponseCache } from "../../utility/requestCoordinator"

const handler: PlasmoMessaging.MessageHandler = async (_req, res) => {
  try {
    await clearApiResponseCache()
    res.send({ success: true })
  } catch (error) {
    console.error("Unable to clear API response cache:", error)
    res.send({ success: false })
  }
}

export default handler
