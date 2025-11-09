import { Storage } from "@plasmohq/storage"

const themeStorage = new Storage({ area: "local" })

export const persistIsDarkMode = async (value: boolean): Promise<void> => {
  await themeStorage.set("isDarkMode", value)
  if (typeof chrome !== "undefined" && chrome.storage?.local?.set) {
    chrome.storage.local.set({ isDarkMode: value })
  }
}

export const ensureIsDarkMode = async (): Promise<boolean> => {
  const stored = await themeStorage.get<boolean>("isDarkMode")
  if (typeof stored === "boolean") {
    return stored
  }
  await persistIsDarkMode(true)
  return true
}
