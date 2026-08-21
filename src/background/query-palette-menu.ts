import { OPEN_QUERY_PALETTE_MESSAGE } from "../utility/query/paletteBridge"

type QueryPaletteMenuDependencies = {
  sendMessage: (
    tabId: number,
    message: {
      name: string
      body: { indicators: string[]; templateKey?: string }
    },
    callback: (response?: { opened?: boolean }) => void
  ) => void
  getLastError: () => unknown
  openWorkspace: (indicators: string[]) => Promise<unknown> | unknown
}

/** Opens in-page when possible and preserves a usable standalone fallback. */
export const openQueryPaletteFromMenu = async (
  tabId: number | undefined,
  indicators: string[],
  templateKey: string | undefined,
  dependencies: QueryPaletteMenuDependencies
): Promise<"palette" | "workspace"> => {
  if (typeof tabId !== "number") {
    await dependencies.openWorkspace(indicators)
    return "workspace"
  }

  return new Promise((resolve) => {
    const fallback = () =>
      Promise.resolve(dependencies.openWorkspace(indicators)).then(() =>
        resolve("workspace")
      )
    try {
      dependencies.sendMessage(
        tabId,
        {
          name: OPEN_QUERY_PALETTE_MESSAGE,
          body: { indicators, templateKey }
        },
        (response) => {
          if (!dependencies.getLastError() && response?.opened === true) {
            resolve("palette")
            return
          }
          void fallback()
        }
      )
    } catch {
      void fallback()
    }
  })
}
