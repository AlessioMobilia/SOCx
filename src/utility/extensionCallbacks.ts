export type ExtensionRuntimeError = { message?: string }

/**
 * Wraps the callback form shared by Chromium and Firefox's `chrome.*` API.
 * Firefox MV2 does not return the Promises exposed by Chromium MV3 typings.
 */
export const callExtensionCallback = <T>(
  invoke: (callback: (value: T) => void) => void,
  readLastError: () => ExtensionRuntimeError | undefined
): Promise<T> =>
  new Promise<T>((resolve, reject) => {
    try {
      invoke((value) => {
        const error = readLastError()
        if (error) {
          reject(new Error(error.message || "Browser extension API failed"))
          return
        }
        resolve(value)
      })
    } catch (error) {
      reject(error)
    }
  })

/** Uses the tab supplied by `commands.onCommand`, querying only as fallback. */
export const resolveActiveTab = async <T>(
  commandTab: T | undefined,
  queryActiveTabs: (callback: (tabs: T[]) => void) => void,
  readLastError: () => ExtensionRuntimeError | undefined
): Promise<T | undefined> => {
  if (commandTab) return commandTab
  const tabs = await callExtensionCallback(queryActiveTabs, readLastError)
  return tabs[0]
}
