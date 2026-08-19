import { beforeEach, describe, expect, it, vi } from "vitest"

const store = new Map<string, unknown>()

vi.mock("@plasmohq/storage", () => ({
  Storage: class {
    async get<T>(key: string): Promise<T | undefined> {
      return store.get(key) as T | undefined
    }
    async set(key: string, value: unknown): Promise<void> {
      store.set(key, value)
    }
    async remove(key: string): Promise<void> {
      store.delete(key)
    }
    async getAll(): Promise<Record<string, unknown>> {
      return Object.fromEntries(store)
    }
  }
}))

const { IOC_HISTORY_LIMIT, saveIOC } = await import("./utils")

type HistoryEntry = { type: string; text: string; timestamp: string }

const readHistory = (): HistoryEntry[] =>
  (store.get("iocHistory") as HistoryEntry[]) ?? []

describe("saveIOC", () => {
  beforeEach(() => {
    store.clear()
  })

  it("stores new indicators at the top of the history", async () => {
    await saveIOC("IP", "8.8.8.8")
    await saveIOC("Domain", "evil.com")

    expect(readHistory().map((entry) => entry.text)).toEqual([
      "evil.com",
      "8.8.8.8"
    ])
  })

  it("promotes a repeated indicator and refreshes its timestamp", async () => {
    await saveIOC("IP", "8.8.8.8")
    const firstTimestamp = readHistory()[0].timestamp
    await saveIOC("Domain", "evil.com")

    vi.setSystemTime(new Date(Date.parse(firstTimestamp) + 60_000))
    await saveIOC("IP", "8.8.8.8")
    vi.useRealTimers()

    const history = readHistory()
    expect(history.map((entry) => entry.text)).toEqual(["8.8.8.8", "evil.com"])
    expect(history).toHaveLength(2)
    expect(Date.parse(history[0].timestamp)).toBeGreaterThan(
      Date.parse(firstTimestamp)
    )
  })

  it("keeps the history within its limit", async () => {
    for (let index = 0; index < IOC_HISTORY_LIMIT + 5; index += 1) {
      await saveIOC("IP", `8.8.8.${index}`)
    }

    expect(readHistory()).toHaveLength(IOC_HISTORY_LIMIT)
  })
})
