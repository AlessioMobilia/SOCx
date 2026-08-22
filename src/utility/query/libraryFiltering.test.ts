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

const { loadLibrary, QUERY_PACK_CACHE_KEY } = await import("./registry")
const { QUERY_PACK_SOURCES_KEY } = await import("./packSources")

const pack = (id: string, dialect: string) => ({
  schema: "socx.querypack/v1",
  id,
  kind: "ioc",
  name: id,
  dialect,
  templates: [
    {
      id: "t",
      name: "T",
      requiresIocs: true,
      byType: { IP: { field: "f", op: "in" } },
      body: "| where {{field}} {{op}} ({{iocs}})"
    }
  ]
})

const seed = (dialects?: string[]) => {
  store.clear()
  store.set(QUERY_PACK_SOURCES_KEY, [
    {
      id: "team",
      label: "Security team catalogue",
      url: "https://example.test/index.json",
      kind: "ioc",
      enabled: true,
      dialects
    }
  ])
  store.set(QUERY_PACK_CACHE_KEY, {
    team: {
      sourceId: "team",
      fetchedAt: 0,
      hash: "x",
      packs: [pack("kql-pack", "kql"), pack("spl-pack", "spl")]
    }
  })
}

const loadedPackIds = async () =>
  (await loadLibrary()).packs.map((entry) => entry.id).sort()

describe("technology selection applied to the library", () => {
  beforeEach(() => store.clear())

  it("serves every cached pack when nothing is selected", async () => {
    seed(undefined)
    expect(await loadedPackIds()).toEqual(["kql-pack", "spl-pack"])
    seed([])
    expect(await loadedPackIds()).toEqual(["kql-pack", "spl-pack"])
  })

  it("attaches the configured source identity to every loaded pack", async () => {
    seed()
    const loaded = await loadLibrary()

    expect(loaded.packs).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          sourceId: "team",
          sourceLabel: "Security team catalogue",
          sourceBuiltIn: false
        })
      ])
    )
  })

  it("hides the languages the source no longer imports", async () => {
    seed(["kql"])
    expect(await loadedPackIds()).toEqual(["kql-pack"])
  })

  it("brings a language back as soon as it is selected again", async () => {
    seed(["kql"])
    expect(await loadedPackIds()).toEqual(["kql-pack"])

    // Widening the selection must not wait for a refresh when the pack is
    // still in the cache.
    store.set(QUERY_PACK_SOURCES_KEY, [
      {
        id: "team",
        url: "https://example.test/index.json",
        kind: "ioc",
        enabled: true,
        dialects: ["kql", "spl"]
      }
    ])
    expect(await loadedPackIds()).toEqual(["kql-pack", "spl-pack"])
  })

  it("keeps a disabled source out regardless of its selection", async () => {
    seed(["kql"])
    store.set(QUERY_PACK_SOURCES_KEY, [
      {
        id: "team",
        url: "https://example.test/index.json",
        kind: "ioc",
        enabled: false,
        dialects: ["kql"]
      }
    ])
    expect(await loadedPackIds()).toEqual([])
  })
})
