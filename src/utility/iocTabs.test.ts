import { afterEach, describe, expect, it, vi } from "vitest"

import {
  buildTabGroupTitle,
  openIocTabs,
  pickTabGroupColor,
  TAB_GROUP_COLORS
} from "./iocTabs"

type CreatedTab = {
  url: string
  active?: boolean
  index?: number
  openerTabId?: number
  windowId?: number
}

const installChromeMock = ({ withGroups }: { withGroups: boolean }) => {
  const created: CreatedTab[] = []
  const grouped: { tabIds: number[] }[] = []
  const groupUpdates: { groupId: number; properties: any }[] = []
  let nextTabId = 100

  const tabs: Record<string, unknown> = {
    create: vi.fn(
      (properties: CreatedTab, callback?: (tab: { id: number }) => void) => {
        created.push(properties)
        const tab = { id: (nextTabId += 1) }
        callback?.(tab)
        return undefined
      }
    )
  }

  if (withGroups) {
    tabs.group = vi.fn(async ({ tabIds }: { tabIds: number[] }) => {
      grouped.push({ tabIds })
      return 7
    })
  }

  const chromeMock: Record<string, unknown> = {
    runtime: { lastError: undefined },
    tabs
  }

  if (withGroups) {
    chromeMock.tabGroups = {
      update: vi.fn(async (groupId: number, properties: unknown) => {
        groupUpdates.push({ groupId, properties })
      })
    }
  }

  vi.stubGlobal("chrome", chromeMock)
  return { created, grouped, groupUpdates }
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe("tab group presentation", () => {
  it("keeps the colour stable for the same indicator", () => {
    expect(pickTabGroupColor("8.8.8.8")).toBe(pickTabGroupColor("8.8.8.8"))
    expect(TAB_GROUP_COLORS).toContain(pickTabGroupColor("evil.com") as any)
  })

  it("truncates long indicators used as a group title", () => {
    expect(buildTabGroupTitle("evil.com")).toBe("evil.com")
    expect(buildTabGroupTitle("a".repeat(40))).toHaveLength(28)
  })
})

describe("openIocTabs on Chromium", () => {
  it("opens background tabs next to the opener and groups them", async () => {
    const { created, grouped, groupUpdates } = installChromeMock({
      withGroups: true
    })

    const result = await openIocTabs({
      ioc: "8.8.8.8",
      urls: ["https://a.example", "https://b.example"],
      openerTabId: 3,
      openerIndex: 4,
      windowId: 9
    })

    expect(created).toEqual([
      {
        url: "https://a.example",
        active: false,
        windowId: 9,
        openerTabId: 3,
        index: 5
      },
      {
        url: "https://b.example",
        active: false,
        windowId: 9,
        openerTabId: 3,
        index: 6
      }
    ])
    expect(result.grouped).toBe(true)
    expect(grouped).toEqual([{ tabIds: result.tabIds }])
    expect(groupUpdates[0].properties.title).toBe("8.8.8.8")
  })
})

describe("openIocTabs without tab group support", () => {
  it("still opens every tab and reports that grouping was skipped", async () => {
    const { created } = installChromeMock({ withGroups: false })

    const result = await openIocTabs({
      ioc: "evil.com",
      urls: ["https://a.example", "https://b.example"]
    })

    expect(created).toHaveLength(2)
    expect(created.every((tab) => tab.active === false)).toBe(true)
    expect(result.tabIds).toHaveLength(2)
    expect(result.grouped).toBe(false)
  })
})
