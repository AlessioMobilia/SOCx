import { describe, expect, it } from "vitest"

import {
  buildQueryMenuDefinitions,
  MAX_MENU_TEMPLATES,
  parseQueryMenuId,
  patternsForPack,
  QUERY_MENU_PREFIX,
  QUERY_MENU_ROOT
} from "../../background/query-menus"
import { buildGroupTree } from "./groups"
import { validateQueryPack, type QueryPack } from "./packSchema"
import { entriesFromTree, fuzzyScore, rankEntries } from "./palette"
import {
  buildSafeMatchPattern,
  matchPacksForUrl,
  userLibraryToPacks
} from "./registry"
import { bundledDialectMap } from "./render"

const knownDialects = new Set(bundledDialectMap().keys())

const makePack = (overrides: Record<string, unknown> = {}): QueryPack => {
  const result = validateQueryPack(
    {
      schema: "socx.querypack/v1",
      id: "defender-pack",
      kind: "ioc",
      name: "Defender",
      dialect: "kql",
      match: { hostnames: ["security.microsoft.com"] },
      groups: [
        {
          id: "network",
          label: "Network",
          order: 10,
          children: [{ id: "egress", label: "Egress" }]
        }
      ],
      templates: [
        {
          id: "connections",
          name: "Network connections",
          group: "network/egress",
          byType: { IP: { field: "RemoteIP", op: "in~" } },
          body: "| where {{field}} {{op}} ({{iocs}})"
        }
      ],
      ...overrides
    },
    { knownDialects }
  )
  if (!result.ok) {
    throw new Error(result.errors.map((error) => error.message).join("; "))
  }
  return result.value
}

describe("platform matching", () => {
  it("matches a console by hostname", () => {
    const packs = [makePack()]
    expect(
      matchPacksForUrl(packs, "https://security.microsoft.com/v2/hunting")
    ).toHaveLength(1)
    expect(matchPacksForUrl(packs, "https://example.com/")).toHaveLength(0)
  })

  it("uses the path hint to separate products sharing a host", () => {
    const sentinel = makePack({
      id: "sentinel-pack",
      name: "Sentinel",
      match: { hostnames: ["portal.azure.com"], pathHint: "(?i)sentinel" }
    })
    const other = makePack({
      id: "other-azure",
      name: "Other",
      match: { hostnames: ["portal.azure.com"] }
    })

    const onSentinel = matchPacksForUrl(
      [sentinel, other],
      "https://portal.azure.com/#view/Microsoft_Azure_Security_Insights/sentinel"
    )
    expect(onSentinel[0].pack.id).toBe("sentinel-pack")

    const elsewhere = matchPacksForUrl(
      [sentinel, other],
      "https://portal.azure.com/#view/HubsExtension/BrowseAll"
    )
    expect(elsewhere[0].pack.id).toBe("other-azure")
    expect(elsewhere.map((match) => match.pack.id)).not.toContain(
      "sentinel-pack"
    )
  })

  it("matches a self hosted console through a URL pattern", () => {
    const pack = makePack({
      id: "internal-splunk",
      match: { urlPatterns: ["^https?://splunk\\.corp\\.local(:\\d+)?/"] }
    })
    expect(
      matchPacksForUrl([pack], "http://splunk.corp.local:8000/app/search")
    ).toHaveLength(1)
  })

  it("ignores a malformed pattern instead of throwing", () => {
    const pack = makePack({ match: { urlPatterns: ["([unclosed"] } })
    expect(matchPacksForUrl([pack], "https://example.com")).toHaveLength(0)
  })

  it("rejects URL patterns with nested quantifiers", () => {
    expect(() => buildSafeMatchPattern("^(a+)+$")).toThrow(/unsafe/)
  })
})

describe("context menu definitions", () => {
  it("builds a two level menu with the console URL patterns", () => {
    const packs = [makePack()]
    const definitions = buildQueryMenuDefinitions(packs, buildGroupTree(packs))

    const root = definitions.find((entry) => entry.id === QUERY_MENU_ROOT)
    expect(root?.contexts).toEqual(["page", "editable", "selection"])

    const leaf = definitions.find((entry) =>
      String(entry.id).endsWith("::connections")
    )
    expect(leaf?.documentUrlPatterns).toContain(
      "*://*.security.microsoft.com/*"
    )
    // Group, then template, both under the root.
    expect(String(leaf?.parentId)).toContain("group:")
  })

  it("shows personal templates on every page", () => {
    const packs = userLibraryToPacks([
      {
        id: "mine",
        name: "My query",
        dialect: "kql",
        kind: "ioc",
        group: "network",
        byType: { IP: { field: "RemoteIP", op: "in~" } },
        body: "| where {{field}} {{op}} ({{iocs}})",
        createdAt: "",
        updatedAt: ""
      }
    ])
    const definitions = buildQueryMenuDefinitions(packs, buildGroupTree(packs))
    const leaf = definitions.find((entry) =>
      String(entry.id).endsWith("::mine")
    )
    expect(leaf?.documentUrlPatterns).toBeUndefined()
  })

  it("caps how many templates reach the menu", () => {
    const templates = Array.from({ length: 60 }, (_, index) => ({
      id: `t-${index}`,
      name: `Template ${index}`,
      group: "network/egress",
      byType: { IP: { field: "RemoteIP", op: "in~" } },
      body: "| where {{field}} {{op}} ({{iocs}})"
    }))
    const packs = [makePack({ templates })]
    const definitions = buildQueryMenuDefinitions(packs, buildGroupTree(packs))
    const leaves = definitions.filter(
      (entry) =>
        String(entry.id).startsWith(QUERY_MENU_PREFIX) &&
        !String(entry.id).includes("group:")
    )
    expect(leaves).toHaveLength(MAX_MENU_TEMPLATES)
  })

  it("returns nothing when there is no pack", () => {
    expect(buildQueryMenuDefinitions([], [])).toEqual([])
  })

  it("recognises its own menu ids", () => {
    expect(parseQueryMenuId(`${QUERY_MENU_PREFIX}pack::template`)).toBe(
      "pack::template"
    )
    expect(
      parseQueryMenuId(`${QUERY_MENU_PREFIX}group:root:network`)
    ).toBeNull()
    expect(parseQueryMenuId("MagicIOC")).toBeNull()
  })

  it("derives host patterns that cover subdomains", () => {
    expect(patternsForPack(makePack())).toEqual([
      "*://*.security.microsoft.com/*",
      "*://security.microsoft.com/*"
    ])
  })

  it("does not pass runtime regular expressions to browser menu patterns", () => {
    const pack = makePack({
      match: {
        hostnames: ["security.microsoft.com"],
        urlPatterns: ["^https?://internal\\.example/"]
      }
    })
    expect(patternsForPack(pack)).toEqual([
      "*://*.security.microsoft.com/*",
      "*://security.microsoft.com/*"
    ])
  })

  it("namespaces equal pack ids by source", () => {
    const first = { ...makePack(), sourceId: "source-a" }
    const second = { ...makePack(), sourceId: "source-b" }
    const entries = entriesFromTree(buildGroupTree([first, second]))
    expect(new Set(entries.map((entry) => entry.key)).size).toBe(2)
  })
})

describe("palette ranking", () => {
  const entries = entriesFromTree(
    buildGroupTree([
      makePack({
        templates: [
          {
            id: "connections",
            name: "Network connections",
            group: "network/egress",
            tags: ["c2"],
            byType: { IP: { field: "RemoteIP", op: "in~" } },
            body: "| where {{field}} {{op}} ({{iocs}})"
          },
          {
            id: "failed-logons",
            name: "Failed logons",
            group: "network",
            byType: { IP: { field: "IPAddress", op: "in~" } },
            body: "| where {{field}} {{op}} ({{iocs}})"
          }
        ]
      })
    ])
  )

  it("prefers a direct substring over a scattered match", () => {
    expect(fuzzyScore("Network connections", "conn")).toBeGreaterThan(
      fuzzyScore("Failed logons", "conn")
    )
  })

  it("filters by name, tag and group", () => {
    expect(rankEntries(entries, "logon")[0].template.id).toBe("failed-logons")
    expect(rankEntries(entries, "c2")[0].template.id).toBe("connections")
    expect(rankEntries(entries, "egress")[0].template.id).toBe("connections")
    expect(rankEntries(entries, "zzzz")).toHaveLength(0)
  })

  it("returns everything for an empty query", () => {
    expect(rankEntries(entries, "  ")).toHaveLength(entries.length)
  })
})
