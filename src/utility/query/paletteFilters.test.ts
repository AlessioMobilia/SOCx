import { describe, expect, it } from "vitest"

import { buildGroupTree } from "./groups"
import { validateQueryPack, type QueryPack } from "./packSchema"
import { entriesFromTree } from "./palette"
import {
  ALL_FILTERS,
  applyPaletteFilters,
  buildFacets,
  collectFacetDefinitions,
  dialectChipLabel,
  rankEntries,
  resolveEntryLabels,
  type PaletteFilterState
} from "./paletteFilters"
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
      groups: [{ id: "network", label: "Network" }],
      templates: [
        {
          id: "connections",
          name: "Network connections",
          description: "Outbound sessions towards the indicators",
          group: "network",
          byType: { IP: { field: "RemoteIP", op: "in~" } },
          body: "DeviceNetworkEvents | where {{field}} {{op}} ({{iocs}})"
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

const splunkPack = makePack({
  id: "splunk-pack",
  name: "Splunk",
  dialect: "spl",
  groups: [{ id: "identity", label: "Identity" }],
  facets: [{ id: "customer", label: "Customer" }],
  labels: { customer: "ACME" },
  templates: [
    {
      id: "logons",
      name: "Failed logons",
      description: "Authentication failures per account",
      group: "identity",
      labels: { customer: ["Globex"] },
      byType: { IP: { field: "src_ip", op: "IN" } },
      body: "index=auth src_ip IN ({{iocs}})"
    }
  ]
})

const entries = entriesFromTree(
  buildGroupTree([
    { ...makePack(), sourceId: "a" },
    { ...splunkPack, sourceId: "b" }
  ])
)

const withFilters = (
  patch: Partial<PaletteFilterState>
): PaletteFilterState => ({
  ...ALL_FILTERS,
  labels: {},
  ...patch
})

describe("deep search", () => {
  it("finds a template by a field name that only appears inside the query", () => {
    const found = rankEntries(entries, "DeviceNetworkEvents")
    expect(found).toHaveLength(1)
    expect(found[0].template.id).toBe("connections")
  })

  it("finds a template by its description", () => {
    expect(rankEntries(entries, "Authentication failures")[0].template.id).toBe(
      "logons"
    )
  })

  it("ranks a name match above a match inside the query text", () => {
    const ranked = rankEntries(entries, "src_ip")
    expect(ranked[0].template.id).toBe("logons")
  })

  it("requires every space separated term to match", () => {
    expect(rankEntries(entries, "logons Globex")).toHaveLength(1)
    expect(rankEntries(entries, "logons Initech")).toHaveLength(0)
  })

  it("still returns everything for an empty query", () => {
    expect(rankEntries(entries, "   ")).toHaveLength(entries.length)
  })
})

describe("custom facets", () => {
  it("merges pack wide labels with the template's own", () => {
    const entry = entries.find((row) => row.template.id === "logons")!
    expect(resolveEntryLabels(entry).customer).toEqual(["ACME", "Globex"])
  })

  it("collects the dimensions the packs declare", () => {
    expect(collectFacetDefinitions(entries)).toEqual([
      { id: "customer", label: "Customer" }
    ])
  })

  it("filters on a declared label", () => {
    const outcome = applyPaletteFilters(
      entries,
      withFilters({ labels: { customer: "Globex" } })
    )
    expect(outcome.entries.map((entry) => entry.template.id)).toEqual([
      "logons"
    ])
  })

  it("offers every value of a facet even while one is selected", () => {
    const facets = buildFacets(
      entries,
      withFilters({ labels: { customer: "Globex" } })
    )
    expect(
      facets.custom[0].options.map((option) => option.value).sort()
    ).toEqual(["ACME", "Globex"])
  })
})

describe("built-in facets", () => {
  it("keeps every option on screen and moves the counts instead", () => {
    const facets = buildFacets(entries, withFilters({ dialect: "spl" }))
    expect(facets.dialects.map((option) => option.value).sort()).toEqual([
      "kql",
      "spl"
    ])
    // The categories of the other language stay listed, counting zero, so the
    // filter row never rearranges itself under the pointer.
    expect(facets.groups).toEqual([
      { value: "Identity", label: "Identity", title: undefined, count: 1 },
      { value: "Network", label: "Network", title: undefined, count: 0 }
    ])
  })

  it("orders the two libraries before anything else", () => {
    const facets = buildFacets(entries, withFilters({}))
    expect(facets.kinds.map((option) => option.value)).toEqual([
      "ioc",
      "standard"
    ])
  })

  it("keeps only the selected language in the result list", () => {
    const outcome = applyPaletteFilters(
      entries,
      withFilters({ dialect: "kql" })
    )
    expect(outcome.entries.map((entry) => entry.template.id)).toEqual([
      "connections"
    ])
  })

  it("labels a dialect chip with its id", () => {
    expect(dialectChipLabel("es-kql")).toBe("ES-KQL")
    expect(dialectChipLabel("unknown")).toBe("Other")
  })
})

describe("favorites", () => {
  const favoriteKey = entries.find(
    (entry) => entry.template.id === "logons"
  )!.key

  it("hoists starred queries to the top", () => {
    const outcome = applyPaletteFilters(entries, withFilters({}), [favoriteKey])
    expect(outcome.favoriteCount).toBe(1)
    expect(outcome.entries[0].template.id).toBe("logons")
  })

  it("restricts the list when the favorites filter is on", () => {
    const outcome = applyPaletteFilters(
      entries,
      withFilters({ favoritesOnly: true }),
      [favoriteKey]
    )
    expect(outcome.entries.map((entry) => entry.template.id)).toEqual([
      "logons"
    ])
  })

  it("counts the starred entries that pass the other filters", () => {
    const facets = buildFacets(entries, withFilters({ dialect: "kql" }), [
      favoriteKey
    ])
    expect(facets.favorites).toBe(0)
  })
})
