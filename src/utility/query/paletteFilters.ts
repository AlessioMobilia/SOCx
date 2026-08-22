// Ranking and faceted filtering shared by the in-page palette and the query
// workspace tab.
//
// A community catalogue is several hundred templates, so the palette is never
// meant to be read as one long list: the analyst narrows it down by kind
// (indicator hunt or hunting playbook), by query language, by source, by group,
// by any custom dimension the repository declares — a customer, a tenant, a
// squad — or by the shortlist they starred, and only then reads what is left.
// Every function here is pure so the two surfaces filter identically and the
// behaviour can be tested without a DOM.

import { UNCATEGORISED_LABEL } from "./groups"
import {
  mergeLabels,
  type FacetLabels,
  type PackKind,
  type QueryFacet,
  type QueryPack,
  type QueryTemplate
} from "./packSchema"

export type FilterableEntry = {
  key: string
  template: QueryTemplate
  pack: QueryPack
  path: string[]
}

export type PaletteFilterState = {
  search: string
  favoritesOnly: boolean
  kind: "all" | PackKind
  /** Dialect id, or `all`. */
  dialect: string
  /** Source id, or `all`. Built-in community catalogues share one value. */
  source: string
  /** Top level group label, or `all`. */
  group: string
  /** Custom facet id to the selected value; a missing key means "any". */
  labels: Record<string, string>
}

export type FacetOption = {
  value: string
  label: string
  title?: string
  count: number
}

export type CustomFacet = {
  id: string
  label: string
  description?: string
  options: FacetOption[]
}

export type PaletteFacets = {
  kinds: FacetOption[]
  dialects: FacetOption[]
  sources: FacetOption[]
  groups: FacetOption[]
  custom: CustomFacet[]
  /** How many of the currently visible queries are starred. */
  favorites: number
}

export const ALL_FILTERS: PaletteFilterState = {
  search: "",
  favoritesOnly: false,
  kind: "all",
  dialect: "all",
  source: "all",
  group: "all",
  labels: {}
}

export const FAVORITES_LABEL = "Favorites"

export const KIND_LABELS: Record<PackKind, string> = {
  ioc: "IOC",
  standard: "Hunting"
}

const titleCase = (value: string): string =>
  value
    .split("-")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ")

// ------------------------------------------------------------------ ranking

/** Subsequence match, the same feel as an editor command palette. */
export const fuzzyScore = (haystack: string, needle: string): number => {
  if (!needle) return 1
  const target = haystack.toLowerCase()
  const query = needle.toLowerCase()

  const direct = target.indexOf(query)
  if (direct >= 0) return 1000 - direct

  let score = 0
  let cursor = 0
  for (const character of query) {
    const found = target.indexOf(character, cursor)
    if (found < 0) return 0
    score += found === cursor ? 3 : 1
    cursor = found + 1
  }
  return score
}

// Searching re-scores the whole catalogue on every keystroke, and the facet
// counts do it several times over, so the two haystacks of a template are built
// once and kept for as long as the template object lives.
const metadataCache = new WeakMap<QueryTemplate, string>()
const queryCache = new WeakMap<QueryTemplate, string>()

/** Name, description, group, pack, tags and custom labels. */
export const metadataHaystack = (entry: FilterableEntry): string => {
  const cached = metadataCache.get(entry.template)
  if (cached !== undefined) return cached
  const haystack = [
    entry.template.name,
    entry.template.description ?? "",
    entry.path.join(" "),
    entry.pack.name,
    entry.pack.sourceLabel ?? "",
    entry.pack.vendor ?? "",
    (entry.template.tags ?? []).join(" "),
    Object.values(resolveEntryLabels(entry)).flat().join(" ")
  ]
    .join(" ")
    .toLowerCase()
  metadataCache.set(entry.template, haystack)
  return haystack
}

/**
 * Everything the query itself is made of: the statement, the fields and tables
 * it binds per indicator type, the operators, the ATT&CK references. Searching
 * for `RemoteIP`, `DeviceProcessEvents` or `T1059` has to find the templates
 * that actually contain them, not just the ones that mention them by name.
 */
export const queryHaystack = (entry: FilterableEntry): string => {
  const cached = queryCache.get(entry.template)
  if (cached !== undefined) return cached
  const bindings = Object.entries(entry.template.byType ?? {}).flatMap(
    ([type, binding]) => [
      type,
      binding?.table ?? "",
      binding?.field ?? "",
      binding?.op ?? "",
      binding?.suffix ?? "",
      binding?.note ?? ""
    ]
  )
  const haystack = [
    entry.template.body,
    entry.template.open ?? "",
    entry.template.reference ?? "",
    (entry.template.mitre ?? []).join(" "),
    entryDialect(entry),
    ...bindings
  ]
    .join(" ")
    .toLowerCase()
  queryCache.set(entry.template, haystack)
  return haystack
}

const MAX_SEARCH_TERMS = 6

/**
 * Scoring is tiered so precision survives the deep search: a literal hit in the
 * name or description outranks a literal hit inside the query text, which in
 * turn outranks a scattered subsequence match. Space separated terms all have
 * to match, which is what makes `acme lateral` a usable search.
 */
export const scoreEntry = (entry: FilterableEntry, query: string): number => {
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean)
  if (terms.length === 0) return 1

  // Both haystacks are already lowercased by their builders.
  const metadata = metadataHaystack(entry)
  const deep = queryHaystack(entry)
  let total = 0

  for (const term of terms.slice(0, MAX_SEARCH_TERMS)) {
    const metadataIndex = metadata.indexOf(term)
    if (metadataIndex >= 0) {
      total += 3000 - Math.min(metadataIndex, 900)
      continue
    }
    const deepIndex = deep.indexOf(term)
    if (deepIndex >= 0) {
      total += 2000 - Math.min(deepIndex, 900)
      continue
    }
    const scattered = fuzzyScore(metadata, term)
    if (scattered <= 0) return 0
    total += scattered
  }

  return total
}

export const rankEntries = <T extends FilterableEntry>(
  entries: T[],
  query: string
): T[] => {
  if (!query.trim()) {
    return entries
  }
  return entries
    .map((entry) => ({ entry, score: scoreEntry(entry, query) }))
    .filter((row) => row.score > 0)
    .sort((a, b) => b.score - a.score)
    .map((row) => row.entry)
}

// ------------------------------------------------------------------- facets

export const entryDialect = (entry: FilterableEntry): string =>
  (entry.template.dialect ?? entry.pack.dialect ?? "").trim() || "unknown"

export const entryGroup = (entry: FilterableEntry): string =>
  entry.path[0]?.trim() || UNCATEGORISED_LABEL

const COMMUNITY_SOURCE_KEY = "socx-community"

export const querySourceKey = (pack: QueryPack): string => {
  if (pack.sourceBuiltIn === true) return COMMUNITY_SOURCE_KEY
  return pack.sourceId?.trim() || "local"
}

export const entrySourceKey = (entry: FilterableEntry): string =>
  querySourceKey(entry.pack)

export const querySourceLabel = (pack: QueryPack): string => {
  if (pack.sourceBuiltIn === true) return "SOCx community packs"
  if (pack.sourceId === "user") return "My queries"
  return pack.sourceLabel?.trim() || titleCase(pack.sourceId ?? "local")
}

/** Pack wide labels plus the template's own, which is how one file per customer works. */
export const resolveEntryLabels = (entry: FilterableEntry): FacetLabels =>
  mergeLabels(entry.pack.labels, entry.template.labels) ?? {}

/**
 * Dialect ids are what an analyst recognises on a chip — `KQL`, `SPL`, `XQL` —
 * while the catalogue label ("Kusto Query Language (Microsoft)") is far too
 * long for one. The label is kept as the tooltip instead.
 */
export const dialectChipLabel = (dialectId: string): string =>
  dialectId === "unknown" ? "Other" : dialectId.toUpperCase()

/**
 * The custom dimensions the visible packs declare. A label used by a template
 * whose facet nobody declared is not dropped — the same rule the group tree
 * follows — so a typo in a pack cannot make a filter disappear.
 */
export const collectFacetDefinitions = (
  entries: FilterableEntry[]
): QueryFacet[] => {
  const declared = new Map<string, QueryFacet>()
  const seenPacks = new Set<QueryPack>()
  const used = new Set<string>()

  for (const entry of entries) {
    if (!seenPacks.has(entry.pack)) {
      seenPacks.add(entry.pack)
      for (const facet of entry.pack.facets ?? []) {
        if (!declared.has(facet.id)) declared.set(facet.id, facet)
      }
    }
    for (const facetId of Object.keys(resolveEntryLabels(entry))) {
      used.add(facetId)
    }
  }

  const facets = [...used].map(
    (id) => declared.get(id) ?? { id, label: titleCase(id) }
  )
  return facets.sort(
    (a, b) =>
      (a.order ?? Number.MAX_SAFE_INTEGER) -
        (b.order ?? Number.MAX_SAFE_INTEGER) || a.label.localeCompare(b.label)
  )
}

type IgnorableFacet =
  | "kind"
  | "dialect"
  | "source"
  | "group"
  | "favorites"
  | `label:${string}`

const matchesFacets = (
  entry: FilterableEntry,
  state: PaletteFilterState,
  favorites: string[],
  ignore?: IgnorableFacet
): boolean => {
  if (
    ignore !== "kind" &&
    state.kind !== "all" &&
    entry.pack.kind !== state.kind
  ) {
    return false
  }
  if (
    ignore !== "dialect" &&
    state.dialect !== "all" &&
    entryDialect(entry) !== state.dialect
  ) {
    return false
  }
  if (
    ignore !== "source" &&
    state.source !== "all" &&
    entrySourceKey(entry) !== state.source
  ) {
    return false
  }
  if (
    ignore !== "group" &&
    state.group !== "all" &&
    entryGroup(entry) !== state.group
  ) {
    return false
  }
  if (
    ignore !== "favorites" &&
    state.favoritesOnly &&
    !favorites.includes(entry.key)
  ) {
    return false
  }

  const labels = resolveEntryLabels(entry)
  for (const [facetId, value] of Object.entries(state.labels ?? {})) {
    if (!value || value === "all" || ignore === labelFacetKey(facetId)) continue
    if (!(labels[facetId] ?? []).includes(value)) return false
  }
  return true
}

/** Cross filtering key for a custom facet, kept distinct from the built-in ones. */
export const labelFacetKey = (facetId: string): `label:${string}` =>
  `label:${facetId}`

/**
 * Starred queries are hoisted to the top of the result list, in the order they
 * were starred, so the shortlist is always the first thing under the cursor.
 */
export const partitionFavorites = <T extends FilterableEntry>(
  entries: T[],
  favorites: string[]
): { starred: T[]; rest: T[] } => {
  const rank = new Map(favorites.map((key, index) => [key, index]))
  const starred = entries
    .filter((entry) => rank.has(entry.key))
    .sort((a, b) => (rank.get(a.key) ?? 0) - (rank.get(b.key) ?? 0))
  const rest = entries.filter((entry) => !rank.has(entry.key))
  return { starred, rest }
}

export const filterEntries = <T extends FilterableEntry>(
  entries: T[],
  state: PaletteFilterState,
  favorites: string[] = [],
  ignore?: IgnorableFacet
): T[] =>
  rankEntries(
    entries.filter((entry) => matchesFacets(entry, state, favorites, ignore)),
    state.search
  )

/** Filtered list in display order: starred first, then everything else. */
export const applyPaletteFilters = <T extends FilterableEntry>(
  entries: T[],
  state: PaletteFilterState,
  favorites: string[] = []
): { entries: T[]; favoriteCount: number } => {
  const { starred, rest } = partitionFavorites(
    filterEntries(entries, state, favorites),
    favorites
  )
  return { entries: [...starred, ...rest], favoriteCount: starred.length }
}

/**
 * Options are built from every value the library holds, not only from the ones
 * that survive the current filters: a filter that vanishes as soon as you click
 * elsewhere is a filter nobody can reason about. Values with no match are kept
 * and simply counted zero, and the order never changes while you type.
 */
const toOptions = (
  universe: Map<string, number>,
  counts: Map<string, number>,
  label: (value: string) => string,
  title?: (value: string) => string | undefined,
  order?: string[]
): FacetOption[] => {
  const options = [...universe.keys()].map((value) => ({
    value,
    label: label(value),
    title: title?.(value),
    count: counts.get(value) ?? 0
  }))
  if (order) {
    return options.sort(
      (a, b) => order.indexOf(a.value) - order.indexOf(b.value)
    )
  }
  return options.sort((a, b) => a.label.localeCompare(b.label))
}

const countBy = <T>(entries: T[], pick: (entry: T) => string) => {
  const counts = new Map<string, number>()
  for (const entry of entries) {
    const value = pick(entry)
    counts.set(value, (counts.get(value) ?? 0) + 1)
  }
  return counts
}

const countLabels = (entries: FilterableEntry[], facetId: string) => {
  const counts = new Map<string, number>()
  for (const entry of entries) {
    for (const value of resolveEntryLabels(entry)[facetId] ?? []) {
      counts.set(value, (counts.get(value) ?? 0) + 1)
    }
  }
  return counts
}

/**
 * Counts are cross filtered: each facet is counted against the entries that
 * pass every *other* facet, so switching from KQL to SPL always shows a live
 * number instead of a dead end.
 */
export const buildFacets = (
  entries: FilterableEntry[],
  state: PaletteFilterState,
  favorites: string[] = [],
  dialectLabels?: Map<string, string>
): PaletteFacets => {
  const sourcesByKey = new Map(
    entries.map((entry) => [entrySourceKey(entry), entry.pack] as const)
  )
  const kinds = countBy(
    filterEntries(entries, state, favorites, "kind"),
    (entry) => entry.pack.kind
  )
  const dialects = countBy(
    filterEntries(entries, state, favorites, "dialect"),
    entryDialect
  )
  const groups = countBy(
    filterEntries(entries, state, favorites, "group"),
    entryGroup
  )
  const sources = countBy(
    filterEntries(entries, state, favorites, "source"),
    entrySourceKey
  )
  const favoriteCount = filterEntries(
    entries,
    state,
    favorites,
    "favorites"
  ).filter((entry) => favorites.includes(entry.key)).length

  const custom = collectFacetDefinitions(entries)
    .map((facet) => ({
      id: facet.id,
      label: facet.label,
      description: facet.description,
      options: toOptions(
        countLabels(entries, facet.id),
        countLabels(
          filterEntries(entries, state, favorites, labelFacetKey(facet.id)),
          facet.id
        ),
        (value) => value
      )
    }))
    .filter((facet) => facet.options.length > 0)

  // The two libraries are a closed set, not something discovered in the data:
  // both are always offered, even when the enabled packs only cover one of
  // them, so the control never changes shape between one console and the next.
  const kindUniverse = new Map<string, number>([
    ["ioc", 0],
    ["standard", 0]
  ])

  return {
    kinds: toOptions(
      kindUniverse,
      kinds,
      (value) => KIND_LABELS[value as PackKind] ?? value,
      undefined,
      ["ioc", "standard"]
    ),
    dialects: toOptions(
      countBy(entries, entryDialect),
      dialects,
      dialectChipLabel,
      (value) => dialectLabels?.get(value)
    ),
    sources: toOptions(
      countBy(entries, entrySourceKey),
      sources,
      (value) => {
        const pack = sourcesByKey.get(value)
        return pack ? querySourceLabel(pack) : value
      },
      (value) => {
        const pack = sourcesByKey.get(value)
        return pack ? querySourceLabel(pack) : value
      }
    ),
    groups: toOptions(countBy(entries, entryGroup), groups, (value) => value),
    custom,
    favorites: favoriteCount
  }
}

export const hasActiveFilters = (state: PaletteFilterState): boolean =>
  state.favoritesOnly ||
  state.kind !== "all" ||
  state.dialect !== "all" ||
  state.source !== "all" ||
  state.group !== "all" ||
  state.search.trim().length > 0 ||
  Object.values(state.labels ?? {}).some((value) => value && value !== "all")
