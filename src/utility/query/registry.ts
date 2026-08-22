// Assembles the query library the palette and the context menu read from:
// bundled dialects, packs cached from remote sources, and the analyst's own
// templates. Precedence is user > remote > built-in, and ids are namespaced per
// source so a remote pack can never silently shadow something local.

import { Storage } from "@plasmohq/storage"

import {
  buildPack,
  USER_QUERY_LIBRARY_KEY,
  type UserQueryTemplate
} from "./builder"
import { buildGroupTree, type GroupNode } from "./groups"
import {
  mergeLabels,
  PACK_INDEX_SCHEMA,
  validatePackIndex,
  validateQueryPack,
  type PackIndex,
  type PackIndexEntry,
  type PackKind,
  type QueryDialect,
  type QueryFacet,
  type QueryPack
} from "./packSchema"
import {
  DEFAULT_PACK_SOURCES,
  dialectSelectionTag,
  hashPackContent,
  isAllowedPackSourceUrl,
  isPlainHttpPackSourceUrl,
  isSelectedDialect,
  looksLikeHtmlResponse,
  QUERY_PACK_SOURCES_KEY,
  resolveIncludeUrl,
  resolvePackUrl,
  toRawPackUrl,
  type PackSource
} from "./packSources"
import { bundledDialectMap } from "./render"

export const QUERY_PACK_CACHE_KEY = "queryPackCache"

const storage = new Storage({ area: "local" })

export type CachedSource = {
  sourceId: string
  fetchedAt: number
  hash: string
  packs: QueryPack[]
  dialects?: QueryDialect[]
}

export type PackCache = Record<string, CachedSource>

export type FetchOutcome = {
  sourceId: string
  status: "ok" | "error" | "changed" | "html"
  message?: string
  packs?: QueryPack[]
  hash?: string
}

/**
 * The catalogue index is the authority that attests a pack as verified. Pack
 * files may repeat the flag, but older and third-party packs are allowed to
 * omit it. Only an explicit contradiction is rejected.
 */
export const applyIndexVerification = (
  entry: { id: string; verified?: boolean },
  rawPack: unknown,
  pack: QueryPack
): QueryPack => {
  if (typeof entry.verified !== "boolean") return pack

  const explicitPackValue =
    rawPack &&
    typeof rawPack === "object" &&
    Object.prototype.hasOwnProperty.call(rawPack, "verified")
      ? (rawPack as { verified?: unknown }).verified
      : undefined

  if (
    typeof explicitPackValue === "boolean" &&
    explicitPackValue !== entry.verified
  ) {
    throw new Error(`${entry.id}: verification status does not match the index`)
  }

  return { ...pack, verified: entry.verified }
}

// ------------------------------------------------------------------ settings

export const readPackSources = async (): Promise<PackSource[]> => {
  try {
    const stored = await storage.get<PackSource[]>(QUERY_PACK_SOURCES_KEY)
    if (!Array.isArray(stored) || stored.length === 0) {
      return DEFAULT_PACK_SOURCES.map((source) => ({ ...source }))
    }
    // Built-in rows are re-added when a stale profile predates them.
    const known = new Set(stored.map((source) => source.id))
    const merged = [...stored]
    for (const builtIn of DEFAULT_PACK_SOURCES) {
      if (!known.has(builtIn.id)) merged.push({ ...builtIn })
    }
    return merged
  } catch {
    return DEFAULT_PACK_SOURCES.map((source) => ({ ...source }))
  }
}

export const writePackSources = async (
  sources: PackSource[]
): Promise<void> => {
  await storage.set(QUERY_PACK_SOURCES_KEY, sources)
}

export const readUserLibrary = async (): Promise<UserQueryTemplate[]> => {
  try {
    const stored = await storage.get<UserQueryTemplate[]>(
      USER_QUERY_LIBRARY_KEY
    )
    return Array.isArray(stored) ? stored : []
  } catch {
    return []
  }
}

export const writeUserLibrary = async (
  templates: UserQueryTemplate[]
): Promise<void> => {
  await storage.set(USER_QUERY_LIBRARY_KEY, templates)
}

const readCache = async (): Promise<PackCache> => {
  try {
    return (await storage.get<PackCache>(QUERY_PACK_CACHE_KEY)) ?? {}
  } catch {
    return {}
  }
}

const writeCache = async (cache: PackCache): Promise<void> => {
  await storage.set(QUERY_PACK_CACHE_KEY, cache)
}

// ------------------------------------------------------------------- fetching

const fetchText = async (
  url: string,
  token?: string
): Promise<{ body: string; contentType: string | null }> => {
  if (!isAllowedPackSourceUrl(url)) {
    throw new Error("Query pack sources must use HTTP or HTTPS")
  }
  const headers: Record<string, string> = { Accept: "application/json" }
  if (token) {
    // GitHub wants a bearer token, GitLab its own header; both are sent because
    // the unused one is ignored by the other host.
    headers.Authorization = `Bearer ${token}`
    headers["PRIVATE-TOKEN"] = token
  }
  const response = await fetch(url, { headers })
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`)
  }
  return {
    body: await response.text(),
    contentType: response.headers.get("content-type")
  }
}

/** Guard rails for a catalogue that links to other catalogues. */
export const MAX_INDEX_DEPTH = 4
export const MAX_INDEX_FILES = 60

type IndexWalk = {
  source: PackSource
  /** Everything fetched, in fetch order: this is what the pin hashes. */
  contentParts: string[]
  visited: Set<string>
  packs: QueryPack[]
  packIds: Set<string>
  files: number
}

/**
 * Facets declared by an index apply to every pack it lists, so a SOC can name
 * its dimensions once — `customer`, `tenant`, `squad` — instead of repeating
 * them in every file. A pack's own declaration wins on the label.
 */
export const mergeFacets = (
  ...lists: (QueryFacet[] | undefined)[]
): QueryFacet[] | undefined => {
  const merged: QueryFacet[] = []
  const seen = new Set<string>()
  for (const list of lists) {
    for (const facet of list ?? []) {
      if (seen.has(facet.id)) continue
      seen.add(facet.id)
      merged.push(facet)
    }
  }
  return merged.length > 0 ? merged : undefined
}

/**
 * Applies what the catalogue knows about a file to the pack it holds: the
 * verification flag, the facet dimensions, and the labels the index attached to
 * that entry — which is how one file per customer gets tagged without touching
 * the pack itself.
 */
export const applyIndexMetadata = (
  entry: PackIndexEntry,
  rawPack: unknown,
  pack: QueryPack,
  indexFacets: (QueryFacet[] | undefined)[]
): QueryPack => {
  const verified = applyIndexVerification(entry, rawPack, pack)
  return {
    ...verified,
    facets: mergeFacets(verified.facets, ...indexFacets),
    labels: mergeLabels(entry.labels, verified.labels)
  }
}

/**
 * A plain HTTP source that cannot be reached at all is worth a hint: the server
 * may be down, but the request can also have been stopped by the browser or by
 * a policy that only allows TLS, and "Failed to fetch" alone sends the analyst
 * looking in the wrong place.
 */
export const describeFetchFailure = (error: unknown, url: string): string => {
  const message = error instanceof Error ? error.message : "fetch failed"
  if (!isPlainHttpPackSourceUrl(url) || !/fetch|network/i.test(message)) {
    return message
  }
  return `${message} — this source is plain HTTP; check that the server is reachable and that the browser is allowed to load it without TLS.`
}

/**
 * Downloads one source. A source URL may point at a single pack file, at an
 * index, or at an index that only links to other index files; all three are
 * accepted so a team can host one file, or split a large catalogue across as
 * many files as it likes.
 */
export const fetchSource = async (
  source: PackSource,
  options: { acceptChange?: boolean } = {}
): Promise<FetchOutcome> => {
  const { url } = toRawPackUrl(source.url)
  const knownDialects = new Set(bundledDialectMap().keys())

  const walkIndex = async (
    indexUrl: string,
    index: PackIndex,
    inheritedFacets: (QueryFacet[] | undefined)[],
    depth: number,
    walk: IndexWalk
  ): Promise<void> => {
    const facetChain = [index.facets, ...inheritedFacets]

    for (const entry of index.packs) {
      if (entry.kind !== walk.source.kind) continue
      // The index names the language of every file, so an unselected technology
      // is never downloaded in the first place.
      if (!isSelectedDialect(walk.source, entry.dialect)) continue
      if (walk.files >= MAX_INDEX_FILES) {
        throw new Error(
          `catalogue is larger than ${MAX_INDEX_FILES} files; split it into separate sources`
        )
      }
      const packUrl = resolvePackUrl(indexUrl, entry.path)
      if (walk.visited.has(packUrl)) continue
      walk.visited.add(packUrl)
      walk.files += 1

      const packBody = await fetchText(packUrl, walk.source.token)
      if (looksLikeHtmlResponse(packBody.body, packBody.contentType)) {
        throw new Error(`${entry.id} returned HTML instead of JSON`)
      }
      const rawPack = JSON.parse(packBody.body)
      const pack = validateQueryPack(rawPack, { knownDialects })
      if (!pack.ok) {
        throw new Error(
          `${entry.id}: ${pack.errors[0]?.message ?? "invalid pack"}`
        )
      }
      if (pack.value.id !== entry.id || pack.value.kind !== entry.kind) {
        throw new Error(`${entry.id}: index metadata does not match the pack`)
      }
      if (
        typeof entry.templates === "number" &&
        entry.templates !== pack.value.templates.length
      ) {
        throw new Error(`${entry.id}: template count does not match the index`)
      }
      // Checked again on the file itself: an index may omit the dialect, a pack
      // never does.
      if (!isSelectedDialect(walk.source, pack.value.dialect)) continue
      // Ids are namespaced per source, not per file, so two files of the same
      // catalogue claiming one id would make their templates indistinguishable.
      if (walk.packIds.has(pack.value.id)) {
        throw new Error(
          `${entry.id}: this catalogue declares the pack id twice`
        )
      }
      walk.packIds.add(pack.value.id)
      walk.contentParts.push(`pack:${packUrl}\n${packBody.body}`)
      walk.packs.push(
        applyIndexMetadata(entry, rawPack, pack.value, facetChain)
      )
    }

    if ((index.includes ?? []).length === 0) return
    if (depth >= MAX_INDEX_DEPTH) {
      throw new Error(
        `included indexes are nested deeper than ${MAX_INDEX_DEPTH} levels`
      )
    }

    for (const reference of index.includes ?? []) {
      if (walk.files >= MAX_INDEX_FILES) {
        throw new Error(
          `catalogue is larger than ${MAX_INDEX_FILES} files; split it into separate sources`
        )
      }
      const includedUrl = resolveIncludeUrl(indexUrl, reference)
      // A diamond in the include graph is a mistake, not a failure.
      if (walk.visited.has(includedUrl)) continue
      walk.visited.add(includedUrl)
      walk.files += 1

      const included = await fetchText(includedUrl, walk.source.token)
      if (looksLikeHtmlResponse(included.body, included.contentType)) {
        throw new Error(`${reference} returned HTML instead of JSON`)
      }
      walk.contentParts.push(`index:${includedUrl}\n${included.body}`)
      const parsedInclude = JSON.parse(included.body)

      // An include may name another index or, for convenience, a pack file.
      if (parsedInclude?.schema === PACK_INDEX_SCHEMA) {
        const nested = validatePackIndex(parsedInclude)
        if (!nested.ok) {
          throw new Error(
            `${reference}: ${nested.errors[0]?.message ?? "invalid index"}`
          )
        }
        await walkIndex(includedUrl, nested.value, facetChain, depth + 1, walk)
        continue
      }

      const pack = validateQueryPack(parsedInclude, { knownDialects })
      if (!pack.ok) {
        throw new Error(
          `${reference}: ${pack.errors[0]?.message ?? "invalid pack or index"}`
        )
      }
      if (pack.value.kind !== walk.source.kind) continue
      if (!isSelectedDialect(walk.source, pack.value.dialect)) continue
      if (walk.packIds.has(pack.value.id)) {
        throw new Error(
          `${reference}: this catalogue declares the pack id twice`
        )
      }
      walk.packIds.add(pack.value.id)
      walk.packs.push({
        ...pack.value,
        facets: mergeFacets(pack.value.facets, ...facetChain)
      })
    }
  }

  try {
    const { body, contentType } = await fetchText(url, source.token)

    if (looksLikeHtmlResponse(body, contentType)) {
      return {
        sourceId: source.id,
        status: "html",
        message:
          "The URL returned a web page rather than a pack file. Use the raw link."
      }
    }

    const parsed = JSON.parse(body)
    const packs: QueryPack[] = []
    const contentParts = [`source:${url}\n${body}`]

    if (parsed?.schema === PACK_INDEX_SCHEMA) {
      const index = validatePackIndex(parsed)
      if (!index.ok) {
        return {
          sourceId: source.id,
          status: "error",
          message: index.errors[0]?.message ?? "invalid index"
        }
      }

      const walk: IndexWalk = {
        source,
        contentParts,
        visited: new Set([url]),
        packs,
        packIds: new Set<string>(),
        files: 1
      }

      try {
        await walkIndex(url, index.value, [], 0, walk)
      } catch (error) {
        // Keep serving the previously accepted cache instead of adopting a
        // catalogue that is silently missing one of its declared packs.
        return {
          sourceId: source.id,
          status: "error",
          message:
            error instanceof Error ? error.message : "Unable to load the index"
        }
      }
    } else {
      const pack = validateQueryPack(parsed, { knownDialects })
      if (!pack.ok) {
        return {
          sourceId: source.id,
          status: "error",
          message: pack.errors[0]?.message ?? "invalid pack"
        }
      }
      if (pack.value.kind !== source.kind) {
        return {
          sourceId: source.id,
          status: "error",
          message: `This file holds ${pack.value.kind} queries; add it to the other list.`
        }
      }
      if (!isSelectedDialect(source, pack.value.dialect)) {
        return {
          sourceId: source.id,
          status: "error",
          message: `This file holds ${pack.value.dialect} queries, which this source is set not to import.`
        }
      }
      packs.push(pack.value)
    }

    if (packs.length === 0) {
      return {
        sourceId: source.id,
        status: "error",
        message: `The source contains no ${source.kind} query pack.`
      }
    }

    // The selection is part of what was imported, so narrowing or widening it
    // re-pins the source instead of silently reusing the old fingerprint.
    contentParts.push(`dialects:${dialectSelectionTag(source)}`)
    const hash = await hashPackContent(contentParts.join("\n\n"))
    if (
      source.pinnedHash &&
      source.pinnedHash !== hash &&
      !options.acceptChange
    ) {
      return {
        sourceId: source.id,
        status: "changed",
        hash,
        message: "The source changed since it was last accepted."
      }
    }

    const cache = await readCache()
    cache[source.id] = {
      sourceId: source.id,
      fetchedAt: Date.now(),
      hash,
      packs
    }
    await writeCache(cache)

    return { sourceId: source.id, status: "ok", packs, hash }
  } catch (error) {
    return {
      sourceId: source.id,
      status: "error",
      message: describeFetchFailure(error, url)
    }
  }
}

export const refreshAllSources = async (
  options: { acceptChange?: boolean } = {}
): Promise<FetchOutcome[]> => {
  const sources = await readPackSources()
  const outcomes: FetchOutcome[] = []
  for (const source of sources) {
    if (!source.enabled) continue
    outcomes.push(await fetchSource(source, options))
  }
  const bySource = new Map(
    outcomes.map((outcome) => [outcome.sourceId, outcome])
  )
  await writePackSources(
    sources.map((source) => {
      const outcome = bySource.get(source.id)
      if (!outcome) return source
      return {
        ...source,
        lastFetched: Date.now(),
        lastStatus:
          outcome.status === "ok"
            ? "ok"
            : outcome.status === "changed"
              ? "changed"
              : "error",
        pinnedHash: outcome.status === "ok" ? outcome.hash : source.pinnedHash,
        packCount:
          outcome.status === "ok" ? outcome.packs?.length : source.packCount
      }
    })
  )
  return outcomes
}

// ------------------------------------------------------------------ assembling

export type QueryLibrary = {
  packs: QueryPack[]
  dialects: Map<string, QueryDialect>
  tree: GroupNode[]
}

/**
 * Personal templates are wrapped in a synthetic pack so that everything
 * downstream — grouping, rendering, the palette — sees one uniform shape.
 */
export const userLibraryToPacks = (
  templates: UserQueryTemplate[]
): QueryPack[] => {
  const packs: QueryPack[] = []
  const knownDialects = new Set(bundledDialectMap().keys())

  for (const template of templates) {
    const kind = template.kind
    const built = buildPack(
      [template],
      kind,
      {
        id: `my-query-${template.id}`,
        name: kind === "ioc" ? "My IOC queries" : "My hunting queries",
        description: "Templates saved in this browser."
      },
      { knownDialects }
    )
    if (built.ok) {
      packs.push({
        ...built.pack,
        sourceId: "user",
        sourceLabel: "My queries",
        sourceBuiltIn: false
      })
    }
  }

  return packs
}

export const loadLibrary = async (
  filter: { kind?: PackKind } = {}
): Promise<QueryLibrary> => {
  const [cache, userTemplates, sources] = await Promise.all([
    readCache(),
    readUserLibrary(),
    readPackSources()
  ])

  const bySourceId = new Map(sources.map((source) => [source.id, source]))
  const remotePacks: QueryPack[] = []
  for (const cached of Object.values(cache)) {
    const source = bySourceId.get(cached.sourceId)
    if (!source || !source.enabled) continue
    remotePacks.push(
      ...cached.packs
        // Narrowing the technology selection takes effect at once, without
        // waiting for the next refresh to prune the cache.
        .filter((pack) => isSelectedDialect(source, pack.dialect))
        .map((pack) => ({
          ...pack,
          sourceId: cached.sourceId,
          sourceLabel: source.label?.trim() || source.url,
          sourceBuiltIn: source.builtIn === true
        }))
    )
  }

  // Packs retain their source namespace; equal ids from two team catalogues do
  // not shadow each other, and personal templates stay alongside community
  // templates with the same id.
  const all = [...remotePacks, ...userLibraryToPacks(userTemplates)]
  const packs = all.filter((pack) => !filter.kind || pack.kind === filter.kind)

  return {
    packs,
    dialects: bundledDialectMap(),
    tree: buildGroupTree(packs)
  }
}

// -------------------------------------------------------- platform matching

export type PlatformMatch = {
  pack: QueryPack
  score: number
}

const hostMatches = (hostname: string, candidate: string): boolean =>
  hostname === candidate || hostname.endsWith(`.${candidate}`)

/**
 * Path hints are always matched case insensitively. A leading `(?i)` written by
 * an author used to PCRE is stripped rather than allowed to throw: JavaScript
 * has no inline flags, so the pattern would silently never match.
 */
const NESTED_QUANTIFIER = /\([^)]*[*+][^)]*\)\s*(?:[*+]|\{\d)/

export const buildSafeMatchPattern = (pattern: string, flags = ""): RegExp => {
  if (pattern.length > 500 || NESTED_QUANTIFIER.test(pattern)) {
    throw new Error("unsafe or oversized URL match pattern")
  }
  return new RegExp(pattern, flags)
}

export const buildPathHint = (pattern: string): RegExp =>
  buildSafeMatchPattern(pattern.replace(/^\(\?i\)/, ""), "i")

/**
 * Which packs belong to the page currently open. Hostname alone is not enough:
 * Sentinel lives inside the Azure portal next to everything else, hence the
 * optional path hint.
 */
export const matchPacksForUrl = (
  packs: QueryPack[],
  pageUrl: string
): PlatformMatch[] => {
  let url: URL
  try {
    url = new URL(pageUrl.slice(0, 8192))
  } catch {
    return []
  }

  const matches: PlatformMatch[] = []
  for (const pack of packs) {
    const hostnames = pack.match?.hostnames ?? []
    const patterns = pack.match?.urlPatterns ?? []

    let score = 0
    if (hostnames.some((candidate) => hostMatches(url.hostname, candidate))) {
      score += 2
    }
    if (
      patterns.some((pattern) => {
        try {
          return buildSafeMatchPattern(pattern).test(pageUrl.slice(0, 8192))
        } catch {
          return false
        }
      })
    ) {
      score += 2
    }
    if (score > 0 && pack.match?.pathHint) {
      try {
        // The hash is part of the route on single page consoles: the Azure
        // portal puts the whole Sentinel path after the # sign.
        const route = `${url.pathname}${url.search}${url.hash}`.slice(0, 8192)
        if (!buildPathHint(pack.match.pathHint).test(route)) {
          continue
        }
        score += 1
      } catch {
        // A malformed hint is ignored rather than fatal.
      }
    }

    if (score > 0) {
      matches.push({ pack, score })
    }
  }

  return matches.sort((a, b) => b.score - a.score)
}
