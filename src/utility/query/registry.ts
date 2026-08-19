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
  validatePackIndex,
  validateQueryPack,
  type PackKind,
  type QueryDialect,
  type QueryPack
} from "./packSchema"
import {
  DEFAULT_PACK_SOURCES,
  hashPackContent,
  isAllowedPackSourceUrl,
  looksLikeHtmlResponse,
  QUERY_PACK_SOURCES_KEY,
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
    throw new Error("Query pack sources must use HTTPS")
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

/**
 * Downloads one source. A source URL may point either at an index or at a
 * single pack file; both are accepted so a team can host one file without
 * building a catalogue.
 */
export const fetchSource = async (
  source: PackSource,
  options: { acceptChange?: boolean } = {}
): Promise<FetchOutcome> => {
  const { url } = toRawPackUrl(source.url)
  const knownDialects = new Set(bundledDialectMap().keys())

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

    if (parsed?.schema === "socx.packindex/v1") {
      const index = validatePackIndex(parsed)
      if (!index.ok) {
        return {
          sourceId: source.id,
          status: "error",
          message: index.errors[0]?.message ?? "invalid index"
        }
      }

      for (const entry of index.value.packs) {
        if (entry.kind !== source.kind) continue
        try {
          const packUrl = resolvePackUrl(url, entry.path)
          const packBody = await fetchText(packUrl, source.token)
          if (looksLikeHtmlResponse(packBody.body, packBody.contentType)) {
            throw new Error(`${entry.id} returned HTML instead of JSON`)
          }
          const rawPack = JSON.parse(packBody.body)
          const pack = validateQueryPack(rawPack, {
            knownDialects
          })
          if (!pack.ok) {
            throw new Error(
              `${entry.id}: ${pack.errors[0]?.message ?? "invalid pack"}`
            )
          }
          if (pack.value.id !== entry.id || pack.value.kind !== entry.kind) {
            throw new Error(
              `${entry.id}: index metadata does not match the pack`
            )
          }
          if (
            typeof entry.templates === "number" &&
            entry.templates !== pack.value.templates.length
          ) {
            throw new Error(
              `${entry.id}: template count does not match the index`
            )
          }
          const indexedPack = applyIndexVerification(entry, rawPack, pack.value)
          contentParts.push(`pack:${packUrl}\n${packBody.body}`)
          packs.push(indexedPack)
        } catch (error) {
          // Keep serving the previously accepted cache instead of adopting a
          // catalogue that is silently missing one of its declared packs.
          return {
            sourceId: source.id,
            status: "error",
            message:
              error instanceof Error
                ? error.message
                : `Unable to load ${entry.id}`
          }
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
      packs.push(pack.value)
    }

    if (packs.length === 0) {
      return {
        sourceId: source.id,
        status: "error",
        message: `The source contains no ${source.kind} query pack.`
      }
    }

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
      message: error instanceof Error ? error.message : "fetch failed"
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
      packs.push({ ...built.pack, sourceId: "user" })
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

  const enabled = new Set(
    sources.filter((source) => source.enabled).map((source) => source.id)
  )

  const remotePacks: QueryPack[] = []
  for (const cached of Object.values(cache)) {
    if (!enabled.has(cached.sourceId)) continue
    remotePacks.push(
      ...cached.packs.map((pack) => ({ ...pack, sourceId: cached.sourceId }))
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
