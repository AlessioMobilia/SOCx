// Where query packs come from, and how a pasted repository link is turned into
// something the extension can actually fetch.

import type { PackKind } from "./packSchema"

export const QUERY_PACK_SOURCES_KEY = "queryPackSources"

export type PackSource = {
  id: string
  url: string
  kind: PackKind
  enabled: boolean
  label?: string
  builtIn?: boolean
  /** Personal access token header value, for private repositories. */
  token?: string
  /**
   * Dialect ids to import from this source. Empty or missing means "every
   * technology": a SOC that only runs Defender and Splunk selects those two and
   * never downloads the other twenty packs.
   */
  dialects?: string[]
  /** Content hash of the last accepted version, used to detect changes. */
  pinnedHash?: string
  lastFetched?: number
  lastStatus?: "ok" | "error" | "changed" | "never"
  packCount?: number
  /** Hosts the analyst approved for this source's `open` templates. */
  allowedOpenHosts?: string[]
}

const REPO = "https://raw.githubusercontent.com/AlessioMobilia/socx-query-packs"
const BRANCH = "main"

/**
 * Preconfigured catalogue. Both entries point at the same index because the
 * index itself declares the kind of every pack; keeping two rows lets the
 * analyst enable indicator packs and hunting playbooks independently, which is
 * how the two settings sections are laid out.
 */
export const DEFAULT_PACK_SOURCES: PackSource[] = [
  {
    id: "socx-community-ioc",
    url: `${REPO}/${BRANCH}/index.json`,
    kind: "ioc",
    enabled: true,
    builtIn: true,
    label: "SOCx community packs — IOC hunting",
    lastStatus: "never"
  },
  {
    id: "socx-community-standard",
    url: `${REPO}/${BRANCH}/index.json`,
    kind: "standard",
    enabled: true,
    builtIn: true,
    label: "SOCx community packs — hunting playbooks",
    lastStatus: "never"
  }
]

export const QUERY_PACK_REPOSITORY =
  "https://github.com/AlessioMobilia/socx-query-packs"

/**
 * Whether a pack written in `dialect` is part of what this source imports.
 * An unknown dialect is always kept: the decision is then taken again on the
 * pack file itself, which is the only place that always names its language.
 */
export const isSelectedDialect = (
  source: Pick<PackSource, "dialects">,
  dialect?: string
): boolean => {
  const selection = source.dialects
  if (!Array.isArray(selection) || selection.length === 0) return true
  if (!dialect || dialect === "unknown") return true
  return selection.includes(dialect)
}

/** Stable fingerprint of the selection, so a change re-pins the source. */
export const dialectSelectionTag = (
  source: Pick<PackSource, "dialects">
): string =>
  Array.isArray(source.dialects) && source.dialects.length > 0
    ? [...source.dialects].sort().join(",")
    : "all"

/**
 * Schemes a pack source may be fetched over. TLS is what a public catalogue
 * should use, but an internal repository is often published by a plain HTTP
 * server on the corporate network, so `http:` is accepted as well and flagged
 * to the analyst instead of being refused.
 */
const PACK_SOURCE_PROTOCOLS = ["https:", "http:"]

export const isAllowedPackSourceUrl = (input: string): boolean => {
  try {
    return PACK_SOURCE_PROTOCOLS.includes(new URL(input).protocol)
  } catch {
    return false
  }
}

/**
 * A source fetched in clear text: the query text can be read and rewritten in
 * transit, so every surface that shows a source says so.
 */
export const isPlainHttpPackSourceUrl = (input: string): boolean => {
  try {
    return new URL(input).protocol === "http:"
  } catch {
    return false
  }
}

// ---------------------------------------------------------------- URL rewrite

export type RewriteResult = {
  url: string
  rewritten: boolean
  reason?: string
}

const GITHUB_BLOB =
  /^https?:\/\/github\.com\/([^/]+)\/([^/]+)\/(?:blob|raw)\/([^/]+)\/(.+)$/i
const GITHUB_GIST = /^https?:\/\/gist\.github\.com\/([^/]+)\/([0-9a-f]+)\/?$/i
// Path based so that a self hosted GitLab is handled exactly like gitlab.com.
const GITLAB_BLOB = /^(https?:\/\/[^/]+\/.+?)\/-\/blob\/(.+)$/i

/**
 * Turns a link copied from a browser address bar into the raw file URL. Pasting
 * a `blob` link is the mistake every user makes on the first attempt, and the
 * page it returns is HTML rather than JSON.
 */
export const toRawPackUrl = (input: string): RewriteResult => {
  const url = input.trim()
  if (!url) {
    return { url, rewritten: false }
  }

  const github = url.match(GITHUB_BLOB)
  if (github) {
    const [, owner, repo, ref, path] = github
    return {
      url: `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${path}`,
      rewritten: true,
      reason: "GitHub blob link rewritten to its raw form"
    }
  }

  const gist = url.match(GITHUB_GIST)
  if (gist) {
    const [, user, id] = gist
    return {
      url: `https://gist.githubusercontent.com/${user}/${id}/raw`,
      rewritten: true,
      reason: "Gist link rewritten to its raw form"
    }
  }

  const gitlab = url.match(GITLAB_BLOB)
  if (gitlab) {
    const [, base, rest] = gitlab
    return {
      url: `${base}/-/raw/${rest}`,
      rewritten: true,
      reason: "GitLab blob link rewritten to its raw form"
    }
  }

  return { url, rewritten: false }
}

/**
 * A response that is clearly a web page rather than a pack. Reported as its own
 * case so the UI can suggest the raw URL instead of saying "invalid JSON".
 */
export const looksLikeHtmlResponse = (
  body: string,
  contentType?: string | null
): boolean => {
  if (contentType && /text\/html/i.test(contentType)) return true
  return /^\s*<(!doctype|html)\b/i.test(body)
}

/**
 * Resolve a pack path from the index against the index URL itself. The origin
 * check carries the scheme with it, so an HTTPS catalogue can never be talked
 * into reading its packs over plain HTTP, and the other way round.
 */
export const resolvePackUrl = (indexUrl: string, packPath: string): string => {
  const resolved = new URL(packPath.replace(/^\.\//, ""), indexUrl)
  const index = new URL(indexUrl)
  if (
    !PACK_SOURCE_PROTOCOLS.includes(resolved.protocol) ||
    resolved.origin !== index.origin
  ) {
    throw new Error("pack paths must stay on the source origin")
  }
  return resolved.toString()
}

/**
 * Resolve an entry of an index `includes` list. A relative path stays on the
 * origin of the index that referenced it, exactly like a pack path; an absolute
 * URL is allowed so a catalogue can point at a file hosted elsewhere, over
 * HTTPS or over the plain HTTP of an internal server — and the whole tree is
 * content hashed, so a change anywhere still has to be re-accepted before it is
 * used.
 */
export const resolveIncludeUrl = (
  indexUrl: string,
  reference: string
): string => {
  const trimmed = reference.trim()
  if (/^https?:\/\//i.test(trimmed)) {
    return toRawPackUrl(trimmed).url
  }
  if (/^[a-z]+:/i.test(trimmed)) {
    throw new Error("included indexes must use HTTP or HTTPS")
  }
  return resolvePackUrl(indexUrl, trimmed)
}

/** Cryptographic digest used to pin every fetched file of a source. */
export const hashPackContent = async (content: string): Promise<string> => {
  const bytes = new TextEncoder().encode(content)
  const digest = await crypto.subtle.digest("SHA-256", bytes)
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("")
}
