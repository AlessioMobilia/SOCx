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

/** Remote query text is accepted only over TLS. */
export const isAllowedPackSourceUrl = (input: string): boolean => {
  try {
    return new URL(input).protocol === "https:"
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

/** Resolve a pack path from the index against the index URL itself. */
export const resolvePackUrl = (indexUrl: string, packPath: string): string => {
  const resolved = new URL(packPath.replace(/^\.\//, ""), indexUrl)
  const index = new URL(indexUrl)
  if (resolved.protocol !== "https:" || resolved.origin !== index.origin) {
    throw new Error("pack paths must stay on the HTTPS source origin")
  }
  return resolved.toString()
}

/** Cryptographic digest used to pin every fetched file of a source. */
export const hashPackContent = async (content: string): Promise<string> => {
  const bytes = new TextEncoder().encode(content)
  const digest = await crypto.subtle.digest("SHA-256", bytes)
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("")
}
