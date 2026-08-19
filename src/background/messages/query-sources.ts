// Source management for query packs: list, add, refresh, accept a changed
// source, remove. The fetch has to happen in the background because that is the
// context host permissions apply to.

import type { PlasmoMessaging } from "@plasmohq/messaging"

import {
  isAllowedPackSourceUrl,
  toRawPackUrl,
  type PackSource
} from "../../utility/query/packSources"
import {
  fetchSource,
  readPackSources,
  writePackSources
} from "../../utility/query/registry"

export type QuerySourcesRequest =
  | { action: "list" }
  | { action: "add"; source: Omit<PackSource, "id"> & { id?: string } }
  | { action: "update"; id: string; patch: Partial<PackSource> }
  | { action: "remove"; id: string }
  | { action: "refresh"; id?: string; acceptChange?: boolean }

export type QuerySourcesResponse = {
  sources: PackSource[]
  outcomes?: {
    sourceId: string
    status: string
    message?: string
    packCount?: number
    hash?: string
  }[]
  error?: string
}

const newId = (label: string): string =>
  `${
    label
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 40) || "source"
  }-${Date.now().toString(36)}`

const handler: PlasmoMessaging.MessageHandler<
  QuerySourcesRequest,
  QuerySourcesResponse
> = async (req, res) => {
  const body = req.body
  let sources = await readPackSources()

  if (!body || body.action === "list") {
    res.send({ sources })
    return
  }

  if (body.action === "add") {
    const rewritten = toRawPackUrl(body.source.url)
    if (!isAllowedPackSourceUrl(rewritten.url)) {
      res.send({
        sources,
        error: "Query pack sources must use a valid HTTPS URL."
      })
      return
    }
    const source: PackSource = {
      ...body.source,
      id: body.source.id ?? newId(body.source.label ?? body.source.kind),
      url: rewritten.url,
      enabled: body.source.enabled !== false,
      lastStatus: "never"
    }
    sources = [...sources, source]
    await writePackSources(sources)

    const outcome = await fetchSource(source)
    sources = sources.map((entry) =>
      entry.id === source.id
        ? {
            ...entry,
            lastStatus: outcome.status === "ok" ? "ok" : "error",
            lastFetched: Date.now(),
            pinnedHash:
              outcome.status === "ok" ? outcome.hash : entry.pinnedHash,
            packCount:
              outcome.status === "ok" ? outcome.packs?.length : entry.packCount
          }
        : entry
    )
    await writePackSources(sources)

    res.send({
      sources,
      outcomes: [
        {
          sourceId: source.id,
          status: outcome.status,
          message:
            outcome.message ??
            (rewritten.rewritten ? rewritten.reason : undefined),
          packCount: outcome.packs?.length,
          hash: outcome.hash
        }
      ]
    })
    return
  }

  if (body.action === "update") {
    sources = sources.map((source) =>
      source.id === body.id ? { ...source, ...body.patch } : source
    )
    await writePackSources(sources)
    res.send({ sources })
    return
  }

  if (body.action === "remove") {
    const target = sources.find((source) => source.id === body.id)
    if (target?.builtIn) {
      // Built-in rows are disabled rather than deleted, so the default
      // catalogue can always be switched back on.
      sources = sources.map((source) =>
        source.id === body.id ? { ...source, enabled: false } : source
      )
    } else {
      sources = sources.filter((source) => source.id !== body.id)
    }
    await writePackSources(sources)
    res.send({ sources })
    return
  }

  if (body.action === "refresh") {
    const targets = body.id
      ? sources.filter((source) => source.id === body.id)
      : sources.filter((source) => source.enabled)

    const outcomes = []
    for (const source of targets) {
      const outcome = await fetchSource(source, {
        acceptChange: body.acceptChange
      })
      outcomes.push({
        sourceId: source.id,
        status: outcome.status,
        message: outcome.message,
        packCount: outcome.packs?.length,
        hash: outcome.hash
      })
      sources = sources.map((entry) =>
        entry.id === source.id
          ? {
              ...entry,
              lastFetched: Date.now(),
              lastStatus:
                outcome.status === "ok"
                  ? "ok"
                  : outcome.status === "changed"
                    ? "changed"
                    : "error",
              // Only an accepted fetch moves the pin forward.
              pinnedHash:
                outcome.status === "ok" ? outcome.hash : entry.pinnedHash,
              packCount:
                outcome.status === "ok"
                  ? outcome.packs?.length
                  : entry.packCount
            }
          : entry
      )
    }
    await writePackSources(sources)
    res.send({ sources, outcomes })
    return
  }

  res.send({ sources, error: "unknown action" })
}

export default handler
