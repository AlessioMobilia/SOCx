import { extractIOCs, identifyIOC } from "../utils"
import type { RenderedIndicator } from "./render"
import { toBindableType } from "./render"

export type QueryWorkspaceLaunch = {
  indicators: string[]
  templateKey?: string
}

export const parseQueryWorkspaceHash = (hash: string): QueryWorkspaceLaunch => {
  const params = new URLSearchParams(hash.replace(/^#/, ""))
  return {
    indicators: (params.get("iocs") ?? "")
      .split("\n")
      .map((value) => value.trim())
      .filter(Boolean),
    templateKey: params.get("template") || undefined
  }
}

export const toWorkspaceIndicators = (text: string): RenderedIndicator[] => {
  const seen = new Set<string>()
  return (extractIOCs(text) ?? [])
    .map((value) => {
      const type = toBindableType(identifyIOC(value), value)
      return type ? { value, type } : null
    })
    .filter((entry): entry is RenderedIndicator => {
      if (!entry || seen.has(entry.value)) return false
      seen.add(entry.value)
      return true
    })
}
