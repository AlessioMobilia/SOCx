// Context menu entries for the query palette.
//
// The per platform filtering is done by the browser: every entry carries the
// `documentUrlPatterns` of the console its pack declares, so a Splunk submenu
// simply does not exist on the Defender page. Entries live in the `editable`
// context, which is exactly the search bar of a hunting console, plus the
// `selection` context for indicator driven queries.

import { buildGroupTree, type GroupNode } from "../utility/query/groups"
import type { QueryPack } from "../utility/query/packSchema"
import { loadLibrary } from "../utility/query/registry"
import { SOCX_MENU_ROOT, type ContextMenuApi } from "./menus"

export const QUERY_MENU_ROOT = "socxQueryRoot"
export const QUERY_MENU_PREFIX = "socxQuery:"
export const QUERY_MENU_OPEN_ALL = "socxQueryOpenAll"

/** Beyond this a context menu stops being faster than the palette. */
export const MAX_MENU_TEMPLATES = 24

const hostPattern = (hostname: string): string => `*://*.${hostname}/*`

export const patternsForPack = (pack: QueryPack): string[] => {
  const patterns: string[] = []
  for (const hostname of pack.match?.hostnames ?? []) {
    if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(hostname)) {
      continue
    }
    patterns.push(hostPattern(hostname), `*://${hostname}/*`)
  }
  // `urlPatterns` are regular expressions used by runtime matching, not Web
  // Extension match patterns. Passing them to documentUrlPatterns makes the
  // browser reject the menu item.
  return patterns
}

export type QueryMenuDefinition = chrome.contextMenus.CreateProperties

/**
 * Builds a two level menu: SOCx › Insert query › Group › Query. Only the packs
 * that declare a console get URL patterns; personal packs are shown everywhere
 * because an analyst must reach their own queries from any page.
 */
export const buildQueryMenuDefinitions = (
  packs: QueryPack[],
  tree: GroupNode[]
): QueryMenuDefinition[] => {
  if (packs.length === 0) return []

  const definitions: QueryMenuDefinition[] = [
    {
      id: QUERY_MENU_ROOT,
      title: "Insert query",
      parentId: SOCX_MENU_ROOT,
      contexts: ["page", "editable", "selection"]
    },
    {
      id: QUERY_MENU_OPEN_ALL,
      parentId: QUERY_MENU_ROOT,
      title: "Open query palette…",
      contexts: ["page", "editable", "selection"]
    }
  ]

  let budget = MAX_MENU_TEMPLATES

  const walk = (nodes: GroupNode[], parentId: string, depth: number) => {
    for (const node of nodes) {
      if (budget <= 0) return
      const templates = node.templates.slice(0, budget)
      const hasChildren = node.children.length > 0
      if (templates.length === 0 && !hasChildren) continue

      const groupId = `${QUERY_MENU_PREFIX}group:${parentId}:${node.id}`
      definitions.push({
        id: groupId,
        parentId,
        title: node.label,
        contexts: ["editable", "selection"]
      })

      for (const entry of templates) {
        if (budget <= 0) break
        const patterns = patternsForPack(entry.pack)
        definitions.push({
          id: `${QUERY_MENU_PREFIX}${entry.key}`,
          parentId: groupId,
          title: entry.template.name,
          contexts: ["editable", "selection"],
          ...(patterns.length > 0 ? { documentUrlPatterns: patterns } : {})
        })
        budget -= 1
      }

      // Two levels is the practical limit for a usable context menu; anything
      // deeper belongs in the palette.
      if (hasChildren && depth < 1) {
        walk(node.children, groupId, depth + 1)
      }
    }
  }

  walk(tree, QUERY_MENU_ROOT, 0)
  return definitions
}

export const getQueryMenuDefinitions = async (): Promise<
  QueryMenuDefinition[]
> => {
  const library = await loadLibrary()
  return buildQueryMenuDefinitions(library.packs, buildGroupTree(library.packs))
}

export const setupQueryMenus = async (
  contextMenus: ContextMenuApi
): Promise<void> => {
  for (const definition of await getQueryMenuDefinitions()) {
    try {
      await contextMenus.create(definition)
    } catch (error) {
      console.debug("Query menu entry skipped:", definition.id, error)
    }
  }
}

export const parseQueryMenuId = (
  menuItemId: string | number
): string | null => {
  const id = String(menuItemId)
  if (!id.startsWith(QUERY_MENU_PREFIX)) return null
  const key = id.slice(QUERY_MENU_PREFIX.length)
  return key.startsWith("group:") ? null : key
}
