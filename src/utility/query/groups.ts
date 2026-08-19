// Resolves the group hierarchy that the palette sections and the context menu
// submenus are built from.
//
// Packs declare their own groups, so the tree is assembled at runtime by
// merging every enabled pack. A template pointing at a group nobody declared is
// never dropped: a placeholder group is synthesised from its path, because a
// typo in a pack must not make a query invisible to the analyst.

import type { QueryGroup, QueryPack, QueryTemplate } from "./packSchema"

export const UNCATEGORISED_ID = "uncategorised"
export const UNCATEGORISED_LABEL = "Uncategorised"

export type ResolvedTemplate = {
  template: QueryTemplate
  pack: QueryPack
  /** Globally unique key: source and pack namespaced, so ids cannot collide. */
  key: string
}

export type GroupNode = {
  id: string
  label: string
  description?: string
  order?: number
  synthesised?: boolean
  children: GroupNode[]
  templates: ResolvedTemplate[]
}

const titleCase = (value: string): string =>
  value
    .split("-")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ")

const findOrCreate = (
  nodes: GroupNode[],
  id: string,
  declared?: QueryGroup
): GroupNode => {
  const existing = nodes.find((node) => node.id === id)
  if (existing) {
    // A later pack may declare a group an earlier one only referenced.
    if (declared) {
      existing.label = declared.label
      existing.description = declared.description ?? existing.description
      existing.order = declared.order ?? existing.order
      existing.synthesised = false
    }
    return existing
  }

  const node: GroupNode = {
    id,
    label: declared?.label ?? titleCase(id),
    description: declared?.description,
    order: declared?.order,
    synthesised: !declared,
    children: [],
    templates: []
  }
  nodes.push(node)
  return node
}

const sortNodes = (nodes: GroupNode[]): GroupNode[] => {
  nodes.sort((a, b) => {
    const orderA = a.order ?? Number.MAX_SAFE_INTEGER
    const orderB = b.order ?? Number.MAX_SAFE_INTEGER
    if (orderA !== orderB) return orderA - orderB
    return a.label.localeCompare(b.label)
  })
  for (const node of nodes) {
    sortNodes(node.children)
    node.templates.sort((a, b) =>
      a.template.name.localeCompare(b.template.name)
    )
  }
  return nodes
}

export const buildGroupTree = (packs: QueryPack[]): GroupNode[] => {
  const roots: GroupNode[] = []

  // Declared groups first, so labels and ordering win over synthesised ones.
  for (const pack of packs) {
    for (const group of pack.groups ?? []) {
      const node = findOrCreate(roots, group.id, group)
      for (const child of group.children ?? []) {
        findOrCreate(node.children, child.id, child)
      }
    }
  }

  for (const pack of packs) {
    for (const template of pack.templates) {
      const resolved: ResolvedTemplate = {
        template,
        pack,
        key: `${pack.sourceId ?? "local"}::${pack.id}::${template.id}`
      }

      const path = template.group?.trim()
      if (!path) {
        findOrCreate(roots, UNCATEGORISED_ID, {
          id: UNCATEGORISED_ID,
          label: UNCATEGORISED_LABEL,
          order: Number.MAX_SAFE_INTEGER
        }).templates.push(resolved)
        continue
      }

      const [parentId, childId] = path.split("/")
      const parent = findOrCreate(roots, parentId)
      if (childId) {
        findOrCreate(parent.children, childId).templates.push(resolved)
      } else {
        parent.templates.push(resolved)
      }
    }
  }

  return sortNodes(roots)
}

export const countTemplates = (nodes: GroupNode[]): number =>
  nodes.reduce(
    (total, node) =>
      total + node.templates.length + countTemplates(node.children),
    0
  )

/** Flattens the tree into the order the palette lists results in. */
export const flattenGroupTree = (
  nodes: GroupNode[],
  trail: string[] = []
): { path: string[]; entry: ResolvedTemplate }[] => {
  const flat: { path: string[]; entry: ResolvedTemplate }[] = []
  for (const node of nodes) {
    const path = [...trail, node.label]
    for (const entry of node.templates) {
      flat.push({ path, entry })
    }
    flat.push(...flattenGroupTree(node.children, path))
  }
  return flat
}
