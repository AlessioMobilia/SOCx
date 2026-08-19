// Rule builder: turns templates written inside the extension into a pack file
// that is valid against the public schema, so an analyst can hand their work to
// the rest of the team or open a pull request against the community repository.

import {
  QUERY_PACK_SCHEMA,
  validateQueryPack,
  type BindableIocType,
  type PackKind,
  type QueryGroup,
  type QueryPack,
  type QueryTemplate,
  type TypeBinding,
  type ValidationIssue
} from "./packSchema"

export const USER_QUERY_LIBRARY_KEY = "queryPackUserLibrary"

/** One entry of the personal library, as edited in the builder form. */
export type UserQueryTemplate = {
  id: string
  name: string
  description?: string
  dialect: string
  kind: PackKind
  group?: string
  tags?: string[]
  byType?: Partial<Record<BindableIocType, TypeBinding>>
  body: string
  open?: string
  excludePrivate?: boolean
  variables?: QueryPack["variables"]
  favourite?: boolean
  createdAt: string
  updatedAt: string
}

export type PackMetadata = {
  id: string
  name: string
  description?: string
  author?: string
  vendor?: string
  homepage?: string
  license?: string
  version?: string
  verified?: boolean
  groups?: QueryGroup[]
  variables?: QueryPack["variables"]
  match?: QueryPack["match"]
}

const slugify = (value: string, fallback: string): string => {
  const slug = value
    .toLowerCase()
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64)
  return /^[a-z0-9]/.test(slug) ? slug : fallback
}

export const suggestTemplateId = (
  name: string,
  taken: Iterable<string> = []
): string => {
  const base = slugify(name, "query")
  const used = new Set(taken)
  if (!used.has(base)) return base
  for (let suffix = 2; suffix < 1000; suffix += 1) {
    const candidate = `${base}-${suffix}`.slice(0, 64)
    if (!used.has(candidate)) return candidate
  }
  return `${base}-${Date.now()}`.slice(0, 64)
}

/**
 * Derives the group tree from the paths the templates actually use, so the
 * exported pack always declares the groups it references and never trips the
 * repository validator.
 */
export const deriveGroups = (
  templates: Pick<UserQueryTemplate, "group">[],
  declared: QueryGroup[] = []
): QueryGroup[] => {
  const groups: QueryGroup[] = declared.map((group) => ({
    ...group,
    children: group.children ? [...group.children] : undefined
  }))

  const titleCase = (value: string) =>
    value
      .split("-")
      .filter(Boolean)
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(" ")

  for (const template of templates) {
    const path = template.group?.trim()
    if (!path) continue
    const [parentId, childId] = path.split("/")
    if (!parentId) continue

    let parent = groups.find((group) => group.id === parentId)
    if (!parent) {
      parent = { id: parentId, label: titleCase(parentId) }
      groups.push(parent)
    }
    if (!childId) continue

    parent.children = parent.children ?? []
    if (!parent.children.some((child) => child.id === childId)) {
      parent.children.push({ id: childId, label: titleCase(childId) })
    }
  }

  return groups
}

// Both branches carry `errors` for the same reason as ValidationResult: the
// project compiles with `strict: false`, where a boolean discriminant does not
// narrow reliably.
export type BuildPackResult =
  | {
      ok: true
      pack: QueryPack
      json: string
      errors: ValidationIssue[]
      warnings: ValidationIssue[]
    }
  | {
      ok: false
      pack?: undefined
      json?: undefined
      errors: ValidationIssue[]
      warnings: ValidationIssue[]
    }

/**
 * Builds one pack per kind: the repository keeps indicator packs and hunting
 * playbooks in separate files, and so does the export.
 */
export const buildPack = (
  templates: UserQueryTemplate[],
  kind: PackKind,
  metadata: PackMetadata,
  options: { knownDialects?: Set<string> } = {}
): BuildPackResult => {
  const selected = templates.filter((template) => template.kind === kind)

  if (selected.length === 0) {
    return {
      ok: false,
      warnings: [],
      errors: [
        {
          path: "$.templates",
          message: `the library holds no ${kind} template to export`
        }
      ]
    }
  }

  const variables: NonNullable<QueryPack["variables"]> = []
  const variablesById = new Map<string, string>()
  for (const variable of [
    ...(metadata.variables ?? []),
    ...selected.flatMap((template) => template.variables ?? [])
  ]) {
    const signature = JSON.stringify(variable)
    const previous = variablesById.get(variable.id)
    if (previous && previous !== signature) {
      return {
        ok: false,
        warnings: [],
        errors: [
          {
            path: "$.variables",
            message: `variable "${variable.id}" has conflicting definitions`
          }
        ]
      }
    }
    if (!previous) {
      variablesById.set(variable.id, signature)
      variables.push(variable)
    }
  }

  // A pack declares one default dialect; the rest ride on the template level
  // override, which is exactly how the community multi platform packs work.
  const dialectCounts = new Map<string, number>()
  for (const template of selected) {
    dialectCounts.set(
      template.dialect,
      (dialectCounts.get(template.dialect) ?? 0) + 1
    )
  }
  const defaultDialect = [...dialectCounts.entries()].sort(
    (a, b) => b[1] - a[1]
  )[0][0]

  const packTemplates: QueryTemplate[] = selected.map((template) => ({
    id: template.id,
    name: template.name,
    description: template.description,
    group: template.group,
    tags: template.tags,
    dialect: template.dialect === defaultDialect ? undefined : template.dialect,
    requiresIocs: kind === "ioc",
    byType: kind === "ioc" ? template.byType : undefined,
    excludePrivate: template.excludePrivate || undefined,
    body: template.body,
    open: template.open
  }))

  const pack: QueryPack = {
    schema: QUERY_PACK_SCHEMA,
    id: slugify(metadata.id || metadata.name, "custom-pack"),
    kind,
    name: metadata.name,
    description: metadata.description,
    vendor: metadata.vendor,
    author: metadata.author,
    homepage: metadata.homepage,
    dialect: defaultDialect,
    version: metadata.version ?? new Date().toISOString().slice(0, 10),
    license: metadata.license,
    verified: metadata.verified === true,
    match: metadata.match,
    variables: variables.length > 0 ? variables : undefined,
    groups: deriveGroups(selected, metadata.groups),
    templates: packTemplates
  }

  const validation = validateQueryPack(JSON.parse(JSON.stringify(pack)), {
    knownDialects: options.knownDialects
  })

  if (!validation.ok) {
    return {
      ok: false,
      errors: validation.errors,
      warnings: validation.warnings
    }
  }

  return {
    ok: true,
    pack: validation.value,
    json: `${JSON.stringify(validation.value, null, 2)}\n`,
    errors: [],
    warnings: validation.warnings
  }
}

/** Import a pack file back into the personal library, for editing or reuse. */
export const importPackIntoLibrary = (
  input: unknown,
  existing: UserQueryTemplate[] = [],
  options: { knownDialects?: Set<string> } = {}
): { templates: UserQueryTemplate[]; errors: ValidationIssue[] } => {
  const validation = validateQueryPack(input, options)
  if (!validation.ok) {
    return { templates: [], errors: validation.errors }
  }

  const pack = validation.value
  const taken = new Set(existing.map((template) => template.id))
  const now = new Date().toISOString()

  const templates = pack.templates.map((template) => {
    const id = suggestTemplateId(template.id, taken)
    taken.add(id)
    return {
      id,
      name: template.name,
      description: template.description,
      dialect: template.dialect ?? pack.dialect,
      kind: pack.kind,
      group: template.group,
      tags: template.tags,
      byType: template.byType,
      body: template.body,
      open: template.open,
      excludePrivate: template.excludePrivate,
      variables: pack.variables,
      createdAt: now,
      updatedAt: now
    } satisfies UserQueryTemplate
  })

  return { templates, errors: [] }
}
