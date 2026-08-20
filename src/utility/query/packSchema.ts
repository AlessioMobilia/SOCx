// Model and validator for SOCx query packs.
//
// A pack is untrusted data fetched over the network, so parsing is defensive:
// unknown fields are dropped rather than passed through, the escape strategy is
// resolved against a fixed list implemented here, and nothing in a pack is ever
// evaluated as code.

export const QUERY_PACK_SCHEMA = "socx.querypack/v1"
export const PACK_INDEX_SCHEMA = "socx.packindex/v1"
export const DIALECTS_SCHEMA = "socx.dialects/v1"

export type PackKind = "ioc" | "standard"

export const ESCAPE_STRATEGIES = [
  "backslash",
  "sql-quote",
  "lucene",
  "regex",
  "json",
  "none"
] as const
export type EscapeStrategy = (typeof ESCAPE_STRATEGIES)[number]

export const LIST_STRATEGIES = [
  "in-operator",
  "or-expansion",
  "regex-alternation"
] as const
export type ListStrategy = (typeof LIST_STRATEGIES)[number]

export const TEMPLATE_FILTERS = [
  "raw",
  "json",
  "regex",
  "newline",
  "or-values",
  "or-terms",
  "urlencode",
  "base64",
  "gzip_base64url",
  "upper",
  "lower"
] as const
export type TemplateFilter = (typeof TEMPLATE_FILTERS)[number]

export const BINDABLE_IOC_TYPES = [
  "IP",
  "Domain",
  "URL",
  "Email",
  "ASN",
  "MAC",
  "CVE",
  "Hash",
  "SHA256",
  "SHA1",
  "MD5"
] as const
export type BindableIocType = (typeof BINDABLE_IOC_TYPES)[number]

export type QueryDialect = {
  id: string
  label: string
  vendors?: string[]
  statementStyle?: "piped" | "sql" | "boolean"
  escape: EscapeStrategy
  quote: string
  listStrategy: ListStrategy
  listOpen?: string
  listClose?: string
  separator?: string
  operators?: Record<string, string>
  comment?: string | null
  commentClose?: string
  timeInQuery?: boolean
  timeExpression?: string
  caseInsensitive?: string
  maxItems?: number
  maxLength?: number
  notes?: string
}

export type TypeBinding = {
  table?: string
  field?: string
  op?: string
  /** Appended after each comparison, e.g. the `nocase` modifier of UDM. */
  suffix?: string
  note?: string
}

/**
 * A custom dimension a repository can slice its catalogue by — a customer, a
 * tenant, a business unit, a detection maturity level. Packs declare the
 * dimension, templates (or whole pack files, from the index) carry the values,
 * and the palette turns each declared dimension into its own filter.
 */
export type QueryFacet = {
  id: string
  label: string
  description?: string
  order?: number
}

/** Facet id to the values an entry carries for it. */
export type FacetLabels = Record<string, string[]>

export type QueryTemplate = {
  id: string
  name: string
  description?: string
  group?: string
  tags?: string[]
  labels?: FacetLabels
  dialect?: string
  requiresIocs: boolean
  byType?: Partial<Record<BindableIocType, TypeBinding>>
  excludePrivate?: boolean
  body: string
  open?: string
  maxItems?: number
  reference?: string
  mitre?: string[]
}

export type QueryGroup = {
  id: string
  label: string
  description?: string
  order?: number
  children?: QueryGroup[]
}

export type QueryPack = {
  schema: typeof QUERY_PACK_SCHEMA
  id: string
  kind: PackKind
  name: string
  description?: string
  vendor?: string
  author?: string
  homepage?: string
  dialect: string
  version?: string
  license?: string
  verified?: boolean
  match?: {
    hostnames?: string[]
    urlPatterns?: string[]
    pathHint?: string
    note?: string
  }
  targets?: { id: string; label: string; baseUrl?: string; tenant?: string }[]
  variables?: {
    id: string
    label: string
    default?: string
    options?: string[]
    description?: string
  }[]
  groups?: QueryGroup[]
  /** Custom filter dimensions this pack contributes to the palette. */
  facets?: QueryFacet[]
  /** Values applied to every template of the pack. */
  labels?: FacetLabels
  templates: QueryTemplate[]
  /** Runtime-only namespace; never read from or written to a pack file. */
  sourceId?: string
}

export type PackIndexEntry = {
  id: string
  kind: PackKind
  name: string
  dialect: string
  path: string
  templates?: number
  verified?: boolean
  /** Facet values applied to the whole file, e.g. `{ customer: ["acme"] }`. */
  labels?: FacetLabels
}

export type PackIndex = {
  schema: typeof PACK_INDEX_SCHEMA
  name?: string
  description?: string
  homepage?: string
  version?: string
  dialects?: string
  /** Custom filter dimensions declared once for every pack of the catalogue. */
  facets?: QueryFacet[]
  /**
   * Other index files this one pulls in, so a catalogue can be split across as
   * many files as the team needs — one per customer, per platform, per squad.
   */
  includes?: string[]
  packs: PackIndexEntry[]
}

export type ValidationIssue = {
  path: string
  message: string
}

// `errors` is present on both branches so that callers can read it without a
// type guard: the project compiles with `strict: false`, where narrowing on a
// boolean discriminant is not reliable.
export type ValidationResult<T> =
  | {
      ok: true
      value: T
      errors: ValidationIssue[]
      warnings: ValidationIssue[]
    }
  | {
      ok: false
      value?: undefined
      errors: ValidationIssue[]
      warnings: ValidationIssue[]
    }

const ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/
/** Ceiling on how many files one index may pull in, per file. */
export const MAX_INDEX_INCLUDES = 50
const GROUP_PATH_PATTERN =
  /^[a-z0-9][a-z0-9-]{0,63}(\/[a-z0-9][a-z0-9-]{0,63})?$/
const PLACEHOLDER_PATTERN = /\{\{([^}]+)\}\}/g
const KNOWN_PLACEHOLDERS = [
  "iocs",
  "ioc",
  "field",
  "table",
  "op",
  "count",
  "chunk",
  "chunks",
  "now",
  "query"
]

const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value)

const asString = (value: unknown, max = 20_000): string | undefined =>
  typeof value === "string" && value.length <= max ? value : undefined

const asStringArray = (
  value: unknown,
  maxEntries = 200,
  maxLength = 500
): string[] | undefined =>
  Array.isArray(value)
    ? value
        .slice(0, maxEntries)
        .filter(
          (entry): entry is string =>
            typeof entry === "string" && entry.length <= maxLength
        )
    : undefined

export const collectGroupPaths = (groups: QueryGroup[] = []): Set<string> => {
  const paths = new Set<string>()
  for (const group of groups) {
    if (!group?.id) continue
    paths.add(group.id)
    for (const child of group.children ?? []) {
      if (child?.id) paths.add(`${group.id}/${child.id}`)
    }
  }
  return paths
}

const parseGroups = (value: unknown): QueryGroup[] | undefined => {
  if (!Array.isArray(value)) return undefined
  const groups: QueryGroup[] = []
  for (const raw of value) {
    if (!isRecord(raw)) continue
    const id = asString(raw.id, 64)
    const label = asString(raw.label, 80)
    if (!id || !ID_PATTERN.test(id) || !label) continue

    const children: QueryGroup[] = []
    if (Array.isArray(raw.children)) {
      for (const rawChild of raw.children) {
        if (!isRecord(rawChild)) continue
        const childId = asString(rawChild.id, 64)
        const childLabel = asString(rawChild.label, 80)
        if (!childId || !ID_PATTERN.test(childId) || !childLabel) continue
        children.push({
          id: childId,
          label: childLabel,
          description: asString(rawChild.description, 500),
          order: typeof rawChild.order === "number" ? rawChild.order : undefined
        })
      }
    }

    groups.push({
      id,
      label,
      description: asString(raw.description, 500),
      order: typeof raw.order === "number" ? raw.order : undefined,
      ...(children.length > 0 ? { children } : {})
    })
  }
  return groups
}

/** Facet ids share the pack id grammar: lowercase, dash separated, short. */
export const MAX_FACETS = 12
const MAX_FACET_VALUES = 40

const parseFacets = (value: unknown): QueryFacet[] | undefined => {
  if (!Array.isArray(value)) return undefined
  const facets: QueryFacet[] = []
  const seen = new Set<string>()
  for (const raw of value) {
    if (!isRecord(raw)) continue
    const id = asString(raw.id, 64)
    const label = asString(raw.label, 80)
    if (!id || !ID_PATTERN.test(id) || !label || seen.has(id)) continue
    seen.add(id)
    facets.push({
      id,
      label,
      description: asString(raw.description, 500),
      order: typeof raw.order === "number" ? raw.order : undefined
    })
    if (facets.length >= MAX_FACETS) break
  }
  return facets.length > 0 ? facets : undefined
}

/**
 * Labels are free text chosen by the repository (customer names, tenants), so
 * only the facet id is constrained; values are trimmed and length capped.
 */
export const parseLabels = (value: unknown): FacetLabels | undefined => {
  if (!isRecord(value)) return undefined
  const labels: FacetLabels = {}
  for (const [facetId, raw] of Object.entries(value)) {
    if (!ID_PATTERN.test(facetId)) continue
    const candidates =
      typeof raw === "string"
        ? [raw]
        : (asStringArray(raw, MAX_FACET_VALUES, 80) ?? [])
    const values: string[] = []
    for (const candidate of candidates) {
      const trimmed = candidate.trim()
      if (trimmed && trimmed.length <= 80 && !values.includes(trimmed)) {
        values.push(trimmed)
      }
    }
    if (values.length > 0) labels[facetId] = values
  }
  return Object.keys(labels).length > 0 ? labels : undefined
}

/** Union of the pack wide labels and the template's own. */
export const mergeLabels = (
  ...sources: (FacetLabels | undefined)[]
): FacetLabels | undefined => {
  const merged: FacetLabels = {}
  for (const source of sources) {
    for (const [facetId, values] of Object.entries(source ?? {})) {
      const current = merged[facetId] ?? []
      for (const value of values) {
        if (!current.includes(value)) current.push(value)
      }
      merged[facetId] = current
    }
  }
  return Object.keys(merged).length > 0 ? merged : undefined
}

const parseByType = (
  value: unknown,
  errors: ValidationIssue[],
  path: string
): Partial<Record<BindableIocType, TypeBinding>> | undefined => {
  if (!isRecord(value)) return undefined
  const bindings: Partial<Record<BindableIocType, TypeBinding>> = {}
  for (const [type, raw] of Object.entries(value)) {
    if (!(BINDABLE_IOC_TYPES as readonly string[]).includes(type)) {
      errors.push({ path, message: `unknown indicator type "${type}"` })
      continue
    }
    if (!isRecord(raw)) continue
    bindings[type as BindableIocType] = {
      table: asString(raw.table, 200),
      field: asString(raw.field, 200),
      op: asString(raw.op, 40),
      suffix: asString(raw.suffix, 40),
      note: asString(raw.note, 500)
    }
  }
  return Object.keys(bindings).length > 0 ? bindings : undefined
}

export const parseTemplatePlaceholders = (
  body: string
): { names: string[]; filters: string[] } => {
  const names: string[] = []
  const filters: string[] = []
  PLACEHOLDER_PATTERN.lastIndex = 0
  let match: RegExpExecArray | null
  while ((match = PLACEHOLDER_PATTERN.exec(body)) !== null) {
    const parts = match[1].split("|").map((part) => part.trim())
    names.push(parts[0])
    for (const filter of parts.slice(1)) {
      filters.push(filter.split(":")[0].trim())
    }
  }
  return { names, filters }
}

export const validateQueryPack = (
  input: unknown,
  options: { knownDialects?: Set<string> } = {}
): ValidationResult<QueryPack> => {
  const errors: ValidationIssue[] = []
  const warnings: ValidationIssue[] = []

  if (!isRecord(input)) {
    return {
      ok: false,
      errors: [{ path: "$", message: "pack is not an object" }],
      warnings
    }
  }

  if (input.schema !== QUERY_PACK_SCHEMA) {
    errors.push({
      path: "$.schema",
      message: `expected "${QUERY_PACK_SCHEMA}", found "${String(input.schema)}"`
    })
  }

  const id = asString(input.id, 64)
  if (!id || !ID_PATTERN.test(id)) {
    errors.push({ path: "$.id", message: "missing or malformed pack id" })
  }

  const kind =
    input.kind === "standard"
      ? "standard"
      : input.kind === "ioc"
        ? "ioc"
        : undefined
  if (!kind) {
    errors.push({ path: "$.kind", message: 'kind must be "ioc" or "standard"' })
  }

  const name = asString(input.name, 120)
  if (!name) {
    errors.push({ path: "$.name", message: "missing pack name" })
  }

  const dialect = asString(input.dialect, 64)
  if (!dialect) {
    errors.push({ path: "$.dialect", message: "missing dialect" })
  } else if (options.knownDialects && !options.knownDialects.has(dialect)) {
    errors.push({
      path: "$.dialect",
      message: `unknown dialect "${dialect}"`
    })
  }

  const groups = parseGroups(input.groups)
  const groupPaths = collectGroupPaths(groups)

  const variables: NonNullable<QueryPack["variables"]> = []
  const seenVariableIds = new Set<string>()
  if (Array.isArray(input.variables)) {
    input.variables.forEach((raw, index) => {
      const path = `$.variables[${index}]`
      if (!isRecord(raw)) {
        errors.push({ path, message: "variable is not an object" })
        return
      }
      const variableId = asString(raw.id, 64)
      const variableLabel = asString(raw.label, 120)
      if (!variableId || !ID_PATTERN.test(variableId) || !variableLabel) {
        errors.push({ path, message: "variable needs a valid id and label" })
        return
      }
      if (seenVariableIds.has(variableId)) {
        errors.push({ path, message: `duplicate variable id "${variableId}"` })
        return
      }
      seenVariableIds.add(variableId)
      variables.push({
        id: variableId,
        label: variableLabel,
        default: asString(raw.default, 500),
        options: asStringArray(raw.options),
        description: asString(raw.description, 500)
      })
    })
  }
  const variableIds = new Set((variables ?? []).map((variable) => variable.id))

  const templates: QueryTemplate[] = []
  const seenTemplateIds = new Set<string>()

  if (!Array.isArray(input.templates) || input.templates.length === 0) {
    errors.push({ path: "$.templates", message: "pack has no templates" })
  } else {
    input.templates.forEach((raw, index) => {
      const path = `$.templates[${index}]`
      if (!isRecord(raw)) {
        errors.push({ path, message: "template is not an object" })
        return
      }

      const templateId = asString(raw.id, 64)
      const templateName = asString(raw.name, 160)
      const body = asString(raw.body, 20_000)

      if (!templateId || !ID_PATTERN.test(templateId)) {
        errors.push({ path, message: "missing or malformed template id" })
        return
      }
      if (seenTemplateIds.has(templateId)) {
        errors.push({ path, message: `duplicate template id "${templateId}"` })
        return
      }
      seenTemplateIds.add(templateId)

      if (!templateName || !body) {
        errors.push({ path, message: "template needs a name and a body" })
        return
      }

      const templateDialect = asString(raw.dialect, 64)
      if (
        templateDialect &&
        options.knownDialects &&
        !options.knownDialects.has(templateDialect)
      ) {
        errors.push({
          path,
          message: `unknown dialect "${templateDialect}"`
        })
      }

      const group = asString(raw.group, 130)
      if (group && !GROUP_PATH_PATTERN.test(group)) {
        warnings.push({ path, message: `malformed group path "${group}"` })
      } else if (group && groupPaths.size > 0 && !groupPaths.has(group)) {
        // Not fatal: a typo must never hide a query from the analyst.
        warnings.push({
          path,
          message: `group "${group}" is not declared by the pack`
        })
      }

      const requiresIocs = raw.requiresIocs !== false
      const byType = parseByType(raw.byType, errors, path)

      if (kind === "ioc" && !requiresIocs) {
        errors.push({
          path,
          message: "ioc pack cannot hold an indicator free template"
        })
      }
      if (kind === "standard" && requiresIocs) {
        errors.push({
          path,
          message: "standard pack templates must set requiresIocs to false"
        })
      }
      if (requiresIocs && !byType) {
        errors.push({
          path,
          message: "template needs indicators but binds no type"
        })
      }

      const { names, filters } = parseTemplatePlaceholders(
        `${body}\n${asString(raw.open, 2_000) ?? ""}`
      )

      for (const filter of filters) {
        if (!(TEMPLATE_FILTERS as readonly string[]).includes(filter)) {
          errors.push({ path, message: `unknown filter "${filter}"` })
        }
      }

      for (const placeholder of names) {
        if (placeholder.startsWith("var:")) {
          const variableId = placeholder.slice(4)
          if (!variableIds.has(variableId)) {
            errors.push({
              path,
              message: `variable "${variableId}" is not declared`
            })
          }
          continue
        }
        if (!KNOWN_PLACEHOLDERS.includes(placeholder)) {
          errors.push({ path, message: `unknown placeholder "${placeholder}"` })
        }
      }

      if (requiresIocs && !names.includes("iocs") && !names.includes("ioc")) {
        errors.push({ path, message: "template never renders its indicators" })
      }

      templates.push({
        id: templateId,
        name: templateName,
        description: asString(raw.description, 2_000),
        group,
        tags: asStringArray(raw.tags),
        labels: parseLabels(raw.labels),
        dialect: templateDialect,
        requiresIocs,
        byType,
        excludePrivate: raw.excludePrivate === true,
        body,
        open: asString(raw.open, 2_000),
        maxItems:
          typeof raw.maxItems === "number" && raw.maxItems > 0
            ? raw.maxItems
            : undefined,
        reference: asString(raw.reference, 500),
        mitre: asStringArray(raw.mitre)
      })
    })
  }

  if (errors.length > 0) {
    return { ok: false, errors, warnings }
  }

  const match = isRecord(input.match)
    ? {
        hostnames: asStringArray(input.match.hostnames),
        urlPatterns: asStringArray(input.match.urlPatterns),
        pathHint: asString(input.match.pathHint, 500),
        note: asString(input.match.note, 500)
      }
    : undefined

  const targets = Array.isArray(input.targets)
    ? input.targets
        .filter(isRecord)
        .map((raw) => ({
          id: asString(raw.id, 64) ?? "",
          label: asString(raw.label, 120) ?? "",
          baseUrl: asString(raw.baseUrl, 500),
          tenant: asString(raw.tenant, 120)
        }))
        .filter((target) => target.id && target.label)
    : undefined

  return {
    ok: true,
    errors,
    warnings,
    value: {
      schema: QUERY_PACK_SCHEMA,
      id: id!,
      kind: kind!,
      name: name!,
      description: asString(input.description, 2_000),
      vendor: asString(input.vendor, 120),
      author: asString(input.author, 120),
      homepage: asString(input.homepage, 500),
      dialect: dialect!,
      version: asString(input.version, 40),
      license: asString(input.license, 40),
      verified: input.verified === true,
      match,
      targets,
      variables: variables.length > 0 ? variables : undefined,
      groups,
      facets: parseFacets(input.facets),
      labels: parseLabels(input.labels),
      templates
    }
  }
}

export const validatePackIndex = (
  input: unknown
): ValidationResult<PackIndex> => {
  const errors: ValidationIssue[] = []
  const warnings: ValidationIssue[] = []

  if (!isRecord(input)) {
    return {
      ok: false,
      errors: [{ path: "$", message: "index is not an object" }],
      warnings
    }
  }
  if (input.schema !== PACK_INDEX_SCHEMA) {
    errors.push({
      path: "$.schema",
      message: `expected "${PACK_INDEX_SCHEMA}", found "${String(input.schema)}"`
    })
  }

  // An index may carry packs, other indexes, or both: a catalogue split across
  // several files often has a root that only points at its parts.
  const includes: string[] = []
  if (Array.isArray(input.includes)) {
    input.includes.slice(0, MAX_INDEX_INCLUDES).forEach((raw, index) => {
      const reference = asString(raw, 500)?.trim()
      if (!reference) {
        warnings.push({
          path: `$.includes[${index}]`,
          message: "entry skipped: not a string"
        })
        return
      }
      if (reference.includes("..")) {
        errors.push({
          path: `$.includes[${index}]`,
          message: `unsafe index path "${reference}"`
        })
        return
      }
      if (/^[a-z]+:/i.test(reference) && !/^https:\/\//i.test(reference)) {
        errors.push({
          path: `$.includes[${index}]`,
          message: "an included index must be a relative path or an HTTPS URL"
        })
        return
      }
      if (!includes.includes(reference)) includes.push(reference)
    })
  }

  const packs: PackIndexEntry[] = []
  const seenEntryIds = new Set<string>()
  if (!Array.isArray(input.packs)) {
    if (includes.length === 0) {
      errors.push({ path: "$.packs", message: "index has no pack list" })
    }
  } else {
    input.packs.forEach((raw, index) => {
      if (!isRecord(raw)) return
      const entryId = asString(raw.id, 64)
      const entryPath = asString(raw.path, 500)
      const entryKind =
        raw.kind === "standard"
          ? "standard"
          : raw.kind === "ioc"
            ? "ioc"
            : undefined
      if (!entryId || !ID_PATTERN.test(entryId) || !entryPath) {
        warnings.push({
          path: `$.packs[${index}]`,
          message: "entry skipped: missing or malformed id/path"
        })
        return
      }
      if (!entryKind) {
        errors.push({
          path: `$.packs[${index}].kind`,
          message: 'kind must be "ioc" or "standard"'
        })
        return
      }
      if (seenEntryIds.has(entryId)) {
        errors.push({
          path: `$.packs[${index}].id`,
          message: `duplicate pack id "${entryId}"`
        })
        return
      }
      seenEntryIds.add(entryId)
      // A relative path must not climb out of the index location.
      if (entryPath.includes("..") || /^[a-z]+:/i.test(entryPath)) {
        errors.push({
          path: `$.packs[${index}].path`,
          message: `unsafe pack path "${entryPath}"`
        })
        return
      }
      packs.push({
        id: entryId,
        kind: entryKind,
        name: asString(raw.name, 120) ?? entryId,
        dialect: asString(raw.dialect, 64) ?? "unknown",
        path: entryPath,
        templates:
          typeof raw.templates === "number" ? raw.templates : undefined,
        verified: raw.verified === true,
        labels: parseLabels(raw.labels)
      })
    })
  }

  if (errors.length > 0) {
    return { ok: false, errors, warnings }
  }

  return {
    ok: true,
    errors,
    warnings,
    value: {
      schema: PACK_INDEX_SCHEMA,
      name: asString(input.name, 120),
      description: asString(input.description, 2_000),
      homepage: asString(input.homepage, 500),
      version: asString(input.version, 40),
      dialects: asString(input.dialects, 500),
      facets: parseFacets(input.facets),
      ...(includes.length > 0 ? { includes } : {}),
      packs
    }
  }
}
