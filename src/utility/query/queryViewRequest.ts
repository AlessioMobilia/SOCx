import type { QueryDialect } from "./packSchema"
import type { PaletteEntry, PaletteRequest } from "./palette"
import { renderTemplate, type RenderedQuery } from "./render"
import { toWorkspaceIndicators } from "./workspace"

const describeQuery = (query: RenderedQuery): string | undefined => {
  const types = query.types?.length
    ? query.types.join(", ")
    : (query.type ?? "")
  const covered = types ? `${query.count} indicators · ${types}` : undefined
  if (query.chunks > 1) {
    return `Chunk ${query.chunk} of ${query.chunks}${covered ? ` · ${covered}` : ""}`
  }
  return covered
}

export const describeQueryIndicators = (text: string): string => {
  const parsed = toWorkspaceIndicators(text)
  if (parsed.length === 0) {
    return text.trim()
      ? "nothing recognisable yet"
      : "none — only queries that need no indicator will render"
  }

  const byType = new Map<string, number>()
  for (const indicator of parsed) {
    byType.set(indicator.type, (byType.get(indicator.type) ?? 0) + 1)
  }
  const breakdown = [...byType.entries()]
    .map(([type, count]) => `${count} ${type}`)
    .join(" · ")
  return `${parsed.length} indicator${parsed.length === 1 ? "" : "s"} · ${breakdown}`
}

type SharedQueryViewOptions = Pick<
  PaletteRequest,
  | "entries"
  | "indicatorHint"
  | "initialKey"
  | "favorites"
  | "platformLabel"
  | "initialSourceKey"
  | "initialDialect"
  | "mergeTypes"
  | "onMergeTypesChange"
  | "onIndicatorTextChange"
  | "onSelectedKeyChange"
  | "onToggleFavorite"
> & {
  dialects: Map<string, QueryDialect>
}

/** Builds the request consumed by both query surfaces. */
export const createQueryViewRequest = (
  options: SharedQueryViewOptions
): PaletteRequest => {
  const { dialects, ...requestOptions } = options
  return {
    ...requestOptions,
    dialects,
    dialectLabels: new Map(
      [...dialects.entries()].map(([id, dialect]) => [id, dialect.label])
    ),
    describeIndicators: describeQueryIndicators,
    onRender: (entry: PaletteEntry, input) => {
      const outcome = renderTemplate({
        template: entry.template,
        pack: entry.pack,
        dialects,
        indicators: toWorkspaceIndicators(input.indicatorText),
        variables: input.variables,
        mergeTypes: input.mergeTypes
      })

      return outcome.queries.map((query, index) => ({
        text: query.text,
        note: describeQuery(query),
        warning:
          [
            query.overLength
              ? "Longer than this platform usually accepts — consider a smaller batch."
              : "",
            index === 0 && outcome.mergeRefusal
              ? `One query per type: ${outcome.mergeRefusal}.`
              : ""
          ]
            .filter(Boolean)
            .join(" ") || undefined
      }))
    }
  }
}
