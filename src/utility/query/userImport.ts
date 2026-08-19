import { importPackIntoLibrary, type UserQueryTemplate } from "./builder"
import { bundledDialectMap } from "./render"

export type UserPackImportResult = {
  templates: UserQueryTemplate[]
  imported: number
  errors: string[]
}

export const importUserPackText = (
  text: string,
  current: UserQueryTemplate[]
): UserPackImportResult => {
  try {
    const result = importPackIntoLibrary(JSON.parse(text), current, {
      knownDialects: new Set(bundledDialectMap().keys())
    })
    return {
      templates: result.templates,
      imported: Math.max(0, result.templates.length - current.length),
      errors: result.errors.map((error) => `${error.path}: ${error.message}`)
    }
  } catch {
    return {
      templates: current,
      imported: 0,
      errors: ["The selected file is not valid JSON."]
    }
  }
}
