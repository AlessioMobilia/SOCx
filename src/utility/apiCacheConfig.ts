import { Storage } from "@plasmohq/storage"

export const API_CACHE_TTL_KEY = "apiCacheTtlMinutes"

// Two minutes stays the default so that existing installs keep their
// behaviour; longer windows are opt-in from Extension Settings.
export const DEFAULT_API_CACHE_TTL_MINUTES = 2
export const API_CACHE_TTL_MINUTES = DEFAULT_API_CACHE_TTL_MINUTES
export const API_CACHE_TTL_MS = DEFAULT_API_CACHE_TTL_MINUTES * 60 * 1000

export const API_CACHE_TTL_OPTIONS = [
  { minutes: 2, label: "2 minutes" },
  { minutes: 5, label: "5 minutes" },
  { minutes: 15, label: "15 minutes" },
  { minutes: 30, label: "30 minutes" },
  { minutes: 60, label: "1 hour" },
  { minutes: 240, label: "4 hours" }
] as const

const ALLOWED_TTL_MINUTES = new Set(
  API_CACHE_TTL_OPTIONS.map((option) => option.minutes as number)
)

export const normalizeApiCacheTtlMinutes = (value: unknown): number => {
  const minutes = typeof value === "number" ? value : Number(value)
  return Number.isFinite(minutes) && ALLOWED_TTL_MINUTES.has(minutes)
    ? minutes
    : DEFAULT_API_CACHE_TTL_MINUTES
}

const storage = new Storage({ area: "local" })

export const readApiCacheTtlMinutes = async (): Promise<number> => {
  try {
    return normalizeApiCacheTtlMinutes(
      await storage.get<number>(API_CACHE_TTL_KEY)
    )
  } catch {
    return DEFAULT_API_CACHE_TTL_MINUTES
  }
}

export const readApiCacheTtlMs = async (): Promise<number> =>
  (await readApiCacheTtlMinutes()) * 60 * 1000

export const formatApiCacheTtl = (minutes: number): string =>
  API_CACHE_TTL_OPTIONS.find((option) => option.minutes === minutes)?.label ??
  `${minutes} minutes`
