import { Storage } from "@plasmohq/storage"

import { API_CACHE_TTL_MS, readApiCacheTtlMs } from "./apiCacheConfig"

export type ApiProvider =
  "VirusTotal" | "AbuseIPDB" | "IPAPI" | "ProxyCheck" | "NVD"

type CacheRecord<T> = {
  expiresAt: number
  // Recorded so that shortening the configured TTL expires existing entries
  // immediately instead of honouring the window they were written with.
  storedAt?: number
  value: T
}

export interface RequestCacheStore {
  get<T>(key: string): Promise<CacheRecord<T> | undefined>
  set<T>(key: string, value: CacheRecord<T>): Promise<void>
  remove(key: string): Promise<void>
  clear(): Promise<void>
}

type CoordinatorOptions = {
  cacheStore?: RequestCacheStore
  now?: () => number
  sleep?: (ms: number) => Promise<void>
  providerIntervals?: Partial<Record<ApiProvider, number>>
  cacheTtlMs?: number
  resolveCacheTtlMs?: () => Promise<number>
}

type CoordinatedRequest<T> = {
  provider: ApiProvider
  cacheKey: string
  request: () => Promise<T>
  maxRetries?: number
  minimumIntervalMs?: number
}

const CACHE_PREFIX = "api-response-cache:"
const MAX_CACHE_ENTRY_CHARS = 750_000
const DEFAULT_PROVIDER_INTERVALS: Record<ApiProvider, number> = {
  VirusTotal: 15_000,
  AbuseIPDB: 250,
  IPAPI: 250,
  ProxyCheck: 250,
  NVD: 6_500
}

const storage = new Storage({ area: "local" })

const hashCacheKey = (value: string): string => {
  let first = 0x811c9dc5
  let second = 0x9e3779b9
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)
    first = Math.imul(first ^ code, 0x01000193)
    second = Math.imul(second ^ code, 0x85ebca6b)
  }
  return `${(first >>> 0).toString(16)}${(second >>> 0).toString(16)}`
}

const persistentCacheStore: RequestCacheStore = {
  get: <T>(key: string) => storage.get<CacheRecord<T>>(key),
  set: <T>(key: string, value: CacheRecord<T>) => storage.set(key, value),
  remove: (key: string) => storage.remove(key),
  clear: async () => {
    const all = await storage.getAll()
    const keys = Object.keys(all).filter((key) => key.startsWith(CACHE_PREFIX))
    await Promise.all(keys.map((key) => storage.remove(key)))
  }
}

export class ApiRequestError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly retryAfterMs?: number
  ) {
    super(message)
    this.name = "ApiRequestError"
  }
}

const isTransientError = (error: unknown): boolean => {
  if (error instanceof ApiRequestError) {
    return [408, 425, 429, 500, 502, 503, 504].includes(error.status)
  }
  return error instanceof TypeError
}

export class ApiRequestCoordinator {
  private readonly cacheStore: RequestCacheStore
  private readonly now: () => number
  private readonly sleep: (ms: number) => Promise<void>
  private readonly providerIntervals: Record<ApiProvider, number>
  private readonly cacheTtlMs?: number
  private readonly resolveCacheTtlMs: () => Promise<number>
  private readonly providerQueues = new Map<ApiProvider, Promise<void>>()
  private readonly providerLastStartedAt = new Map<ApiProvider, number>()
  private readonly inFlight = new Map<string, Promise<unknown>>()
  private cacheGeneration = 0

  constructor(options: CoordinatorOptions = {}) {
    this.cacheStore = options.cacheStore ?? persistentCacheStore
    this.now = options.now ?? Date.now
    this.sleep =
      options.sleep ??
      ((ms) => new Promise((resolve) => setTimeout(resolve, ms)))
    this.providerIntervals = {
      ...DEFAULT_PROVIDER_INTERVALS,
      ...options.providerIntervals
    }
    this.cacheTtlMs = options.cacheTtlMs
    this.resolveCacheTtlMs =
      options.resolveCacheTtlMs ??
      (async () => {
        try {
          return await readApiCacheTtlMs()
        } catch {
          return API_CACHE_TTL_MS
        }
      })
  }

  private async currentCacheTtlMs(): Promise<number> {
    if (typeof this.cacheTtlMs === "number") {
      return this.cacheTtlMs
    }
    return this.resolveCacheTtlMs()
  }

  run<T>({
    provider,
    cacheKey,
    request,
    maxRetries = 2,
    minimumIntervalMs
  }: CoordinatedRequest<T>): Promise<T> {
    const requestKey = `${provider}:${cacheKey}`
    const existing = this.inFlight.get(requestKey) as Promise<T> | undefined
    if (existing) return existing

    const generation = this.cacheGeneration
    const coordinated = this.runInternal(
      provider,
      requestKey,
      request,
      maxRetries,
      generation,
      minimumIntervalMs
    ).finally(() => this.inFlight.delete(requestKey))
    this.inFlight.set(requestKey, coordinated)
    return coordinated
  }

  async clearCache(): Promise<void> {
    this.cacheGeneration += 1
    await this.cacheStore.clear()
  }

  private async runInternal<T>(
    provider: ApiProvider,
    requestKey: string,
    request: () => Promise<T>,
    maxRetries: number,
    generation: number,
    minimumIntervalMs?: number
  ): Promise<T> {
    const storageKey = `${CACHE_PREFIX}${provider}:${hashCacheKey(requestKey)}`
    const cacheTtlMs = await this.currentCacheTtlMs()
    let cached: CacheRecord<T> | undefined
    try {
      cached = await this.cacheStore.get<T>(storageKey)
    } catch (error) {
      console.warn("Unable to read the API response cache:", error)
    }
    if (cached) {
      // The configured TTL wins over the one the entry was written with, so a
      // shorter window takes effect on the next lookup.
      const expiresAt =
        typeof cached.storedAt === "number"
          ? Math.min(cached.expiresAt, cached.storedAt + cacheTtlMs)
          : cached.expiresAt
      if (expiresAt > this.now()) return cached.value
      try {
        await this.cacheStore.remove(storageKey)
      } catch (error) {
        console.warn("Unable to remove an expired API cache entry:", error)
      }
    }

    const value = await this.enqueue(provider, () =>
      this.executeWithRetry(provider, request, maxRetries, minimumIntervalMs)
    )
    if (generation === this.cacheGeneration && this.isCacheable(value)) {
      try {
        const storedAt = this.now()
        await this.cacheStore.set(storageKey, {
          expiresAt: storedAt + cacheTtlMs,
          storedAt,
          value
        })
      } catch (error) {
        console.warn("Unable to persist an API cache entry:", error)
      }
    }
    return value
  }

  private enqueue<T>(
    provider: ApiProvider,
    task: () => Promise<T>
  ): Promise<T> {
    const previous = this.providerQueues.get(provider) ?? Promise.resolve()
    const execution = previous.catch(() => undefined).then(task)
    this.providerQueues.set(
      provider,
      execution.then(
        () => undefined,
        () => undefined
      )
    )
    return execution
  }

  private async executeWithRetry<T>(
    provider: ApiProvider,
    request: () => Promise<T>,
    maxRetries: number,
    minimumIntervalMs?: number
  ): Promise<T> {
    let attempt = 0
    while (true) {
      try {
        await this.waitForProvider(provider, minimumIntervalMs)
        return await request()
      } catch (error) {
        if (attempt >= maxRetries || !isTransientError(error)) throw error
        const retryAfterMs =
          error instanceof ApiRequestError ? error.retryAfterMs : undefined
        const backoffMs = retryAfterMs ?? 750 * 2 ** attempt
        attempt += 1
        await this.sleep(backoffMs)
      }
    }
  }

  private async waitForProvider(
    provider: ApiProvider,
    minimumIntervalMs?: number
  ): Promise<void> {
    const interval = minimumIntervalMs ?? this.providerIntervals[provider]
    const lastStartedAt = this.providerLastStartedAt.get(provider)
    if (lastStartedAt !== undefined) {
      const waitMs = Math.max(0, interval - (this.now() - lastStartedAt))
      if (waitMs > 0) await this.sleep(waitMs)
    }
    this.providerLastStartedAt.set(provider, this.now())
  }

  private isCacheable(value: unknown): boolean {
    try {
      return JSON.stringify(value).length <= MAX_CACHE_ENTRY_CHARS
    } catch {
      return false
    }
  }
}

export const apiRequestCoordinator = new ApiRequestCoordinator()

export const clearApiResponseCache = (): Promise<void> =>
  apiRequestCoordinator.clearCache()
