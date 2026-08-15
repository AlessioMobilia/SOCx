import { describe, expect, it, vi } from "vitest"

import {
  ApiRequestCoordinator,
  ApiRequestError,
  type RequestCacheStore
} from "./requestCoordinator"

const createMemoryStore = (): RequestCacheStore => {
  const values = new Map<string, any>()
  return {
    get: async (key) => values.get(key),
    set: async (key, value) => {
      values.set(key, value)
    },
    remove: async (key) => {
      values.delete(key)
    },
    clear: async () => {
      values.clear()
    }
  }
}

const zeroIntervals = {
  VirusTotal: 0,
  AbuseIPDB: 0,
  IPAPI: 0,
  ProxyCheck: 0,
  NVD: 0
} as const

describe("API request coordinator", () => {
  it("serves successful responses from the short-lived cache", async () => {
    let now = 1_000
    const request = vi.fn().mockResolvedValue({ verdict: "clean" })
    const coordinator = new ApiRequestCoordinator({
      cacheStore: createMemoryStore(),
      cacheTtlMs: 100,
      now: () => now,
      providerIntervals: zeroIntervals
    })

    const options = {
      provider: "VirusTotal" as const,
      cacheKey: "ip:203.0.113.10",
      request
    }
    expect(await coordinator.run(options)).toEqual({ verdict: "clean" })
    expect(await coordinator.run(options)).toEqual({ verdict: "clean" })
    expect(request).toHaveBeenCalledTimes(1)

    now += 101
    await coordinator.run(options)
    expect(request).toHaveBeenCalledTimes(2)
  })

  it("deduplicates simultaneous requests for the same provider and IOC", async () => {
    let resolveRequest: (value: string) => void = () => undefined
    const pendingRequest = new Promise<string>((resolve) => {
      resolveRequest = resolve
    })
    const request = vi.fn(() => pendingRequest)
    const coordinator = new ApiRequestCoordinator({
      cacheStore: createMemoryStore(),
      providerIntervals: zeroIntervals
    })

    const options = {
      provider: "AbuseIPDB" as const,
      cacheKey: "ip:198.51.100.8",
      request
    }
    const first = coordinator.run(options)
    const second = coordinator.run(options)
    resolveRequest("done")

    await expect(Promise.all([first, second])).resolves.toEqual([
      "done",
      "done"
    ])
    expect(request).toHaveBeenCalledTimes(1)
  })

  it("retries transient failures with exponential backoff", async () => {
    const sleep = vi.fn().mockResolvedValue(undefined)
    const request = vi
      .fn()
      .mockRejectedValueOnce(new ApiRequestError("busy", 503))
      .mockRejectedValueOnce(new ApiRequestError("limited", 429, 2_000))
      .mockResolvedValue("ok")
    const coordinator = new ApiRequestCoordinator({
      cacheStore: createMemoryStore(),
      providerIntervals: zeroIntervals,
      sleep
    })

    await expect(
      coordinator.run({
        provider: "IPAPI",
        cacheKey: "ip:192.0.2.4",
        request
      })
    ).resolves.toBe("ok")
    expect(sleep).toHaveBeenNthCalledWith(1, 750)
    expect(sleep).toHaveBeenNthCalledWith(2, 2_000)
  })

  it("runs different requests for the same provider sequentially", async () => {
    let finishFirst: () => void = () => undefined
    const firstPending = new Promise<void>((resolve) => {
      finishFirst = resolve
    })
    const firstRequest = vi.fn(() => firstPending.then(() => "first"))
    const secondRequest = vi.fn().mockResolvedValue("second")
    const coordinator = new ApiRequestCoordinator({
      cacheStore: createMemoryStore(),
      providerIntervals: zeroIntervals
    })

    const first = coordinator.run({
      provider: "AbuseIPDB",
      cacheKey: "ip:192.0.2.1",
      request: firstRequest
    })
    const second = coordinator.run({
      provider: "AbuseIPDB",
      cacheKey: "ip:192.0.2.2",
      request: secondRequest
    })
    await vi.waitFor(() => expect(firstRequest).toHaveBeenCalledTimes(1))
    expect(secondRequest).not.toHaveBeenCalled()

    finishFirst()
    await expect(Promise.all([first, second])).resolves.toEqual([
      "first",
      "second"
    ])
  })

  it("clears cached responses on demand", async () => {
    const request = vi.fn().mockResolvedValue("fresh")
    const coordinator = new ApiRequestCoordinator({
      cacheStore: createMemoryStore(),
      providerIntervals: zeroIntervals
    })
    const options = {
      provider: "ProxyCheck" as const,
      cacheKey: "ip:192.0.2.7",
      request
    }

    await coordinator.run(options)
    await coordinator.clearCache()
    await coordinator.run(options)
    expect(request).toHaveBeenCalledTimes(2)
  })

  it("allows a request-specific provider interval", async () => {
    let now = 1_000
    const sleep = vi.fn(async (ms: number) => {
      now += ms
    })
    const coordinator = new ApiRequestCoordinator({
      cacheStore: createMemoryStore(),
      now: () => now,
      sleep,
      providerIntervals: { ...zeroIntervals, NVD: 6_500 }
    })

    await coordinator.run({
      provider: "NVD",
      cacheKey: "CVE-2024-0001",
      minimumIntervalMs: 1_000,
      request: async () => "first"
    })
    await coordinator.run({
      provider: "NVD",
      cacheKey: "CVE-2024-0002",
      minimumIntervalMs: 1_000,
      request: async () => "second"
    })

    expect(sleep).toHaveBeenCalledWith(1_000)
  })
})
