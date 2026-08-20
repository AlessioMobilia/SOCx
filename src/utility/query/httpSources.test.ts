import { afterEach, describe, expect, it, vi } from "vitest"

import type { PackSource } from "./packSources"
import { fetchSource } from "./registry"

const packFile = {
  schema: "socx.querypack/v1",
  id: "intranet-kql",
  kind: "ioc",
  name: "Intranet — Defender",
  dialect: "kql",
  templates: [
    {
      id: "network-contact",
      name: "Network contact",
      byType: { IP: { field: "RemoteIP", op: "in~" } },
      body: "DeviceNetworkEvents | where {{field}} {{op}} ({{iocs}})"
    }
  ]
}

const indexFile = {
  schema: "socx.packindex/v1",
  name: "Intranet catalogue",
  packs: [
    {
      id: "intranet-kql",
      kind: "ioc",
      name: "Intranet — Defender",
      dialect: "kql",
      path: "packs/intranet-kql.json",
      templates: 1
    }
  ]
}

const respond = (body: unknown) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" }
  })

const serve = (files: Record<string, unknown>) =>
  vi.fn(async (url: string) => {
    const file = files[String(url)]
    if (!file) return new Response("not found", { status: 404 })
    return respond(file)
  })

const source = (url: string): PackSource => ({
  id: "intranet",
  url,
  kind: "ioc",
  enabled: true
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe("plain HTTP pack sources", () => {
  it("imports an index and its packs over http", async () => {
    const fetchMock = serve({
      "http://intranet.example/index.json": indexFile,
      "http://intranet.example/packs/intranet-kql.json": packFile
    })
    vi.stubGlobal("fetch", fetchMock)

    const outcome = await fetchSource(
      source("http://intranet.example/index.json")
    )

    expect(outcome.status, outcome.message).toBe("ok")
    expect(outcome.packs).toHaveLength(1)
    expect(outcome.packs?.[0].templates).toHaveLength(1)
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it("imports a single pack file over http", async () => {
    vi.stubGlobal(
      "fetch",
      serve({ "http://intranet.example/pack.json": packFile })
    )

    const outcome = await fetchSource(
      source("http://intranet.example/pack.json")
    )

    expect(outcome.status, outcome.message).toBe("ok")
    expect(outcome.packs?.[0].id).toBe("intranet-kql")
  })

  it("refuses a source on any other scheme", async () => {
    const fetchMock = serve({})
    vi.stubGlobal("fetch", fetchMock)

    const outcome = await fetchSource(
      source("ftp://intranet.example/index.json")
    )

    expect(outcome.status).toBe("error")
    expect(outcome.message).toMatch(/HTTP or HTTPS/)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
