import { describe, expect, it } from "vitest"

import { importUserPackText } from "./userImport"

const pack = {
  schema: "socx.querypack/v1",
  id: "local-ioc",
  kind: "ioc",
  name: "Local IOC",
  dialect: "kql",
  templates: [
    {
      id: "network",
      name: "Network",
      byType: { IP: { field: "RemoteIP", op: "in~" } },
      body: "DeviceNetworkEvents | where {{field}} {{op}} ({{iocs}})"
    }
  ]
}

describe("custom query file import", () => {
  it("imports a valid pack into the personal library", () => {
    const result = importUserPackText(JSON.stringify(pack), [])
    expect(result.errors).toEqual([])
    expect(result.imported).toBe(1)
    expect(result.templates[0].name).toBe("Network")
  })

  it("reports malformed JSON without changing the library", () => {
    const existing = []
    const result = importUserPackText("not-json", existing)
    expect(result.templates).toBe(existing)
    expect(result.imported).toBe(0)
    expect(result.errors[0]).toMatch(/valid JSON/)
  })
})
