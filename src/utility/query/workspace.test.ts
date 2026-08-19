import { describe, expect, it } from "vitest"

import { buildQueryWorkspaceUrl } from "../../background/query-workspace"
import { parseQueryWorkspaceHash, toWorkspaceIndicators } from "./workspace"

describe("query workspace launch", () => {
  it("round-trips selected indicators and a template through the hash", () => {
    const url = buildQueryWorkspaceUrl(
      "chrome-extension://socx/tabs/query-workspace.html",
      ["8.8.8.8", "evil.example"],
      "catalogue::pack::query"
    )
    const parsed = parseQueryWorkspaceHash(new URL(url).hash)
    expect(parsed).toEqual({
      indicators: ["8.8.8.8", "evil.example"],
      templateKey: "catalogue::pack::query"
    })
  })

  it("canonicalizes and classifies an IOC list", () => {
    expect(
      toWorkspaceIndicators("hxxps://Evil[.]example/a\n8.8.8.8\n8.8.8.8")
    ).toEqual([
      { value: "https://evil.example/a", type: "URL" },
      { value: "8.8.8.8", type: "IP" }
    ])
  })
})
