import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { afterEach, describe, expect, it } from "vitest"

import { publishChromeExtension } from "./publish-chrome.mjs"
import { publishEdgeExtension } from "./publish-edge.mjs"
import { buildFirefoxPublishArguments } from "./publish-firefox.mjs"

const temporaryDirectories = []

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true }))
  )
})

const temporaryArchive = async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "socx-publish-"))
  temporaryDirectories.push(directory)
  const archive = path.join(directory, "extension.zip")
  await writeFile(archive, "test archive")
  return archive
}

const jsonResponse = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), { status, headers })

describe("store publishers", () => {
  it("retries Edge conflicts, replaces the draft, and verifies publication", async () => {
    const archive = await temporaryArchive()
    const calls = []
    const responses = [
      jsonResponse({ message: "submission in progress" }, 409),
      jsonResponse({}, 202, { Location: "upload-1" }),
      jsonResponse({ status: "InProgress" }, 202),
      jsonResponse({ status: "Succeeded" }, 202),
      jsonResponse({}, 202, { Location: "publish-1" }),
      jsonResponse({ status: "Succeeded" }, 202)
    ]
    const fetchImpl = async (url, options = {}) => {
      calls.push({ url, options })
      return responses.shift()
    }

    await publishEdgeExtension({
      credentials: {
        productId: "edge-product",
        clientId: "edge-client",
        apiKey: "edge-key"
      },
      filePath: archive,
      notes: "SOCx update",
      fetchImpl,
      sleepImpl: async () => {},
      retryMilliseconds: 1,
      pollMilliseconds: 1,
      maxWaitMilliseconds: 10_000,
      log: () => {}
    })

    expect(
      calls.filter((call) => call.url.endsWith("/draft/package"))
    ).toHaveLength(2)
    expect(
      calls.some((call) => call.url.endsWith("/operations/publish-1"))
    ).toBe(true)
    expect(calls.at(-2).options.body).toBe(
      JSON.stringify({ notes: "SOCx update" })
    )
  })

  it("uses Chrome V2 and cancels the previous active submission", async () => {
    const archive = await temporaryArchive()
    const calls = []
    const responses = [
      jsonResponse({ access_token: "token" }),
      jsonResponse({
        submittedItemRevisionStatus: { state: "PENDING_REVIEW" }
      }),
      jsonResponse({ state: "CANCELLED" }),
      jsonResponse({ uploadState: "SUCCEEDED" }),
      jsonResponse({ state: "PENDING_REVIEW" })
    ]
    const fetchImpl = async (url, options = {}) => {
      calls.push({ url, options })
      return responses.shift()
    }

    await publishChromeExtension({
      credentials: {
        publisherId: "publisher",
        extId: "extension",
        clientId: "client",
        clientSecret: "secret",
        refreshToken: "refresh"
      },
      filePath: archive,
      fetchImpl,
      log: () => {}
    })

    expect(calls.some((call) => call.url.endsWith(":cancelSubmission"))).toBe(
      true
    )
    expect(calls.some((call) => call.url.includes("/upload/v2/"))).toBe(true)
    expect(calls.at(-1).url).toMatch(/:publish$/)
  })

  it("keeps Chrome V1 compatible until publisherId is configured", async () => {
    const archive = await temporaryArchive()
    const calls = []
    const responses = [
      jsonResponse({ access_token: "token" }),
      jsonResponse({ uploadState: "SUCCESS" }),
      jsonResponse({ status: ["OK"] })
    ]
    const fetchImpl = async (url, options = {}) => {
      calls.push({ url, options })
      return responses.shift()
    }

    await publishChromeExtension({
      credentials: {
        extId: "extension",
        clientId: "client",
        clientSecret: "secret",
        refreshToken: "refresh"
      },
      filePath: archive,
      fetchImpl,
      log: () => {}
    })

    expect(calls.some((call) => call.url.includes("/v1.1/items/"))).toBe(true)
    expect(calls.at(-1).url).toMatch(/\/publish$/)
  })

  it("reports the actionable Chrome OAuth error returned by Google", async () => {
    const archive = await temporaryArchive()

    await expect(
      publishChromeExtension({
        credentials: {
          extId: "extension",
          clientId: "client",
          clientSecret: "secret",
          refreshToken: "expired-refresh-token"
        },
        filePath: archive,
        fetchImpl: async () =>
          jsonResponse(
            {
              error: "invalid_grant",
              error_description: "Token has been expired or revoked"
            },
            400
          ),
        log: () => {}
      })
    ).rejects.toThrow("invalid_grant: Token has been expired or revoked")
  })

  it("explains a Chrome publication refusal without blaming the package", async () => {
    const archive = await temporaryArchive()
    const responses = [
      jsonResponse({ access_token: "token" }),
      jsonResponse({ submittedItemRevisionStatus: { state: "PUBLISHED" } }),
      jsonResponse({ uploadState: "SUCCEEDED" }),
      jsonResponse(
        {
          error: {
            message:
              "Your submission does not meet the requirements to be published in the store."
          }
        },
        400
      )
    ]

    const failure = await publishChromeExtension({
      credentials: {
        extId: "extension",
        publisherId: "publisher",
        clientId: "client",
        clientSecret: "secret",
        refreshToken: "refresh"
      },
      filePath: archive,
      fetchImpl: async () => responses.shift(),
      log: () => {}
    }).catch((error) => error)

    expect(failure.message).toContain("does not meet the requirements")
    // The package is fine: say so, and point at the one place that can fix it.
    expect(failure.message).toContain("saved as a draft")
    expect(failure.message).toContain(
      "https://chrome.google.com/webstore/devconsole/publisher/extension/edit"
    )
    expect(failure.message).toContain("Privacy practices")
  })

  it("uses the current web-ext submission flow with reviewer source", () => {
    const args = buildFirefoxPublishArguments({
      sourceDirectory: "build/firefox-prod",
      sourceArchive: "dist/source.zip"
    })

    expect(args).toContain("web-ext@10.6.0")
    expect(args).toContain("--channel=listed")
    expect(args).toContain("--source-dir=build/firefox-prod")
    expect(args).toContain("--upload-source-code=dist/source.zip")
  })
})
