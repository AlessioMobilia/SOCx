import { readFile } from "node:fs/promises"
import { pathToFileURL } from "node:url"

const TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
const CHROME_V1_API = "https://www.googleapis.com"
const CHROME_V2_API = "https://chromewebstore.googleapis.com"

const sleep = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds))

const readResponse = async (response) => {
  const text = await response.text()
  if (!text) return {}
  try {
    return JSON.parse(text)
  } catch {
    return { message: text }
  }
}

const checkedJson = async (action, response) => {
  const body = await readResponse(response)
  if (!response.ok) {
    const detail =
      body?.error?.message ||
      [
        typeof body?.error === "string" ? body.error : "",
        body?.error_description
      ]
        .filter(Boolean)
        .join(": ") ||
      body?.message ||
      response.statusText
    throw new Error(
      `${action} failed (${response.status})${detail ? `: ${detail}` : ""}`
    )
  }
  return body
}

/** Where a human has to go when the store refuses to publish. */
const dashboardUrl = ({ publisherId, extId }) =>
  publisherId
    ? `https://chrome.google.com/webstore/devconsole/${publisherId}/${extId}/edit`
    : "https://chrome.google.com/webstore/devconsole"

const getAccessToken = async (credentials, fetchImpl) => {
  const response = await fetchImpl(TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: credentials.clientId,
      client_secret: credentials.clientSecret,
      refresh_token: credentials.refreshToken,
      grant_type: "refresh_token"
    })
  })
  const body = await checkedJson("Chrome OAuth", response)
  if (!body.access_token)
    throw new Error("Chrome OAuth returned no access token")
  return body.access_token
}

const publishWithV1 = async ({
  credentials,
  archive,
  token,
  fetchImpl,
  log
}) => {
  log(
    "::warning::Chrome publisherId is missing; using deprecated Web Store API V1. Add chrome.publisherId to SUBMIT_KEYS before 2026-10-15."
  )
  const itemUrl = `${CHROME_V1_API}/chromewebstore/v1.1/items/${encodeURIComponent(credentials.extId)}`
  const uploadResponse = await fetchImpl(
    `${CHROME_V1_API}/upload/chromewebstore/v1.1/items/${encodeURIComponent(credentials.extId)}`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/zip",
        "x-goog-api-version": "2"
      },
      body: archive
    }
  )
  const upload = await checkedJson("Chrome V1 upload", uploadResponse)
  if (!/success/i.test(String(upload.uploadState ?? ""))) {
    throw new Error(
      `Chrome V1 upload did not succeed: ${upload.uploadState || "unknown state"}`
    )
  }

  const publishResponse = await fetchImpl(`${itemUrl}/publish`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "x-goog-api-version": "2"
    },
    body: JSON.stringify({ target: "default" })
  })
  const published = await checkedJson("Chrome V1 publication", publishResponse)
  const statuses = Array.isArray(published.status)
    ? published.status
    : [published.status].filter(Boolean)
  if (!statuses.includes("OK")) {
    throw new Error(`Chrome V1 publication failed: ${statuses.join(", ")}`)
  }
  log("Chrome V1 accepted the package for publication.")
}

const publishWithV2 = async ({
  credentials,
  archive,
  token,
  fetchImpl,
  sleepImpl,
  pollMilliseconds,
  maxWaitMilliseconds,
  log
}) => {
  const itemName = `publishers/${encodeURIComponent(credentials.publisherId)}/items/${encodeURIComponent(credentials.extId)}`
  const itemUrl = `${CHROME_V2_API}/v2/${itemName}`
  const authHeaders = { Authorization: `Bearer ${token}` }
  const status = await checkedJson(
    "Chrome V2 status",
    await fetchImpl(`${itemUrl}:fetchStatus`, { headers: authHeaders })
  )
  const pendingState = status.submittedItemRevisionStatus?.state
  if (["PENDING_REVIEW", "STAGED"].includes(pendingState)) {
    log(`Cancelling previous Chrome submission (${pendingState}).`)
    await checkedJson(
      "Chrome V2 cancellation",
      await fetchImpl(`${itemUrl}:cancelSubmission`, {
        method: "POST",
        headers: { ...authHeaders, "Content-Type": "application/json" },
        body: "{}"
      })
    )
  }

  const upload = await checkedJson(
    "Chrome V2 upload",
    await fetchImpl(
      `${CHROME_V2_API}/upload/v2/${itemName}:upload?uploadType=media`,
      {
        method: "POST",
        headers: { ...authHeaders, "Content-Type": "application/zip" },
        body: archive
      }
    )
  )

  let uploadState = upload.uploadState
  const deadline = Date.now() + maxWaitMilliseconds
  while (["IN_PROGRESS", "UPLOAD_IN_PROGRESS"].includes(uploadState)) {
    if (Date.now() >= deadline) {
      throw new Error("Chrome V2 upload did not complete before the deadline")
    }
    await sleepImpl(pollMilliseconds)
    const nextStatus = await checkedJson(
      "Chrome V2 upload status",
      await fetchImpl(`${itemUrl}:fetchStatus`, { headers: authHeaders })
    )
    uploadState = nextStatus.lastAsyncUploadState
  }
  if (uploadState !== "SUCCEEDED") {
    throw new Error(
      `Chrome V2 upload failed: ${uploadState || "unknown state"}`
    )
  }

  // The upload has already succeeded at this point: the new package is sitting
  // on the item as a draft. A refusal here is about the listing, not the
  // package — most often a permission added since the published version and
  // still without a justification, or a data-usage certification to renew — so
  // the error says where to go and what is already done.
  let publication
  try {
    publication = await checkedJson(
      "Chrome V2 publication",
      await fetchImpl(`${itemUrl}:publish`, {
        method: "POST",
        headers: { ...authHeaders, "Content-Type": "application/json" },
        body: JSON.stringify({
          publishType: "DEFAULT_PUBLISH",
          blockOnWarnings: false
        })
      })
    )
  } catch (error) {
    throw new Error(
      `${error.message}\n` +
        `The ${credentials.extId} package uploaded successfully and is saved as a draft; only publication was refused.\n` +
        `Resolve the item requirements at ${dashboardUrl(credentials)} — check Privacy practices for a permission justification or a data usage certification — then publish from there, or re-run the workflow with Chrome as the only enabled store.`
    )
  }
  if (!publication.state) {
    throw new Error("Chrome V2 publication returned no submission state")
  }
  log(`Chrome V2 accepted the package with state ${publication.state}.`)
}

export const publishChromeExtension = async ({
  credentials,
  filePath,
  fetchImpl = fetch,
  sleepImpl = sleep,
  pollMilliseconds = 5_000,
  maxWaitMilliseconds = 10 * 60_000,
  log = console.log
}) => {
  const { extId, clientId, clientSecret, refreshToken } = credentials ?? {}
  if (!extId || !clientId || !clientSecret || !refreshToken) {
    throw new Error(
      "SUBMIT_KEYS.chrome must contain extId, clientId, clientSecret, and refreshToken"
    )
  }

  const archive = await readFile(filePath)
  const token = await getAccessToken(credentials, fetchImpl)
  if (credentials.publisherId) {
    await publishWithV2({
      credentials,
      archive,
      token,
      fetchImpl,
      sleepImpl,
      pollMilliseconds,
      maxWaitMilliseconds,
      log
    })
    return
  }

  await publishWithV1({ credentials, archive, token, fetchImpl, log })
}

const isCli =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href

if (isCli) {
  const submitKeys = JSON.parse(process.env.SUBMIT_KEYS || "{}")
  await publishChromeExtension({
    credentials: submitKeys.chrome,
    filePath: process.env.CHROME_ZIP || "build/chrome-mv3-prod.zip"
  })
}
